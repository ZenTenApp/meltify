// Copyright (c) 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright (c) 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package pkcs12 encodes a single-entry PKCS#12 (also known as P12 or PFX)
// keystore: one private key, its end-entity certificate, and a friendly name.
//
// It is a trimmed copy of the encoder in
// software.sslmate.com/src/go-pkcs12 v0.7.4, reduced to the one shape meltify
// needs and extended to set the friendlyName attribute. Upstream leaves
// friendlyName unset, which makes Java derive the entry alias from a counter
// (so keytool reports "1"); setting it keeps the alias visible to keytool and
// to Android signing configurations.
//
// Files use modern parameters (the upstream Modern2023 encoder): PBES2 with
// PBKDF2-HMAC-SHA-256 and AES-256-CBC for both the certificates and the
// shrouded private key, and an HMAC-SHA-256 MAC over the authenticated safe.
// These are readable by OpenSSL 1.1.1+ and Java 12+.
package pkcs12

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // localKeyID is defined as a SHA-1 fingerprint by RFC 7292.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// iterations is the PBKDF2 and HMAC iteration count used by both the
	// encryption keys and the MAC key.
	iterations = 2048

	// saltLen is the length in bytes of the generated salts.
	saltLen = 16

	// aes256KeyLen is the AES-256 key length in bytes.
	aes256KeyLen = 32

	// pfxVersion is the PKCS#12 PFX version defined by RFC 7292.
	pfxVersion = 3

	// ASN.1 classes and tags used to build the PFX structure.
	asn1ClassContextSpecific = 2
	asn1TagSet               = 17
	asn1TagBMPString         = 30
)

var (
	oidDataContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEncryptedDataContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	oidFriendlyName = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	oidLocalKeyID   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}

	oidCertTypeX509Certificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidPKCS8ShroudedKeyBag     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBag                 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}

	oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHmacWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidSHA256         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

// ASN.1 structures from RFC 7292 appendix C and RFC 8018. Only the parts needed
// to write a single-entry keystore are modelled.

type pfxPdu struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

func (i encryptedContentInfo) Algorithm() pkix.AlgorithmIdentifier {
	return i.ContentEncryptionAlgorithm
}

func (i encryptedContentInfo) Data() []byte { return i.EncryptedContent }

func (i *encryptedContentInfo) SetData(data []byte) { i.EncryptedContent = data }

type encryptedPrivateKeyInfo struct {
	AlgorithmIdentifier pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

func (i encryptedPrivateKeyInfo) Algorithm() pkix.AlgorithmIdentifier { return i.AlgorithmIdentifier }

func (i encryptedPrivateKeyInfo) Data() []byte { return i.EncryptedData }

func (i *encryptedPrivateKeyInfo) SetData(data []byte) { i.EncryptedData = data }

type safeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"tag:0,explicit"`
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

type pkcs12Attribute struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type certBag struct {
	ID   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

type pbes2Params struct {
	Kdf              pkix.AlgorithmIdentifier
	EncryptionScheme pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt       asn1.RawValue
	Iterations int
	KeyLength  int                      `asn1:"optional"`
	Prf        pkix.AlgorithmIdentifier `asn1:"optional"`
}

// encryptable abstracts an object that carries PBES2 ciphertext.
type encryptable interface {
	Algorithm() pkix.AlgorithmIdentifier
	SetData([]byte)
}

// contextTag returns a context-specific, explicitly tagged, constructed raw
// value wrapping content.
func contextTag(content []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: content}
}

// Encode produces a DER-encoded PKCS#12 file containing privateKey and
// certificate, with the entry's friendlyName set to alias.
//
// random supplies the salts and IVs, so a deterministic reader yields
// reproducible output. alias and password must be non-empty; the password
// protects both the certificate and the private key, since PKCS#12 keys are
// shrouded with the keystore password.
func Encode(random io.Reader, privateKey any, certificate *x509.Certificate, alias, password string) ([]byte, error) {
	if random == nil {
		return nil, errors.New("pkcs12: random source is required")
	}
	if certificate == nil {
		return nil, errors.New("pkcs12: certificate is required")
	}
	if alias == "" {
		return nil, errors.New("pkcs12: alias cannot be empty")
	}
	if password == "" {
		return nil, errors.New("pkcs12: password cannot be empty")
	}

	// The legacy PKCS#12 KDF (used for the integrity key) takes a
	// NULL-terminated UCS-2 password; PBES2 takes the UTF-8 password.
	macPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, err
	}
	encryptionPassword := []byte(password)

	attributes, err := entryAttributes(certificate, alias)
	if err != nil {
		return nil, err
	}

	certificateBag, err := makeCertBag(certificate.Raw, attributes)
	if err != nil {
		return nil, err
	}
	keyBag, err := makeKeyBag(random, privateKey, attributes, encryptionPassword)
	if err != nil {
		return nil, err
	}

	// The authenticated safe holds two SafeContents: an encrypted one with the
	// certificates, and a plaintext one whose contents (the shrouded key) are
	// already encrypted, matching OpenSSL's PKCS12_create.
	var authenticatedSafe [2]contentInfo
	if authenticatedSafe[0], err = encryptedSafeContents(random, []safeBag{certificateBag}, encryptionPassword); err != nil {
		return nil, err
	}
	if authenticatedSafe[1], err = plainSafeContents([]safeBag{keyBag}); err != nil {
		return nil, err
	}

	authenticatedSafeBytes, err := asn1.Marshal(authenticatedSafe[:])
	if err != nil {
		return nil, fmt.Errorf("pkcs12: could not encode authenticated safe: %w", err)
	}

	var pfx pfxPdu
	pfx.Version = pfxVersion

	macSalt, err := randomBytes(random, saltLen)
	if err != nil {
		return nil, err
	}
	pfx.MacData = macData{
		Mac: digestInfo{
			Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
		},
		MacSalt:    macSalt,
		Iterations: iterations,
	}
	mac := hmac.New(sha256.New, macKey(macSalt, macPassword, iterations))
	mac.Write(authenticatedSafeBytes)
	pfx.MacData.Mac.Digest = mac.Sum(nil)

	authSafeContent, err := asn1.Marshal(authenticatedSafeBytes)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: could not encode authSafe: %w", err)
	}
	pfx.AuthSafe.ContentType = oidDataContentType
	pfx.AuthSafe.Content = contextTag(authSafeContent)

	pfxData, err := asn1.Marshal(pfx)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: could not encode PKCS#12: %w", err)
	}

	return pfxData, nil
}

// entryAttributes returns the attributes shared by the key bag and the
// certificate bag: the friendly name (the keystore alias) and the local key ID
// that ties the certificate to its private key.
func entryAttributes(certificate *x509.Certificate, alias string) ([]pkcs12Attribute, error) {
	friendlyName, err := friendlyNameAttribute(alias)
	if err != nil {
		return nil, err
	}
	localKeyID, err := localKeyIDAttribute(certificate)
	if err != nil {
		return nil, err
	}
	return []pkcs12Attribute{friendlyName, localKeyID}, nil
}

func friendlyNameAttribute(alias string) (pkcs12Attribute, error) {
	bmpAlias, err := bmpString(alias)
	if err != nil {
		return pkcs12Attribute{}, err
	}
	encodedBMPString, err := asn1.Marshal(asn1.RawValue{Tag: asn1TagBMPString, Bytes: bmpAlias})
	if err != nil {
		return pkcs12Attribute{}, fmt.Errorf("pkcs12: could not encode friendly name: %w", err)
	}
	return pkcs12Attribute{
		ID:    oidFriendlyName,
		Value: asn1.RawValue{Tag: asn1TagSet, IsCompound: true, Bytes: encodedBMPString},
	}, nil
}

func localKeyIDAttribute(certificate *x509.Certificate) (pkcs12Attribute, error) {
	fingerprint := sha1.Sum(certificate.Raw) //nolint:gosec // RFC 7292 defines localKeyID as a SHA-1 fingerprint.
	encodedFingerprint, err := asn1.Marshal(fingerprint[:])
	if err != nil {
		return pkcs12Attribute{}, fmt.Errorf("pkcs12: could not encode local key ID: %w", err)
	}
	return pkcs12Attribute{
		ID:    oidLocalKeyID,
		Value: asn1.RawValue{Tag: asn1TagSet, IsCompound: true, Bytes: encodedFingerprint},
	}, nil
}

func makeCertBag(certificateDER []byte, attributes []pkcs12Attribute) (safeBag, error) {
	bag := certBag{ID: oidCertTypeX509Certificate, Data: certificateDER}
	encoded, err := asn1.Marshal(bag)
	if err != nil {
		return safeBag{}, fmt.Errorf("pkcs12: could not encode cert bag: %w", err)
	}
	return safeBag{
		ID:         oidCertBag,
		Value:      contextTag(encoded),
		Attributes: attributes,
	}, nil
}

func makeKeyBag(random io.Reader, privateKey any, attributes []pkcs12Attribute, password []byte) (safeBag, error) {
	plain, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return safeBag{}, fmt.Errorf("pkcs12: could not encode PKCS#8 private key: %w", err)
	}

	parameters, err := newPBES2Parameters(random)
	if err != nil {
		return safeBag{}, err
	}

	var info encryptedPrivateKeyInfo
	info.AlgorithmIdentifier = pkix.AlgorithmIdentifier{
		Algorithm:  oidPBES2,
		Parameters: asn1.RawValue{FullBytes: parameters},
	}
	if err := encrypt(&info, plain, password); err != nil {
		return safeBag{}, err
	}

	encoded, err := asn1.Marshal(info)
	if err != nil {
		return safeBag{}, fmt.Errorf("pkcs12: could not encode shrouded key bag: %w", err)
	}

	return safeBag{
		ID:         oidPKCS8ShroudedKeyBag,
		Value:      contextTag(encoded),
		Attributes: attributes,
	}, nil
}

func plainSafeContents(bags []safeBag) (contentInfo, error) {
	encodedBags, err := asn1.Marshal(bags)
	if err != nil {
		return contentInfo{}, fmt.Errorf("pkcs12: could not encode safe contents: %w", err)
	}
	content, err := asn1.Marshal(encodedBags)
	if err != nil {
		return contentInfo{}, fmt.Errorf("pkcs12: could not encode safe contents content: %w", err)
	}
	return contentInfo{
		ContentType: oidDataContentType,
		Content:     contextTag(content),
	}, nil
}

func encryptedSafeContents(random io.Reader, bags []safeBag, password []byte) (contentInfo, error) {
	encodedBags, err := asn1.Marshal(bags)
	if err != nil {
		return contentInfo{}, fmt.Errorf("pkcs12: could not encode safe contents: %w", err)
	}

	parameters, err := newPBES2Parameters(random)
	if err != nil {
		return contentInfo{}, err
	}

	data := encryptedData{Version: 0} // Only version 0 is defined for EncryptedData.
	data.EncryptedContentInfo.ContentType = oidDataContentType
	data.EncryptedContentInfo.ContentEncryptionAlgorithm = pkix.AlgorithmIdentifier{
		Algorithm:  oidPBES2,
		Parameters: asn1.RawValue{FullBytes: parameters},
	}
	if err := encrypt(&data.EncryptedContentInfo, encodedBags, password); err != nil {
		return contentInfo{}, err
	}

	encoded, err := asn1.Marshal(data)
	if err != nil {
		return contentInfo{}, fmt.Errorf("pkcs12: could not encode encrypted safe contents: %w", err)
	}

	return contentInfo{
		ContentType: oidEncryptedDataContentType,
		Content:     contextTag(encoded),
	}, nil
}

// newPBES2Parameters builds PBES2 parameters (RFC 8018, appendix A.2) using
// PBKDF2-HMAC-SHA-256 with a fresh salt and AES-256-CBC with a fresh IV.
func newPBES2Parameters(random io.Reader) ([]byte, error) {
	salt, err := randomBytes(random, saltLen)
	if err != nil {
		return nil, err
	}
	iv, err := randomBytes(random, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	encodedSalt, err := asn1.Marshal(salt)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: could not encode PBKDF2 salt: %w", err)
	}
	encodedIV, err := asn1.Marshal(iv)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: could not encode AES IV: %w", err)
	}

	kdfParams := pbkdf2Params{
		Salt:       asn1.RawValue{FullBytes: encodedSalt},
		Iterations: iterations,
		Prf: pkix.AlgorithmIdentifier{
			Algorithm:  oidHmacWithSHA256,
			Parameters: asn1.NullRawValue,
		},
	}
	encodedKDFParams, err := asn1.Marshal(kdfParams)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: could not encode PBKDF2 parameters: %w", err)
	}

	params := pbes2Params{
		Kdf: pkix.AlgorithmIdentifier{
			Algorithm:  oidPBKDF2,
			Parameters: asn1.RawValue{FullBytes: encodedKDFParams},
		},
		EncryptionScheme: pkix.AlgorithmIdentifier{
			Algorithm:  oidAES256CBC,
			Parameters: asn1.RawValue{FullBytes: encodedIV},
		},
	}

	encoded, err := asn1.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: could not encode PBES2 parameters: %w", err)
	}
	return encoded, nil
}

// encrypt applies PBES2 (AES-256-CBC, PKCS#7 padding) to plaintext and stores
// the ciphertext in info.
func encrypt(info encryptable, plaintext, password []byte) error {
	algorithm := info.Algorithm()
	if !algorithm.Algorithm.Equal(oidPBES2) {
		return fmt.Errorf("pkcs12: unsupported encryption algorithm %s", algorithm.Algorithm.String())
	}

	var params pbes2Params
	if rest, err := asn1.Unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
		return fmt.Errorf("pkcs12: could not decode PBES2 parameters: %w", err)
	} else if len(rest) != 0 {
		return errors.New("pkcs12: trailing data after PBES2 parameters")
	}

	if !params.Kdf.Algorithm.Equal(oidPBKDF2) {
		return fmt.Errorf("pkcs12: unsupported PBES2 KDF %s", params.Kdf.Algorithm.String())
	}
	if !params.EncryptionScheme.Algorithm.Equal(oidAES256CBC) {
		return fmt.Errorf("pkcs12: unsupported PBES2 cipher %s", params.EncryptionScheme.Algorithm.String())
	}

	var kdfParams pbkdf2Params
	if rest, err := asn1.Unmarshal(params.Kdf.Parameters.FullBytes, &kdfParams); err != nil {
		return fmt.Errorf("pkcs12: could not decode PBKDF2 parameters: %w", err)
	} else if len(rest) != 0 {
		return errors.New("pkcs12: trailing data after PBKDF2 parameters")
	}
	if kdfParams.Salt.Tag != asn1.TagOctetString {
		return errors.New("pkcs12: only octet string PBKDF2 salts are supported")
	}

	key := pbkdf2.Key(password, kdfParams.Salt.Bytes, kdfParams.Iterations, aes256KeyLen, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("pkcs12: could not create AES cipher: %w", err)
	}
	iv := params.EncryptionScheme.Parameters.Bytes
	if len(iv) != block.BlockSize() {
		return fmt.Errorf("pkcs12: invalid IV length %d", len(iv))
	}

	// PKCS#7 padding.
	padLen := block.BlockSize() - len(plaintext)%block.BlockSize()
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	copy(padded[len(plaintext):], bytes.Repeat([]byte{byte(padLen)}, padLen))

	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	info.SetData(ciphertext)
	return nil
}

func randomBytes(random io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(random, buf); err != nil {
		return nil, fmt.Errorf("pkcs12: could not read %d random bytes: %w", n, err)
	}
	return buf, nil
}
