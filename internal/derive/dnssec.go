package derive

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// DNSSEC algorithm numbers.
const (
	// DNSSECAlgorithmRSASHA256 is DNSSEC algorithm 8 (RSASHA256).
	DNSSECAlgorithmRSASHA256 = 8
)

// DNSSEC DNSKEY flag values.
const (
	// DNSSECKSKFlags marks a key-signing key (flags 257).
	DNSSECKSKFlags = 257

	// DNSSECZSKFlags marks a zone-signing key (flags 256).
	DNSSECZSKFlags = 256
)

const (
	dnssecProtocol           = 3
	dnssecDSDigestSHA256     = 2
	dnssecExtendedExpLenMark = 0
	dnssecByteShift          = 8
	dnssecMaxLabelLen        = 63
	dnssecRDATAHeaderLen     = 4
)

// DNSSECKeypair holds deterministic DNSSEC key material in BIND-compatible form.
type DNSSECKeypair struct {
	// Domain is the canonical absolute owner name, ending in a dot.
	Domain string

	// Algorithm is the DNSSEC algorithm number. Currently only 8 (RSASHA256) is supported.
	Algorithm int

	// Flags is the DNSKEY flags field: 257 for KSK, 256 for ZSK.
	Flags int

	// KeyTag is the DNSSEC key tag/key ID computed from DNSKEY RDATA.
	KeyTag uint16

	// FileBase is the BIND-style basename without extension, e.g. Kexample.com.+008+33206.
	FileBase string

	// PublicKeyBase64 is the DNSSEC RSA public key field, base64-encoded.
	PublicKeyBase64 string

	// DNSKEYRecord is the public DNSKEY RR suitable for a zone file.
	DNSKEYRecord string

	// DSRecord is the SHA-256 DS RR suitable for registrar/parent-zone submission.
	DSRecord string

	// KeyFile is the content of the BIND .key file.
	KeyFile []byte

	// PrivateKeyFile is the content of the BIND .private file.
	PrivateKeyFile []byte
}

// DNSSEC deterministically derives a BIND-compatible DNSSEC RSA keypair from an
// Ed25519 private key.
//
// This matches seedify.DeriveDNSSECKeypair. Only algorithm 8 (RSASHA256) is
// supported. The domain, algorithm, flags, and RSA bit size are included in the
// domain-separation label so that KSK/ZSK keys and keys for different zones are
// cryptographically distinct.
//
// flags must be DNSSECKSKFlags (257) or DNSSECZSKFlags (256). bits must be
// 2048, 3072, or 4096. The output includes BIND-style .key/.private file
// contents plus DNSKEY and SHA-256 DS records.
func DNSSEC(key *ed25519.PrivateKey, domain string, algorithm, flags, bits int) (*DNSSECKeypair, error) {
	if key == nil {
		return nil, errors.New("ed25519 key is required")
	}
	if algorithm != DNSSECAlgorithmRSASHA256 {
		return nil, fmt.Errorf("unsupported DNSSEC algorithm %d: only 8 (RSASHA256) is supported", algorithm)
	}
	if flags != DNSSECKSKFlags && flags != DNSSECZSKFlags {
		return nil, fmt.Errorf("invalid DNSSEC flags %d: use 257 for KSK or 256 for ZSK", flags)
	}
	if err := ValidRSABits(bits); err != nil {
		return nil, err
	}

	canonicalDomain, err := canonicalDNSName(domain)
	if err != nil {
		return nil, err
	}

	label := []byte(fmt.Sprintf("seedify:dnssec:%s:%d:%d:%d:", canonicalDomain, algorithm, flags, bits))
	input := make([]byte, len(label)+len(key.Seed()))
	copy(input, label)
	copy(input[len(label):], key.Seed())

	rsaKey, err := deriveRSAKeyFromDomainHash(sha256.Sum256(input), bits)
	if err != nil {
		return nil, fmt.Errorf("could not derive RSA key for DNSSEC: %w", err)
	}

	publicKey := dnssecRSAPublicKeyBytes(&rsaKey.PublicKey)
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKey)
	rdata := dnskeyRDATA(flags, algorithm, publicKey)
	keyTag := dnssecKeyTag(rdata)
	fileBase := fmt.Sprintf("K%s.+%03d+%05d", strings.TrimSuffix(canonicalDomain, "."), algorithm, keyTag)
	keyRecord := fmt.Sprintf("%s IN DNSKEY %d %d %d %s", canonicalDomain, flags, dnssecProtocol, algorithm, publicKeyBase64)

	wireName, err := dnsNameToWire(canonicalDomain)
	if err != nil {
		return nil, err
	}
	dsInput := make([]byte, 0, len(wireName)+len(rdata))
	dsInput = append(dsInput, wireName...)
	dsInput = append(dsInput, rdata...)
	dsDigest := sha256.Sum256(dsInput)
	dsRecord := fmt.Sprintf("%s IN DS %d %d %d %s", canonicalDomain, keyTag, algorithm, dnssecDSDigestSHA256, strings.ToUpper(hex.EncodeToString(dsDigest[:])))

	return &DNSSECKeypair{
		Domain:          canonicalDomain,
		Algorithm:       algorithm,
		Flags:           flags,
		KeyTag:          keyTag,
		FileBase:        fileBase,
		PublicKeyBase64: publicKeyBase64,
		DNSKEYRecord:    keyRecord,
		DSRecord:        dsRecord,
		KeyFile:         []byte(keyRecord + "\n"),
		PrivateKeyFile:  dnssecPrivateKeyFile(rsaKey, algorithm),
	}, nil
}

func canonicalDNSName(domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return "", errors.New("DNSSEC domain is required")
	}
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	if domain == "." {
		return "", errors.New("DNSSEC root zone is not supported")
	}
	return domain, nil
}

func dnssecRSAPublicKeyBytes(pub *rsa.PublicKey) []byte {
	exponent := big.NewInt(int64(pub.E)).Bytes()
	modulus := pub.N.Bytes()
	out := make([]byte, 0, 1+len(exponent)+len(modulus))
	if len(exponent) < 256 { //nolint:mnd // An exponent longer than 255 bytes uses the extended length form.
		out = append(out, byte(len(exponent)))
	} else {
		out = append(out, dnssecExtendedExpLenMark, byte(len(exponent)>>dnssecByteShift), byte(len(exponent)))
	}
	out = append(out, exponent...)
	out = append(out, modulus...)
	return out
}

func dnskeyRDATA(flags, algorithm int, publicKey []byte) []byte {
	rdata := make([]byte, dnssecRDATAHeaderLen+len(publicKey))
	binary.BigEndian.PutUint16(rdata[0:2], uint16(flags)) //nolint:gosec // DNSSEC flags are validated to 256 or 257.
	rdata[2] = dnssecProtocol
	rdata[3] = byte(algorithm)
	copy(rdata[dnssecRDATAHeaderLen:], publicKey)
	return rdata
}

func dnssecKeyTag(rdata []byte) uint16 {
	var ac uint32
	for i, b := range rdata {
		if i&1 == 0 {
			ac += uint32(b) << dnssecByteShift
		} else {
			ac += uint32(b)
		}
	}
	ac += (ac >> 16) & 0xffff
	return uint16(ac & 0xffff) //nolint:gosec // Key tag is defined as the low 16 bits.
}

func dnsNameToWire(domain string) ([]byte, error) {
	canonical, err := canonicalDNSName(domain)
	if err != nil {
		return nil, err
	}
	labels := strings.Split(strings.TrimSuffix(canonical, "."), ".")
	wire := make([]byte, 0, len(canonical)+1)
	for _, label := range labels {
		if label == "" {
			return nil, fmt.Errorf("invalid DNS name %q: empty label", domain)
		}
		if len(label) > dnssecMaxLabelLen {
			return nil, fmt.Errorf("invalid DNS name %q: label %q is too long", domain, label)
		}
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	wire = append(wire, 0)
	return wire, nil
}

func dnssecPrivateKeyFile(key *rsa.PrivateKey, algorithm int) []byte {
	created := pgpEpoch.UTC().Format("20060102150405")
	b64 := func(n *big.Int) string { return base64.StdEncoding.EncodeToString(n.Bytes()) }
	content := fmt.Sprintf(`Private-key-format: v1.3
Algorithm: %d (RSASHA256)
Modulus: %s
PublicExponent: %s
PrivateExponent: %s
Prime1: %s
Prime2: %s
Exponent1: %s
Exponent2: %s
Coefficient: %s
Created: %s
Publish: %s
Activate: %s
`,
		algorithm,
		b64(key.N),
		b64(big.NewInt(int64(key.E))),
		b64(key.D),
		b64(key.Primes[0]),
		b64(key.Primes[1]),
		b64(key.Precomputed.Dp),
		b64(key.Precomputed.Dq),
		b64(key.Precomputed.Qinv),
		created,
		created,
		created,
	)
	return []byte(content)
}
