package derive

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/mr-tron/base58"
	"github.com/tyler-smith/go-bip39"
)

// SLIP-0132 extended-key version prefixes for BIP48 multisig accounts.
// Uppercase Y/Z marks a multisig account; lowercase y/z is single-sig.
const (
	multisigYpubVersion uint32 = 0x0295B43F
	multisigYprvVersion uint32 = 0x0295B005
	multisigZpubVersion uint32 = 0x02AA7ED3
	multisigZprvVersion uint32 = 0x02AA7A99
)

const (
	multisigBIP48Purpose    uint32 = 48
	multisigBitcoinCoinType uint32 = 0
	multisigDefaultAccount  uint32 = 0
	multisigExternalChain   uint32 = 0
	multisigChangeChain     uint32 = 1
	extendedKeyPayloadSize         = 78
	extendedKeyChecksumSize        = 4
	masterFingerprintSize          = 4
	// BIP32 and SLIP-0132 extended-key version bytes.
	xpubVersion uint32 = 0x0488B21E
	xprvVersion uint32 = 0x0488ADE4
	ypubVersion uint32 = 0x049D7CB2
	yprvVersion uint32 = 0x049D7878
	zpubVersion uint32 = 0x04B24746
	zprvVersion uint32 = 0x04B2430C
	// MaxMultisigCosigners is the largest key set a legacy P2SH multisig script
	// can hold (consensus OP_CHECKMULTISIG limit for script-hash wallets).
	MaxMultisigCosigners   = 15
	opCheckMultiSig        = 0xae
	opWitnessV0            = 0x00
	opSmallIntBase         = 0x50
	maxSmallInt            = 16
	compressedKeyLen       = 33
	witnessProgramLen      = 32
	multisigScriptOverhead = 3 // OP_m + ... + OP_n + OP_CHECKMULTISIG
	witnessProgramOverhead = 2 // OP_0 + push length
	descriptorChangePos    = "0/*"
	fingerprintHexLen      = 8
	hardenedMarker         = "'"
)

// BitcoinMultisigScriptType is the BIP48 script-type field of a multisig policy.
// The value is the BIP48 derivation index: 0' legacy P2SH, 1' nested
// P2SH-P2WSH, 2' native P2WSH.
type BitcoinMultisigScriptType uint32

// BIP48 script types. The zero value is the legacy P2SH policy.
const (
	BitcoinMultisigLegacyP2SH BitcoinMultisigScriptType = iota
	BitcoinMultisigNestedSegwitP2SHP2WSH
	BitcoinMultisigNativeSegwitP2WSH
)

// String returns the policy name used by wallet UIs for the script type.
func (s BitcoinMultisigScriptType) String() string {
	switch s {
	case BitcoinMultisigLegacyP2SH:
		return "Legacy (P2SH)"
	case BitcoinMultisigNestedSegwitP2SHP2WSH:
		return "Nested Segwit (P2SH-P2WSH)"
	case BitcoinMultisigNativeSegwitP2WSH:
		return "Native Segwit (P2WSH)"
	default:
		return "Unknown"
	}
}

// DerivationPath returns the BIP48 account path for the script type.
func (s BitcoinMultisigScriptType) DerivationPath() string {
	return fmt.Sprintf("m/48'/0'/0'/%d'", uint32(s))
}

// ParseBitcoinMultisigScriptType maps a user-supplied script-type name to the
// BIP48 script type. Accepted names: legacy, p2sh, 0; nested, p2sh-p2wsh,
// segwit, 1; native, p2wsh, bech32, 2.
func ParseBitcoinMultisigScriptType(name string) (BitcoinMultisigScriptType, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "legacy", "p2sh", "0":
		return BitcoinMultisigLegacyP2SH, nil
	case "nested", "p2sh-p2wsh", "segwit", "1":
		return BitcoinMultisigNestedSegwitP2SHP2WSH, nil
	case "native", "p2wsh", "bech32", "2":
		return BitcoinMultisigNativeSegwitP2WSH, nil
	default:
		return 0, fmt.Errorf("unknown script type %q: use legacy, nested, or native", name)
	}
}

// BitcoinMultisigExtendedKeys holds the BIP48 account-level extended keys.
// StandardPublicKey/StandardPrivateKey are always the BIP32 xpub/xprv;
// ExtendedPublicKey/ExtendedPrivateKey carry the SLIP-0132 variant when one
// exists (Ypub/Yprv for nested SegWit, Zpub/Zprv for native SegWit) and the
// standard keys for legacy P2SH.
type BitcoinMultisigExtendedKeys struct {
	StandardPublicKey  string
	StandardPrivateKey string
	ExtendedPublicKey  string
	ExtendedPrivateKey string
}

// BitcoinMultisigCosigner is one key in a multisig policy descriptor.
type BitcoinMultisigCosigner struct {
	// AccountXPub is the BIP32 xpub at the policy's BIP48 account path.
	AccountXPub string
	// MasterFingerprint is the optional 8-character lowercase hex master key
	// fingerprint. When set, the descriptor key carries a key origin.
	MasterFingerprint string
	// Derivation overrides the key origin path. It defaults to the script
	// type's BIP48 account path.
	Derivation string
}

// BitcoinMasterFingerprint returns the BIP32 master key fingerprint for a
// mnemonic: the first 4 bytes of HASH160 of the compressed master public key,
// as 8 lowercase hex characters.
//
// This matches seedify.DeriveBitcoinMasterFingerprint.
func BitcoinMasterFingerprint(mnemonic, bip39Passphrase string) (string, error) {
	masterKey, err := newBitcoinMasterKey(mnemonic, bip39Passphrase)
	if err != nil {
		return "", err
	}

	masterPubKey, err := masterKey.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get master public key: %w", err)
	}

	pubKeyHash := btcutil.Hash160(masterPubKey.SerializeCompressed())
	return hex.EncodeToString(pubKeyHash[:masterFingerprintSize]), nil
}

// BitcoinMultisigAccount derives the BIP48 account-level extended keys at
// m/48'/0'/0'/<scriptType>' for a mnemonic.
//
// This matches seedify.DeriveBitcoinMultisigNativeSegwitExtendedKeys (script
// type 2'), seedify.DeriveBitcoinMultisigSegwitExtendedKeys (1'), and
// seedify.DeriveBitcoinMultisigLegacyExtendedKeys (0').
func BitcoinMultisigAccount(mnemonic, bip39Passphrase string, scriptType BitcoinMultisigScriptType) (*BitcoinMultisigExtendedKeys, error) {
	masterKey, err := newBitcoinMasterKey(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, err
	}

	accountKey, err := deriveBIP32Path(masterKey, []uint32{
		hdkeychain.HardenedKeyStart + multisigBIP48Purpose,
		hdkeychain.HardenedKeyStart + multisigBitcoinCoinType,
		hdkeychain.HardenedKeyStart + multisigDefaultAccount,
		hdkeychain.HardenedKeyStart + uint32(scriptType),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to derive account key: %w", err)
	}

	accountPubKey, err := accountKey.Neuter()
	if err != nil {
		return nil, fmt.Errorf("failed to neuter key: %w", err)
	}

	keys := &BitcoinMultisigExtendedKeys{
		StandardPublicKey:  accountPubKey.String(),
		StandardPrivateKey: accountKey.String(),
	}

	switch scriptType {
	case BitcoinMultisigLegacyP2SH:
		keys.ExtendedPublicKey = keys.StandardPublicKey
		keys.ExtendedPrivateKey = keys.StandardPrivateKey
	case BitcoinMultisigNestedSegwitP2SHP2WSH:
		keys.ExtendedPublicKey = encodeExtendedKey(accountPubKey, multisigYpubVersion)
		keys.ExtendedPrivateKey = encodeExtendedKey(accountKey, multisigYprvVersion)
	case BitcoinMultisigNativeSegwitP2WSH:
		keys.ExtendedPublicKey = encodeExtendedKey(accountPubKey, multisigZpubVersion)
		keys.ExtendedPrivateKey = encodeExtendedKey(accountKey, multisigZprvVersion)
	}

	if keys.ExtendedPublicKey == "" || keys.ExtendedPrivateKey == "" {
		return nil, fmt.Errorf("failed to re-encode account key as SLIP-0132")
	}
	return keys, nil
}

// BitcoinMultisigAddress derives the 1-of-1 multisig address for a mnemonic at
// m/48'/0'/0'/<scriptType>'/0/0.
//
// This matches seedify.DeriveBitcoinMultisigNativeSegwitKeys (2'),
// seedify.DeriveBitcoinMultisigSegwitKeys (1'), and
// seedify.DeriveBitcoinMultisigLegacyKeys (0').
func BitcoinMultisigAddress(mnemonic, bip39Passphrase string, scriptType BitcoinMultisigScriptType) (string, error) {
	masterKey, err := newBitcoinMasterKey(mnemonic, bip39Passphrase)
	if err != nil {
		return "", err
	}

	addressKey, err := deriveBIP32Path(masterKey, []uint32{
		hdkeychain.HardenedKeyStart + multisigBIP48Purpose,
		hdkeychain.HardenedKeyStart + multisigBitcoinCoinType,
		hdkeychain.HardenedKeyStart + multisigDefaultAccount,
		hdkeychain.HardenedKeyStart + uint32(scriptType),
		0, // external chain
		0, // first receiving address
	})
	if err != nil {
		return "", fmt.Errorf("failed to derive address key: %w", err)
	}

	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %w", err)
	}

	script, err := multisigRedeemScript([][]byte{pubKey.SerializeCompressed()}, 1)
	if err != nil {
		return "", err
	}
	return multisigScriptAddress(script, scriptType)
}

// BitcoinMultisigAddressSet holds the first addressCount receive (external
// chain 0) and change (internal chain 1) addresses of a BIP48 multisig policy.
type BitcoinMultisigAddressSet struct {
	Receive []string
	Change  []string
}

// BitcoinMultisigAddresses derives the first count receive and change addresses
// of an m-of-n BIP48 multisig policy from every cosigner's account xpub,
// including this wallet's own. accountXpubs may be supplied in any order: each
// address's public keys are sorted lexicographically, matching the sortedmulti
// descriptor, before the redeem script is built.
func BitcoinMultisigAddresses(scriptType BitcoinMultisigScriptType, required int, accountXpubs []string, count int) (*BitcoinMultisigAddressSet, error) {
	if err := validateMultisigPolicy(required, len(accountXpubs)); err != nil {
		return nil, err
	}
	if count < 1 {
		return nil, fmt.Errorf("address count must be at least 1, got %d", count)
	}

	accountKeys := make([]*hdkeychain.ExtendedKey, 0, len(accountXpubs))
	for i, xpub := range accountXpubs {
		normalized, err := NormalizeBitcoinExtendedKey(xpub)
		if err != nil {
			return nil, fmt.Errorf("cosigner %d: %w", i+1, err)
		}
		key, err := hdkeychain.NewKeyFromString(normalized)
		if err != nil {
			return nil, fmt.Errorf("cosigner %d: invalid account extended public key: %w", i+1, err)
		}
		if key.IsPrivate() {
			return nil, fmt.Errorf("cosigner %d: account key is private; provide an xpub, not an xprv", i+1)
		}
		accountKeys = append(accountKeys, key)
	}

	receive, err := multisigChainAddresses(scriptType, required, accountKeys, multisigExternalChain, count)
	if err != nil {
		return nil, fmt.Errorf("receive addresses: %w", err)
	}
	change, err := multisigChainAddresses(scriptType, required, accountKeys, multisigChangeChain, count)
	if err != nil {
		return nil, fmt.Errorf("change addresses: %w", err)
	}
	return &BitcoinMultisigAddressSet{Receive: receive, Change: change}, nil
}

// multisigChainAddresses derives count addresses on one BIP48 chain (0 external,
// 1 internal) for every account key, sorting each address's public keys.
func multisigChainAddresses(scriptType BitcoinMultisigScriptType, required int, accountKeys []*hdkeychain.ExtendedKey, chain uint32, count int) ([]string, error) {
	addresses := make([]string, 0, count)
	for index := 0; index < count; index++ {
		pubKeys := make([][]byte, 0, len(accountKeys))
		for cosigner, accountKey := range accountKeys {
			chainKey, err := accountKey.Derive(chain)
			if err != nil {
				return nil, fmt.Errorf("cosigner %d: failed to derive chain %d: %w", cosigner+1, chain, err)
			}
			addressKey, err := chainKey.Derive(uint32(index)) //nolint:gosec // index is bounded by count above.
			if err != nil {
				return nil, fmt.Errorf("cosigner %d: failed to derive index %d: %w", cosigner+1, index, err)
			}
			pubKey, err := addressKey.ECPubKey()
			if err != nil {
				return nil, fmt.Errorf("cosigner %d: failed to get public key: %w", cosigner+1, err)
			}
			pubKeys = append(pubKeys, pubKey.SerializeCompressed())
		}

		sort.Slice(pubKeys, func(i, j int) bool { return bytes.Compare(pubKeys[i], pubKeys[j]) < 0 })

		script, err := multisigRedeemScript(pubKeys, required)
		if err != nil {
			return nil, err
		}
		address, err := multisigScriptAddress(script, scriptType)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

// multisigScriptAddress encodes a redeem script as the address the script type
// commits to.
func multisigScriptAddress(script []byte, scriptType BitcoinMultisigScriptType) (string, error) {
	switch scriptType {
	case BitcoinMultisigLegacyP2SH:
		return payToScriptHashAddress(script)
	case BitcoinMultisigNestedSegwitP2SHP2WSH:
		witnessScriptHash := sha256.Sum256(script)
		return payToScriptHashAddress(witnessScriptHashScriptPubKey(witnessScriptHash[:]))
	case BitcoinMultisigNativeSegwitP2WSH:
		witnessScriptHash := sha256.Sum256(script)
		addr, err := btcutil.NewAddressWitnessScriptHash(witnessScriptHash[:], &chaincfg.MainNetParams)
		if err != nil {
			return "", fmt.Errorf("failed to create P2WSH address: %w", err)
		}
		return addr.EncodeAddress(), nil
	default:
		return "", fmt.Errorf("unsupported script type %d", uint32(scriptType))
	}
}

// validateMultisigPolicy checks the m-of-n shape shared by descriptors and
// address derivation.
func validateMultisigPolicy(required, cosignerCount int) error {
	if required < 1 {
		return fmt.Errorf("required signatures must be at least 1, got %d", required)
	}
	if cosignerCount < required {
		return fmt.Errorf("%d required signatures need at least %d cosigners, got %d", required, required, cosignerCount)
	}
	if cosignerCount > MaxMultisigCosigners {
		return fmt.Errorf("at most %d cosigners are supported, got %d", MaxMultisigCosigners, cosignerCount)
	}
	return nil
}

// NormalizeBitcoinExtendedKey rewrites a SLIP-0132 extended key (ypub/zpub and
// their multisig Ypub/Zpub variants, public or private) to its BIP32 xpub/xprv
// form. Standard xpub/xprv keys pass through unchanged.
func NormalizeBitcoinExtendedKey(key string) (string, error) {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return "", errors.New("extended key is empty")
	}

	decoded, err := base58.Decode(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid extended key: %w", err)
	}
	if len(decoded) != extendedKeyPayloadSize+extendedKeyChecksumSize {
		return "", fmt.Errorf("extended key has %d bytes, want %d", len(decoded), extendedKeyPayloadSize+extendedKeyChecksumSize)
	}

	payload := decoded[:extendedKeyPayloadSize]
	firstHash := sha256.Sum256(payload)
	secondHash := sha256.Sum256(firstHash[:])
	if !bytes.Equal(decoded[extendedKeyPayloadSize:], secondHash[:extendedKeyChecksumSize]) {
		return "", errors.New("extended key checksum mismatch")
	}

	version := binary.BigEndian.Uint32(payload[:4])
	var target uint32
	switch version {
	case xpubVersion, xprvVersion:
		return trimmed, nil
	case ypubVersion, zpubVersion, multisigYpubVersion, multisigZpubVersion:
		target = xpubVersion
	case yprvVersion, zprvVersion, multisigYprvVersion, multisigZprvVersion:
		target = xprvVersion
	default:
		return "", fmt.Errorf("unsupported extended key version %#08x", version)
	}

	binary.BigEndian.PutUint32(payload[:4], target)
	firstHash = sha256.Sum256(payload)
	secondHash = sha256.Sum256(firstHash[:])
	return base58.Encode(append(payload, secondHash[:extendedKeyChecksumSize]...)), nil
}

// BitcoinMultisigDescriptor renders the BIP380 output descriptor for a BIP48
// multisig policy, for example
//
//	wsh(sortedmulti(1,[3e1f3ae0/48'/0'/0'/2']xpub.../0/*))
//
// required is the m of the m-of-n policy. cosigners holds every cosigner key,
// including this wallet's own; the descriptor text keeps them in the given
// order because sortedmulti sorts derived public keys at derivation time, not
// in the descriptor. No descriptor checksum is appended.
func BitcoinMultisigDescriptor(scriptType BitcoinMultisigScriptType, required int, cosigners []BitcoinMultisigCosigner) (string, error) {
	if err := validateMultisigPolicy(required, len(cosigners)); err != nil {
		return "", err
	}

	expressions := make([]string, 0, len(cosigners))
	for i, cosigner := range cosigners {
		expression, err := cosigner.scriptExpression(scriptType)
		if err != nil {
			return "", fmt.Errorf("cosigner %d: %w", i+1, err)
		}
		expressions = append(expressions, expression)
	}

	multi := fmt.Sprintf("sortedmulti(%d,%s)", required, strings.Join(expressions, ","))
	switch scriptType {
	case BitcoinMultisigLegacyP2SH:
		return "sh(" + multi + ")", nil
	case BitcoinMultisigNestedSegwitP2SHP2WSH:
		return "sh(wsh(" + multi + "))", nil
	case BitcoinMultisigNativeSegwitP2WSH:
		return "wsh(" + multi + ")", nil
	default:
		return "", fmt.Errorf("unsupported script type %d", uint32(scriptType))
	}
}

// scriptExpression renders one descriptor key: an optional key origin followed
// by the account xpub and the external-chain wildcard.
func (c BitcoinMultisigCosigner) scriptExpression(scriptType BitcoinMultisigScriptType) (string, error) {
	xpub := strings.TrimSpace(c.AccountXPub)
	if xpub == "" {
		return "", fmt.Errorf("account extended public key is empty")
	}

	normalized, err := NormalizeBitcoinExtendedKey(xpub)
	if err != nil {
		return "", err
	}
	key, err := hdkeychain.NewKeyFromString(normalized)
	if err != nil {
		return "", fmt.Errorf("invalid account extended public key: %w", err)
	}
	if key.IsPrivate() {
		return "", fmt.Errorf("account key is private; provide an xpub, not an xprv")
	}

	origin := ""
	fingerprint := strings.ToLower(strings.TrimSpace(c.MasterFingerprint))
	if fingerprint != "" {
		if len(fingerprint) != fingerprintHexLen {
			return "", fmt.Errorf("master fingerprint %q must be 8 hex characters", fingerprint)
		}
		if _, decodeErr := hex.DecodeString(fingerprint); decodeErr != nil {
			return "", fmt.Errorf("master fingerprint %q is not hex: %w", fingerprint, decodeErr)
		}
		path := strings.TrimSpace(c.Derivation)
		if path == "" {
			path = scriptType.DerivationPath()
		}
		origin = "[" + fingerprint + "/" + strings.TrimPrefix(path, "m/") + "]"
	}

	return origin + key.String() + "/" + descriptorChangePos, nil
}

// newBitcoinMasterKey builds the BIP32 master key for a mnemonic.
func newBitcoinMasterKey(mnemonic, bip39Passphrase string) (*hdkeychain.ExtendedKey, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}
	return masterKey, nil
}

// encodeExtendedKey re-serializes an extended key with a BIP32 version prefix,
// used to produce SLIP-0132 ypub/zpub keys.
//
// This matches seedify.encodeExtendedKey.
func encodeExtendedKey(key *hdkeychain.ExtendedKey, version uint32) string {
	decoded, err := base58.Decode(key.String())
	if err != nil || len(decoded) < extendedKeyPayloadSize+extendedKeyChecksumSize {
		return ""
	}

	payload := decoded[:extendedKeyPayloadSize]
	versionBytes := make([]byte, 4) //nolint:mnd // BIP32 version field is 4 bytes.
	binary.BigEndian.PutUint32(versionBytes, version)
	copy(payload[:4], versionBytes)

	firstHash := sha256.Sum256(payload)
	secondHash := sha256.Sum256(firstHash[:])
	return base58.Encode(append(payload, secondHash[:extendedKeyChecksumSize]...))
}

// multisigRedeemScript builds an m-of-n OP_CHECKMULTISIG redeem script.
func multisigRedeemScript(pubKeys [][]byte, required int) ([]byte, error) {
	if len(pubKeys) == 0 {
		return nil, fmt.Errorf("multisig script needs at least one public key")
	}
	if required < 1 || required > len(pubKeys) {
		return nil, fmt.Errorf("required signatures %d out of range for %d keys", required, len(pubKeys))
	}

	requiredOp, err := smallIntOpcode(required)
	if err != nil {
		return nil, err
	}
	totalOp, err := smallIntOpcode(len(pubKeys))
	if err != nil {
		return nil, err
	}

	script := make([]byte, 0, multisigScriptOverhead+len(pubKeys)*(1+compressedKeyLen))
	script = append(script, requiredOp)
	for _, pubKey := range pubKeys {
		if len(pubKey) != compressedKeyLen {
			return nil, fmt.Errorf("public key must be %d bytes, got %d", compressedKeyLen, len(pubKey))
		}
		script = append(script, compressedKeyLen)
		script = append(script, pubKey...)
	}
	return append(script, totalOp, opCheckMultiSig), nil
}

// smallIntOpcode returns the OP_n opcode for 1..16.
func smallIntOpcode(n int) (byte, error) {
	if n < 1 || n > maxSmallInt {
		return 0, fmt.Errorf("value %d has no OP_n opcode", n)
	}
	return byte(opSmallIntBase + n), nil //nolint:gosec // n is bounded to 1..16 above.
}

// payToScriptHashAddress wraps a redeem script in a P2SH address.
func payToScriptHashAddress(redeemScript []byte) (string, error) {
	addr, err := btcutil.NewAddressScriptHashFromHash(btcutil.Hash160(redeemScript), &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create P2SH address: %w", err)
	}
	return addr.EncodeAddress(), nil
}

// witnessScriptHashScriptPubKey builds the v0 P2WSH scriptPubKey a nested
// SegWit P2SH address commits to.
func witnessScriptHashScriptPubKey(witnessScriptHash []byte) []byte {
	scriptPubKey := make([]byte, 0, witnessProgramOverhead+witnessProgramLen)
	scriptPubKey = append(scriptPubKey, opWitnessV0, witnessProgramLen)
	return append(scriptPubKey, witnessScriptHash...)
}
