package derive

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/mr-tron/base58"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/blake2b"
)

const rippleAlphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

// Litecoin derives a BIP84 P2WPKH address at m/84'/2'/0'/0/0.
func Litecoin(mnemonic, bip39Passphrase string) (string, error) {
	pubKeyHash, err := deriveBIPAddress(mnemonic, bip39Passphrase, 84, 2) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive Litecoin key: %w", err)
	}
	addr, err := encodeBech32Address("ltc", 0, pubKeyHash)
	if err != nil {
		return "", fmt.Errorf("failed to encode Litecoin address: %w", err)
	}
	return addr, nil
}

// Dogecoin derives a BIP44 P2PKH address at m/44'/3'/0'/0/0.
func Dogecoin(mnemonic, bip39Passphrase string) (string, error) {
	pubKeyHash, err := deriveBIPAddress(mnemonic, bip39Passphrase, 44, 3) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive Dogecoin key: %w", err)
	}
	return encodeBase58Check(0x1E, pubKeyHash), nil //nolint:mnd
}

// Cosmos derives a BIP44 Bech32 address at m/44'/118'/0'/0/0.
func Cosmos(mnemonic, bip39Passphrase string) (string, error) {
	return cosmosBech32(mnemonic, bip39Passphrase, 118, "cosmos") //nolint:mnd
}

// Ripple derives a BIP44 XRP address at m/44'/144'/0'/0/0.
func Ripple(mnemonic, bip39Passphrase string) (string, error) {
	pubKeyHash, err := deriveBIPAddress(mnemonic, bip39Passphrase, 44, 144) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive Ripple key: %w", err)
	}
	return encodeRippleBase58Check(0x00, pubKeyHash), nil //nolint:mnd
}

// Stellar derives a SEP-0005 Ed25519 address at m/44'/148'/0'.
func Stellar(mnemonic, bip39Passphrase string) (string, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}
	key := deriveEd25519Key(seed, []uint32{44, 148, 0})
	privateKey := ed25519.NewKeyFromSeed(key)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return encodeStellarStrKey(0x30, publicKey), nil //nolint:mnd
}

// Sui derives a SLIP-0010 Ed25519 address at m/44'/784'/0'/0'/0'.
func Sui(mnemonic, bip39Passphrase string) (string, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}
	key := deriveEd25519Key(seed, []uint32{44, 784, 0, 0, 0})
	privateKey := ed25519.NewKeyFromSeed(key)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	payload := make([]byte, 0, 1+len(publicKey))
	payload = append(payload, 0x00) //nolint:mnd // Ed25519 flag byte
	payload = append(payload, publicKey...)
	hash := blake2b.Sum256(payload)
	return fmt.Sprintf("0x%s", hex.EncodeToString(hash[:])), nil
}

// SilentPayment derives a BIP 352 sp1 address (scan m/352'/0'/0'/1'/0, spend m/352'/0'/0'/0'/0).
func SilentPayment(mnemonic, bip39Passphrase string) (string, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create master key: %w", err)
	}

	scanPath := []uint32{
		hdkeychain.HardenedKeyStart + 352,
		hdkeychain.HardenedKeyStart + 0,
		hdkeychain.HardenedKeyStart + 0,
		hdkeychain.HardenedKeyStart + 1,
		0,
	}
	scanKey, err := deriveBIP32Path(masterKey, scanPath)
	if err != nil {
		return "", fmt.Errorf("failed to derive scan key: %w", err)
	}
	scanPubKey, err := scanKey.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get scan public key: %w", err)
	}
	scanPubBytes := scanPubKey.SerializeCompressed()
	if len(scanPubBytes) != 33 { //nolint:mnd
		return "", fmt.Errorf("scan public key must be 33 bytes, got %d", len(scanPubBytes))
	}

	spendPath := []uint32{
		hdkeychain.HardenedKeyStart + 352,
		hdkeychain.HardenedKeyStart + 0,
		hdkeychain.HardenedKeyStart + 0,
		hdkeychain.HardenedKeyStart + 0,
		0,
	}
	spendKey, err := deriveBIP32Path(masterKey, spendPath)
	if err != nil {
		return "", fmt.Errorf("failed to derive spend key: %w", err)
	}
	spendPubKey, err := spendKey.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get spend public key: %w", err)
	}
	spendPubBytes := spendPubKey.SerializeCompressed()
	if len(spendPubBytes) != 33 { //nolint:mnd
		return "", fmt.Errorf("spend public key must be 33 bytes, got %d", len(spendPubBytes))
	}

	data := make([]byte, 0, 66) //nolint:mnd
	data = append(data, scanPubBytes...)
	data = append(data, spendPubBytes...)
	converted, err := bech32.ConvertBits(data, 8, 5, true) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to convert bits for sp1 address: %w", err)
	}
	finalData := make([]byte, 0, 1+len(converted))
	finalData = append(finalData, 0)
	finalData = append(finalData, converted...)
	encoded, err := bech32.EncodeM("sp", finalData)
	if err != nil {
		return "", fmt.Errorf("failed to encode sp1 address: %w", err)
	}
	return encoded, nil
}

func deriveBIP32Path(masterKey *hdkeychain.ExtendedKey, path []uint32) (*hdkeychain.ExtendedKey, error) {
	key := masterKey
	var err error
	for _, index := range path {
		key, err = key.Derive(index)
		if err != nil {
			return nil, fmt.Errorf("failed to derive at index %d: %w", index, err)
		}
	}
	return key, nil
}

func deriveBIPAddress(mnemonic string, bip39Passphrase string, purpose, coinType uint32) ([]byte, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}
	path := []uint32{
		hdkeychain.HardenedKeyStart + purpose,
		hdkeychain.HardenedKeyStart + coinType,
		hdkeychain.HardenedKeyStart + 0,
		0,
		0,
	}
	addressKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}
	pubKey, err := addressKey.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}
	return btcutil.Hash160(pubKey.SerializeCompressed()), nil
}

func encodeBech32Address(hrp string, witnessVersion byte, witnessProgram []byte) (string, error) {
	converted, err := bech32.ConvertBits(witnessProgram, 8, 5, true) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %w", err)
	}
	data := make([]byte, 0, 1+len(converted))
	data = append(data, witnessVersion)
	data = append(data, converted...)
	encoded, err := bech32.Encode(hrp, data)
	if err != nil {
		return "", fmt.Errorf("failed to encode bech32: %w", err)
	}
	return encoded, nil
}

func encodeBase58Check(version byte, payload []byte) string {
	data := make([]byte, 0, 1+len(payload)+4) //nolint:mnd
	data = append(data, version)
	data = append(data, payload...)
	firstHash := sha256.Sum256(data)
	secondHash := sha256.Sum256(firstHash[:])
	data = append(data, secondHash[:4]...)
	return base58.Encode(data)
}

func encodeRippleBase58Check(version byte, payload []byte) string {
	data := make([]byte, 0, 1+len(payload)+4) //nolint:mnd
	data = append(data, version)
	data = append(data, payload...)
	firstHash := sha256.Sum256(data)
	secondHash := sha256.Sum256(firstHash[:])
	data = append(data, secondHash[:4]...)
	return encodeBase58WithAlphabet(data, rippleAlphabet)
}

func encodeBase58WithAlphabet(data []byte, alphabet string) string {
	standardAlphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	encoded := base58.Encode(data)
	var result strings.Builder
	result.Grow(len(encoded))
	for _, c := range encoded {
		idx := strings.IndexRune(standardAlphabet, c)
		if idx >= 0 {
			result.WriteByte(alphabet[idx])
		}
	}
	return result.String()
}

func cosmosBech32(mnemonic, bip39Passphrase string, coinType uint32, hrp string) (string, error) {
	pubKeyHash, err := deriveBIPAddress(mnemonic, bip39Passphrase, 44, coinType) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive %s key: %w", hrp, err)
	}
	converted, err := bech32.ConvertBits(pubKeyHash, 8, 5, true) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to convert bits for %s address: %w", hrp, err)
	}
	encoded, err := bech32.Encode(hrp, converted)
	if err != nil {
		return "", fmt.Errorf("failed to encode %s address: %w", hrp, err)
	}
	return encoded, nil
}

func encodeStellarStrKey(version byte, payload []byte) string {
	data := make([]byte, 0, 1+len(payload))
	data = append(data, version)
	data = append(data, payload...)
	checksum := crc16xmodem(data)
	data = append(data, byte(checksum&0xFF), byte(checksum>>8)) //nolint:mnd
	return base32Encode(data)
}

func crc16xmodem(data []byte) uint16 {
	crc := uint16(0)
	for _, b := range data {
		crc ^= uint16(b) << 8 //nolint:mnd
		for range 8 {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021 //nolint:mnd
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

func base32Encode(data []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var result strings.Builder
	result.Grow((len(data)*8 + 4) / 5) //nolint:mnd
	bits := 0
	buffer := 0
	for _, b := range data {
		buffer = (buffer << 8) | int(b) //nolint:mnd
		bits += 8
		for bits >= 5 {
			bits -= 5
			result.WriteByte(alphabet[(buffer>>bits)&0x1F])
		}
	}
	if bits > 0 {
		result.WriteByte(alphabet[(buffer<<(5-bits))&0x1F]) //nolint:mnd
	}
	return result.String()
}
