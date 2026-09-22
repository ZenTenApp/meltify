package derive

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"ekyu.moe/cryptonight"
	"filippo.io/edwards25519"
	"github.com/chekist32/go-monero/utils"
	polyseed "github.com/complex-gh/polyseed_go"
	"github.com/mr-tron/base58"
)

// CryptonoteKeys holds a CryptoNote primary address and subaddresses.
type CryptonoteKeys struct {
	PrimaryAddress string
	Subaddresses   []string
}

const (
	polyseedKeySize            = 32
	moneroPrimaryPrefix        = 0x12
	moneroSubaddressPrefix     = 0x2A
	beldexSubaddrPrefixByte    = byte(116)
	cryptonotePubKeySize       = 32
	cryptonoteChecksumLen      = 4
	cryptonoteFullBlock        = 8
	cryptonoteFullEncodedBlock = 11
)

var beldexMainnetPrefix = []byte{0xD1, 0x01}

var moneroBase58PartialBlockSizes = [9]int{0, 2, 3, 5, 6, 7, 9, 10, 11}

// MoneroFromPolyseed derives Monero addresses from a 16-word polyseed.
//
// This matches seedify.DeriveMoneroKeys.
func MoneroFromPolyseed(mnemonic string, numSubaddresses int) (*CryptonoteKeys, error) {
	keyPair, err := moneroKeyPairFromPolyseed(mnemonic, "")
	if err != nil {
		return nil, err
	}
	return moneroKeysFromKeyPair(keyPair, numSubaddresses)
}

// MoneroFromLegacy derives Monero addresses from a 25-word legacy mnemonic.
//
// This matches seedify.DeriveMoneroKeysFromLegacySeed.
func MoneroFromLegacy(mnemonic string, numSubaddresses int) (*CryptonoteKeys, error) {
	keyPair, err := moneroKeyPairFromLegacySeed(mnemonic, "")
	if err != nil {
		return nil, err
	}
	return moneroKeysFromKeyPair(keyPair, numSubaddresses)
}

// BeldexFromLegacy derives Beldex addresses from a 25-word legacy mnemonic.
//
// This matches seedify.DeriveBeldexKeysFromLegacySeed.
func BeldexFromLegacy(mnemonic string, numSubaddresses int) (*CryptonoteKeys, error) {
	seed, err := utils.NewSeedMnemonic(mnemonic, utils.English)
	if err != nil {
		return nil, fmt.Errorf("failed to decode mnemonic: %w", err)
	}
	keyPair := seed.FullKeyPair()
	viewSecKey := keyPair.ViewKeyPair().PrivateKey().Bytes()
	spendPubKey := keyPair.SpendKeyPair().PublicKey().Bytes()
	viewPubKey := keyPair.ViewKeyPair().PublicKey().Bytes()

	primaryAddr, err := buildCryptonoteAddress(beldexMainnetPrefix, spendPubKey, viewPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to build Beldex primary address: %w", err)
	}

	subaddresses := make([]string, 0, numSubaddresses)
	for i := uint32(1); i <= uint32(numSubaddresses); i++ { //nolint:gosec
		subaddr, subErr := deriveBeldexSubaddress(viewSecKey, spendPubKey, 0, i)
		if subErr != nil {
			return nil, fmt.Errorf("failed to derive Beldex subaddress (0,%d): %w", i, subErr)
		}
		subaddresses = append(subaddresses, subaddr)
	}

	return &CryptonoteKeys{PrimaryAddress: primaryAddr, Subaddresses: subaddresses}, nil
}

func moneroKeyPairFromPolyseed(mnemonic, seedOffset string) (*utils.FullKeyPair, error) {
	seed, _, err := polyseed.Decode(mnemonic, polyseed.CoinMonero)
	if err != nil {
		return nil, fmt.Errorf("failed to decode polyseed mnemonic: %w", err)
	}
	defer seed.Free()

	spendKeyBytes := seed.Keygen(polyseed.CoinMonero, polyseedKeySize)
	reducedKey := scReduce32(spendKeyBytes)
	return moneroKeyPairFromSpendKey(reducedKey, seedOffset)
}

func moneroKeyPairFromLegacySeed(mnemonic, seedOffset string) (*utils.FullKeyPair, error) {
	seed, err := utils.NewSeedMnemonic(mnemonic, utils.English)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Monero legacy mnemonic: %w", err)
	}
	spendKey := seed.FullKeyPair().SpendKeyPair().PrivateKey().Bytes()
	return moneroKeyPairFromSpendKey(spendKey, seedOffset)
}

func moneroKeyPairFromSpendKey(spendKey []byte, seedOffset string) (*utils.FullKeyPair, error) {
	keyBytes, err := applyMoneroSeedOffset(spendKey, seedOffset)
	if err != nil {
		return nil, err
	}
	spendPrivKey, err := utils.NewPrivateKey(hex.EncodeToString(keyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create spend private key: %w", err)
	}
	keyPair, err := utils.NewFullKeyPairSpendPrivateKey(spendPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create Monero key pair: %w", err)
	}
	return keyPair, nil
}

func moneroKeysFromKeyPair(keyPair *utils.FullKeyPair, numSubaddresses int) (*CryptonoteKeys, error) {
	viewSecKey := keyPair.ViewKeyPair().PrivateKey().Bytes()
	spendPubKey := keyPair.SpendKeyPair().PublicKey().Bytes()
	viewPubKey := keyPair.ViewKeyPair().PublicKey().Bytes()

	primaryAddr, err := buildCryptonoteAddress([]byte{moneroPrimaryPrefix}, spendPubKey, viewPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to build primary address: %w", err)
	}

	subaddresses := make([]string, 0, numSubaddresses)
	for i := uint32(1); i <= uint32(numSubaddresses); i++ { //nolint:gosec
		subaddr, err := deriveMoneroSubaddress(viewSecKey, spendPubKey, 0, i)
		if err != nil {
			return nil, fmt.Errorf("failed to derive subaddress (0,%d): %w", i, err)
		}
		subaddresses = append(subaddresses, subaddr)
	}

	return &CryptonoteKeys{PrimaryAddress: primaryAddr, Subaddresses: subaddresses}, nil
}

func applyMoneroSeedOffset(spendKey []byte, seedOffset string) ([]byte, error) {
	if len(spendKey) != 32 { //nolint:mnd
		return nil, fmt.Errorf("monero seed offset: expected 32-byte spend key, got %d", len(spendKey))
	}
	keyScalar, err := edwards25519.NewScalar().SetCanonicalBytes(spendKey)
	if err != nil {
		return nil, fmt.Errorf("monero seed offset: invalid spend key scalar: %w", err)
	}
	if seedOffset == "" {
		return keyScalar.Bytes(), nil
	}

	offsetHash := cryptonight.Sum([]byte(seedOffset), 0)
	offsetScalar := scReduce32(offsetHash)
	offset, err := edwards25519.NewScalar().SetCanonicalBytes(offsetScalar)
	if err != nil {
		return nil, fmt.Errorf("monero seed offset: invalid offset scalar: %w", err)
	}
	return edwards25519.NewScalar().Subtract(keyScalar, offset).Bytes(), nil
}

func deriveMoneroSubaddress(viewSecretKey, spendPubKey []byte, major, minor uint32) (string, error) {
	subSpendPub, subViewPub, err := cryptonoteSubaddressPubs(viewSecretKey, spendPubKey, major, minor)
	if err != nil {
		return "", err
	}
	return buildCryptonoteAddress([]byte{moneroSubaddressPrefix}, subSpendPub, subViewPub)
}

func deriveBeldexSubaddress(viewSecretKey, spendPubKey []byte, major, minor uint32) (string, error) {
	subSpendPub, subViewPub, err := cryptonoteSubaddressPubs(viewSecretKey, spendPubKey, major, minor)
	if err != nil {
		return "", err
	}
	return buildCryptonoteAddress([]byte{beldexSubaddrPrefixByte}, subSpendPub, subViewPub)
}

func cryptonoteSubaddressPubs(viewSecretKey, spendPubKey []byte, major, minor uint32) ([]byte, []byte, error) {
	if major == 0 && minor == 0 {
		return nil, nil, fmt.Errorf("(0,0) is the primary address, not a subaddress")
	}

	prefix := []byte("SubAddr\x00")
	majorBytes := make([]byte, 4) //nolint:mnd
	minorBytes := make([]byte, 4) //nolint:mnd
	binary.LittleEndian.PutUint32(majorBytes, major)
	binary.LittleEndian.PutUint32(minorBytes, minor)

	data := make([]byte, 0, len(prefix)+32+8) //nolint:mnd
	data = append(data, prefix...)
	data = append(data, viewSecretKey...)
	data = append(data, majorBytes...)
	data = append(data, minorBytes...)

	hash, err := utils.Keccak256Hash(data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to hash subaddress data: %w", err)
	}
	m := scReduce32(hash)

	mScalar, err := edwards25519.NewScalar().SetCanonicalBytes(m)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create scalar from m: %w", err)
	}
	mG := edwards25519.NewIdentityPoint().ScalarBaseMult(mScalar)

	spendPubPoint, err := edwards25519.NewIdentityPoint().SetBytes(spendPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse spend public key: %w", err)
	}
	subSpendPub := edwards25519.NewIdentityPoint().Add(spendPubPoint, mG)

	viewSecScalar, err := edwards25519.NewScalar().SetCanonicalBytes(viewSecretKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create scalar from view secret: %w", err)
	}
	subViewPub := edwards25519.NewIdentityPoint().ScalarMult(viewSecScalar, subSpendPub)
	return subSpendPub.Bytes(), subViewPub.Bytes(), nil
}

func buildCryptonoteAddress(prefixBytes, spendPubKey, viewPubKey []byte) (string, error) {
	addrData := make([]byte, len(prefixBytes)+cryptonotePubKeySize+cryptonotePubKeySize)
	copy(addrData, prefixBytes)
	copy(addrData[len(prefixBytes):], spendPubKey)
	copy(addrData[len(prefixBytes)+cryptonotePubKeySize:], viewPubKey)

	checksum, err := utils.Keccak256Hash(addrData)
	if err != nil {
		return "", fmt.Errorf("failed to calculate address checksum: %w", err)
	}

	fullAddr := append(addrData, checksum[:cryptonoteChecksumLen]...)
	return string(moneroBase58Encode(fullAddr)), nil
}

func moneroBase58Encode(rawBytes []byte) []byte {
	n := len(rawBytes)
	fullBlocks := n / cryptonoteFullBlock
	remainder := n % cryptonoteFullBlock

	outputSize := fullBlocks*cryptonoteFullEncodedBlock + moneroBase58PartialBlockSizes[remainder]
	res := make([]byte, outputSize)

	for i := range fullBlocks {
		start := i * cryptonoteFullBlock
		enc := []byte(base58.Encode(rawBytes[start : start+cryptonoteFullBlock]))
		offset := i * cryptonoteFullEncodedBlock
		pad := cryptonoteFullEncodedBlock - len(enc)
		for j := range pad {
			res[offset+j] = '1'
		}
		copy(res[offset+pad:], enc)
	}

	if remainder > 0 {
		enc := []byte(base58.Encode(rawBytes[fullBlocks*cryptonoteFullBlock:]))
		partialSize := moneroBase58PartialBlockSizes[remainder]
		offset := fullBlocks * cryptonoteFullEncodedBlock
		pad := partialSize - len(enc)
		for j := range pad {
			res[offset+j] = '1'
		}
		copy(res[offset+pad:], enc)
	}
	return res
}

func scReduce32(input []byte) []byte {
	if len(input) != 32 { //nolint:mnd
		return input
	}
	scalar, err := edwards25519.NewScalar().SetCanonicalBytes(input)
	if err == nil {
		return scalar.Bytes()
	}
	padded := make([]byte, 64) //nolint:mnd
	copy(padded, input)
	scalar, err = edwards25519.NewScalar().SetUniformBytes(padded)
	if err != nil {
		result := make([]byte, 32) //nolint:mnd
		copy(result, input)
		result[31] &= 0x0F
		return result
	}
	return scalar.Bytes()
}
