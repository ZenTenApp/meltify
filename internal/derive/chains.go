package derive

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/mr-tron/base58"
	hdwallet "github.com/stephenlacy/go-ethereum-hdwallet"
	"github.com/tyler-smith/go-bip39"
)

// BitcoinNativeSegwit derives a BIP84 P2WPKH address at m/84'/0'/0'/0/0.
//
// This matches seedify.DeriveBitcoinAddressNativeSegwit.
func BitcoinNativeSegwit(mnemonic, bip39Passphrase string) (string, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create master key: %w", err)
	}

	purpose, err := masterKey.Derive(hdkeychain.HardenedKeyStart + 84) //nolint:mnd
	if err != nil {
		return "", fmt.Errorf("failed to derive purpose: %w", err)
	}
	coinType, err := purpose.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", fmt.Errorf("failed to derive coin type: %w", err)
	}
	account, err := coinType.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", fmt.Errorf("failed to derive account: %w", err)
	}
	change, err := account.Derive(0)
	if err != nil {
		return "", fmt.Errorf("failed to derive change: %w", err)
	}
	addressIndex, err := change.Derive(0)
	if err != nil {
		return "", fmt.Errorf("failed to derive address index: %w", err)
	}

	pubKey, err := addressIndex.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %w", err)
	}

	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("failed to create address: %w", err)
	}
	return addr.EncodeAddress(), nil
}

// Ethereum derives a BIP44 address at m/44'/60'/0'/0/0.
//
// This matches seedify.DeriveEthereumAddress.
func Ethereum(mnemonic, bip39Passphrase string) (string, error) {
	wallet, err := ethereumWallet(mnemonic, bip39Passphrase)
	if err != nil {
		return "", err
	}
	path := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0")
	account, err := wallet.Derive(path, false)
	if err != nil {
		return "", fmt.Errorf("failed to derive account: %w", err)
	}
	return account.Address.Hex(), nil
}

// Tron derives a BIP44 address at m/44'/195'/0'/0/0.
//
// Same 20-byte Keccak payload as Ethereum, encoded as Base58Check with prefix 0x41.
// This matches seedify.DeriveTronAddress.
func Tron(mnemonic, bip39Passphrase string) (string, error) {
	wallet, err := ethereumWallet(mnemonic, bip39Passphrase)
	if err != nil {
		return "", err
	}
	path := hdwallet.MustParseDerivationPath("m/44'/195'/0'/0/0")
	account, err := wallet.Derive(path, false)
	if err != nil {
		return "", fmt.Errorf("failed to derive account: %w", err)
	}
	return encodeTronAddress(account.Address.Bytes()), nil
}

// Solana derives a SLIP-0010 Ed25519 address at m/44'/501'/0'/0'.
//
// This matches seedify.DeriveSolanaAddress.
func Solana(mnemonic, bip39Passphrase string) (string, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}
	key := deriveEd25519Key(seed, []uint32{44, 501, 0, 0})
	privateKey := ed25519.NewKeyFromSeed(key)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return base58.Encode(publicKey), nil
}

func ethereumWallet(mnemonic, bip39Passphrase string) (*hdwallet.Wallet, error) {
	var (
		wallet *hdwallet.Wallet
		err    error
	)
	if bip39Passphrase != "" {
		seed, seedErr := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
		if seedErr != nil {
			return nil, fmt.Errorf("invalid mnemonic: %w", seedErr)
		}
		wallet, err = hdwallet.NewFromSeed(seed)
	} else {
		wallet, err = hdwallet.NewFromMnemonic(mnemonic)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create wallet from mnemonic: %w", err)
	}
	return wallet, nil
}

func encodeTronAddress(addrBytes []byte) string {
	payload := make([]byte, 0, 25)  //nolint:mnd // 1 prefix + 20 address + 4 checksum
	payload = append(payload, 0x41) //nolint:mnd // Tron mainnet address prefix
	payload = append(payload, addrBytes...)
	firstHash := sha256.Sum256(payload)
	secondHash := sha256.Sum256(firstHash[:])
	payload = append(payload, secondHash[:4]...)
	return base58.Encode(payload)
}

// deriveEd25519Key implements SLIP-0010 Ed25519 hierarchical derivation.
func deriveEd25519Key(seed []byte, path []uint32) []byte {
	h := hmac.New(sha512.New, []byte("ed25519 seed"))
	h.Write(seed)
	sum := h.Sum(nil)
	key := sum[:32]
	chainCode := sum[32:]

	for _, index := range path {
		hardenedIndex := index + 0x80000000 //nolint:mnd
		data := make([]byte, 37)            //nolint:mnd
		data[0] = 0x00
		copy(data[1:33], key)
		binary.BigEndian.PutUint32(data[33:], hardenedIndex)

		h = hmac.New(sha512.New, chainCode)
		h.Write(data)
		sum = h.Sum(nil)
		key = sum[:32]
		chainCode = sum[32:]
	}
	return key
}
