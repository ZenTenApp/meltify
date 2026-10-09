package derive

import (
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/tyler-smith/go-bip39"
)

const (
	cakeBIP44Purpose = 44
	cakeMoneroCoin   = 128
	cakeKeySize      = 32
)

// ed25519Order is the Ed25519/Monero curve order l
// (2^252 + 27742317777372353535851937790883648493).
var ed25519Order = mustBigInt("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED")

func mustBigInt(hexDigits string) *big.Int {
	n, ok := new(big.Int).SetString(hexDigits, 16) //nolint:mnd
	if !ok {
		panic("derive: invalid ed25519 order constant")
	}
	return n
}

// CakeSpendKey returns the 32-byte Monero spend key Cake Wallet / Unstoppable
// Wallet derive from a BIP39 mnemonic.
//
// Pipeline (Cake Wallet, no Keccak — unlike Ledger):
//
//  1. BIP39 seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase)
//  2. BIP32 path m/44'/128'/account'/0/0
//  3. Interpret the 32-byte secp256k1 privkey as little-endian, mod l
//
// Empty passphrase and account 0 match Unstoppable's BIP39 Monero account.
func CakeSpendKey(mnemonic, bip39Passphrase string, account uint32) ([]byte, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	path := []uint32{
		hdkeychain.HardenedKeyStart + cakeBIP44Purpose,
		hdkeychain.HardenedKeyStart + cakeMoneroCoin,
		hdkeychain.HardenedKeyStart + account,
		0,
		0,
	}
	addressKey, err := deriveBIP32Path(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("failed to derive cake wallet path: %w", err)
	}

	privKey, err := addressKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}

	serialized := privKey.Serialize()
	if len(serialized) != cakeKeySize {
		return nil, fmt.Errorf("cake wallet private key: expected %d bytes, got %d", cakeKeySize, len(serialized))
	}
	return cakeReduceECKey(serialized), nil
}

// cakeReduceECKey matches CakeWalletStyleConverter.reduceECKey: read the
// 32-byte buffer as little-endian, reduce modulo the Ed25519 order, write
// little-endian 32 bytes. No Keccak.
func cakeReduceECKey(buffer []byte) []byte {
	n := new(big.Int).SetBytes(reverseBytes(buffer))
	n.Mod(n, ed25519Order)

	be := n.FillBytes(make([]byte, cakeKeySize))
	return reverseBytes(be)
}

func reverseBytes(in []byte) []byte {
	out := make([]byte, len(in))
	for i := range in {
		out[len(in)-1-i] = in[i]
	}
	return out
}
