package derive

import (
	"fmt"

	nostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip06"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/tyler-smith/go-bip39"
)

// NostrKeys holds NIP-06 keys derived from a BIP39 mnemonic.
type NostrKeys struct {
	Npub       string
	Nsec       string
	PubKeyHex  string
	PrivKeyHex string
}

// NostrKeysFromMnemonic derives Nostr keys from a BIP39 mnemonic via NIP-06
// path m/44'/1237'/0'/0/0.
//
// This matches seedify.DeriveNostrKeysWithHex.
func NostrKeysFromMnemonic(mnemonic, bip39Passphrase string) (*NostrKeys, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return nil, fmt.Errorf("invalid mnemonic: %w", err)
	}

	privateKeyHex, err := nip06.PrivateKeyFromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to derive private key from seed: %w", err)
	}

	publicKeyHex, err := nostr.GetPublicKey(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	npub, err := nip19.EncodePublicKey(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}

	nsec, err := nip19.EncodePrivateKey(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	return &NostrKeys{
		Npub:       npub,
		Nsec:       nsec,
		PubKeyHex:  publicKeyHex,
		PrivKeyHex: privateKeyHex,
	}, nil
}
