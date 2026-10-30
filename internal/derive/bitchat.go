package derive

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// BitChat domain-separation labels. These are meltify-native: BitChat itself
// specifies no mapping from an SSH seed, and seedify has no BitChat domain.
const (
	bitchatNoiseLabel  = "bitchat:noise:"
	bitchatSignLabel   = "bitchat:sign:"
	bitchatDeviceLabel = "bitchat:device-seed:"

	// bitchatPeerIDSize is the number of leading bytes of SHA-256(noise_pub)
	// used as the mesh peer ID (16 lowercase hex characters).
	bitchatPeerIDSize = 8

	// RFC 7748 §5 X25519 scalar clamping constants.
	bitchatClampClearLow  = 248
	bitchatClampClearHigh = 127
	bitchatClampSetBit    = 64
)

// BitChatKeys holds the four long-term secrets that make up a BitChat identity,
// plus the derived public material. The nickname BitChat also stores is chosen
// by the user and is not part of this struct.
type BitChatKeys struct {
	// NoisePrivateKey is the 32-byte clamped X25519 static scalar.
	NoisePrivateKey []byte

	// NoisePublicKey is the X25519 static public key.
	NoisePublicKey []byte

	// NoiseFingerprint is SHA-256(NoisePublicKey), the 32-byte identity
	// fingerprint BitChat shows for a peer.
	NoiseFingerprint []byte

	// SigningSeed is the 32-byte Ed25519 seed used for announces, packets and
	// vouches.
	SigningSeed []byte

	// SigningPublicKey is the Ed25519 public key for SigningSeed.
	SigningPublicKey []byte

	// DeviceSeed is the 32-byte HMAC-SHA256 key behind per-geohash and bridge
	// Nostr identities.
	DeviceSeed []byte

	// PeerID is the 8-byte mesh peer ID: SHA-256(NoisePublicKey)[:8].
	PeerID []byte

	// Nostr holds the NIP-06 keys derived from Mnemonic24 of the same seed, so
	// a meltify identity keeps one nsec across meltify-info and BitChat.
	Nostr *NostrKeys
}

// PeerIDHex returns the mesh peer ID as 16 lowercase hex characters.
func (k *BitChatKeys) PeerIDHex() string {
	return hex.EncodeToString(k.PeerID)
}

// BitChat derives a deterministic BitChat identity from an Ed25519 private key.
//
// BitChat (iOS/Android) generates four independent random secrets and has no
// import path, so this mapping is meltify's own. All inputs come from the same
// Ed25519 seed S:
//
//	noise    = X25519(SHA-256("bitchat:noise:"       || S))    # clamped
//	sign     = Ed25519(SHA-256("bitchat:sign:"       || S))
//	device   =          SHA-256("bitchat:device-seed:" || S)
//	nostr    = NIP-06 of Mnemonic24(S)                         # same nsec as meltify-info
//	peer-id  = SHA-256(noise_pub)[:8]
//
// Security note: the derived identity is cryptographically linked to the source
// SSH key. Compromising either key compromises both.
func BitChat(key *ed25519.PrivateKey) (*BitChatKeys, error) {
	if key == nil {
		return nil, errors.New("ed25519 key is required")
	}
	seed := key.Seed()

	noisePrivScalar, noisePubKey, err := bitchatNoiseKeypair(seed)
	if err != nil {
		return nil, err
	}

	signSeed := bitchatSHA256(bitchatSignLabel, seed)
	signPrivKey := ed25519.NewKeyFromSeed(signSeed)
	signPubKey, ok := signPrivKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("derived BitChat signing key is not Ed25519")
	}

	deviceSeed := bitchatSHA256(bitchatDeviceLabel, seed)

	noiseFingerprint := sha256.Sum256(noisePubKey)
	peerID := bitchatPeerIDFromFingerprint(noiseFingerprint[:])

	mnemonic24, err := Mnemonic24(key)
	if err != nil {
		return nil, fmt.Errorf("bitchat: could not generate 24-word MELT mnemonic: %w", err)
	}
	nostrKeys, err := NostrKeysFromMnemonic(mnemonic24, "")
	if err != nil {
		return nil, fmt.Errorf("bitchat: could not derive Nostr keys: %w", err)
	}

	return &BitChatKeys{
		NoisePrivateKey:  noisePrivScalar,
		NoisePublicKey:   noisePubKey,
		NoiseFingerprint: noiseFingerprint[:],
		SigningSeed:      signSeed,
		SigningPublicKey: signPubKey,
		DeviceSeed:       deviceSeed,
		PeerID:           peerID,
		Nostr:            nostrKeys,
	}, nil
}

// BitChatPeerID returns the 16-character BitChat mesh peer ID for key:
// SHA-256(noise_pub)[:8], lowercase hex — the same value meltify-bitchat prints
// as bitchat:<peer-id>.
func BitChatPeerID(key *ed25519.PrivateKey) (string, error) {
	if key == nil {
		return "", errors.New("ed25519 key is required")
	}
	_, noisePubKey, err := bitchatNoiseKeypair(key.Seed())
	if err != nil {
		return "", err
	}
	fingerprint := sha256.Sum256(noisePubKey)
	return hex.EncodeToString(bitchatPeerIDFromFingerprint(fingerprint[:])), nil
}

// bitchatNoiseKeypair returns the clamped X25519 static scalar and its public key.
func bitchatNoiseKeypair(seed []byte) ([]byte, []byte, error) {
	scalar := bitchatX25519Scalar(bitchatNoiseLabel, seed)
	pub, err := curve25519.X25519(scalar, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("bitchat: noise public key derivation failed: %w", err)
	}
	return scalar, pub, nil
}

// bitchatPeerIDFromFingerprint takes the leading bytes of SHA-256(noise_pub).
func bitchatPeerIDFromFingerprint(fingerprint []byte) []byte {
	peerID := make([]byte, bitchatPeerIDSize)
	copy(peerID, fingerprint[:bitchatPeerIDSize])
	return peerID
}

// bitchatSHA256 returns SHA-256(label || seed).
func bitchatSHA256(label string, seed []byte) []byte {
	input := make([]byte, len(label)+len(seed))
	copy(input, label)
	copy(input[len(label):], seed)
	sum := sha256.Sum256(input)
	return sum[:]
}

// bitchatX25519Scalar returns SHA-256(label || seed) clamped per RFC 7748 §5.
func bitchatX25519Scalar(label string, seed []byte) []byte {
	scalar := bitchatSHA256(label, seed)
	scalar[0] &= bitchatClampClearLow
	scalar[31] &= bitchatClampClearHigh
	scalar[31] |= bitchatClampSetBit
	return scalar
}
