package derive

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestBitChatRejectsNilKey(t *testing.T) {
	t.Parallel()
	if _, err := BitChat(nil); err == nil {
		t.Fatal("BitChat(nil) succeeded, want error")
	}
}

func TestBitChatMatchesGolden(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	keys, err := BitChat(&key)
	if err != nil {
		t.Fatalf("BitChat: %v", err)
	}

	assertEq(t, "noise private key", hex.EncodeToString(keys.NoisePrivateKey), GoldenBitChatNoisePrivateKey)
	assertEq(t, "noise public key", hex.EncodeToString(keys.NoisePublicKey), GoldenBitChatNoisePublicKey)
	assertEq(t, "noise fingerprint", hex.EncodeToString(keys.NoiseFingerprint), GoldenBitChatNoiseFingerprint)
	assertEq(t, "signing seed", hex.EncodeToString(keys.SigningSeed), GoldenBitChatSigningSeed)
	assertEq(t, "signing public key", hex.EncodeToString(keys.SigningPublicKey), GoldenBitChatSigningPublicKey)
	assertEq(t, "device seed", hex.EncodeToString(keys.DeviceSeed), GoldenBitChatDeviceSeed)
	assertEq(t, "peer id", keys.PeerIDHex(), GoldenBitChatPeerID)
}

// TestBitChatNostrSliceMatchesInfo locks the one piece of the identity that is
// not meltify-native: BitChat's nsec is NIP-06 of the same 24-word MELT phrase,
// so it must equal what meltify-info prints for the same seed.
func TestBitChatNostrSliceMatchesInfo(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	keys, err := BitChat(&key)
	if err != nil {
		t.Fatalf("BitChat: %v", err)
	}
	if keys.Nostr == nil {
		t.Fatal("nostr slice is nil")
	}
	assertEq(t, "nsec", keys.Nostr.Nsec, GoldenNsec)
	assertEq(t, "npub", keys.Nostr.Npub, GoldenNpub)
	assertEq(t, "pubkey hex", keys.Nostr.PubKeyHex, GoldenPubHex)
	assertEq(t, "privkey hex", keys.Nostr.PrivKeyHex, GoldenPrivHex)
}

func TestBitChatNoiseKeyIsClampedX25519(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	keys, err := BitChat(&key)
	if err != nil {
		t.Fatalf("BitChat: %v", err)
	}

	if len(keys.NoisePrivateKey) != 32 || len(keys.NoisePublicKey) != 32 {
		t.Fatalf("noise key lengths = %d/%d, want 32/32",
			len(keys.NoisePrivateKey), len(keys.NoisePublicKey))
	}
	if keys.NoisePrivateKey[0]&0x07 != 0 {
		t.Fatalf("scalar low bits not cleared: %02x", keys.NoisePrivateKey[0])
	}
	if keys.NoisePrivateKey[31]&0x80 != 0 {
		t.Fatalf("scalar high bit not cleared: %02x", keys.NoisePrivateKey[31])
	}
	if keys.NoisePrivateKey[31]&0x40 == 0 {
		t.Fatalf("scalar bit 6 not set: %02x", keys.NoisePrivateKey[31])
	}

	// Recompute the public key independently from the derived scalar.
	wantPub, err := curve25519.X25519(keys.NoisePrivateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("X25519: %v", err)
	}
	assertEq(t, "recomputed noise public key", hex.EncodeToString(keys.NoisePublicKey), hex.EncodeToString(wantPub))

	// The signing key must be a real Ed25519 key pair for the derived seed.
	signPriv := ed25519.NewKeyFromSeed(keys.SigningSeed)
	wantSignPub, ok := signPriv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("derived signing key is not Ed25519")
	}
	assertEq(t, "recomputed signing public key", hex.EncodeToString(keys.SigningPublicKey), hex.EncodeToString(wantSignPub))
}

func TestBitChatPeerIDIsFingerprintPrefix(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	keys, err := BitChat(&key)
	if err != nil {
		t.Fatalf("BitChat: %v", err)
	}
	if len(keys.PeerID) != bitchatPeerIDSize {
		t.Fatalf("peer id length = %d, want %d", len(keys.PeerID), bitchatPeerIDSize)
	}
	assertEq(t, "peer id", keys.PeerIDHex(), hex.EncodeToString(keys.NoiseFingerprint[:bitchatPeerIDSize]))
	if len(keys.PeerIDHex()) != 16 {
		t.Fatalf("peer id hex = %q, want 16 characters", keys.PeerIDHex())
	}
}

func TestBitChatDiffersByKey(t *testing.T) {
	t.Parallel()
	firstKey := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	first, err := BitChat(&firstKey)
	if err != nil {
		t.Fatalf("BitChat(first): %v", err)
	}

	otherSeed := make([]byte, 32)
	copy(otherSeed, FixedSeed00to1f)
	otherSeed[0] ^= 0xff
	secondKey := ed25519.NewKeyFromSeed(otherSeed)
	second, err := BitChat(&secondKey)
	if err != nil {
		t.Fatalf("BitChat(second): %v", err)
	}

	if first.PeerIDHex() == second.PeerIDHex() ||
		hex.EncodeToString(first.NoisePrivateKey) == hex.EncodeToString(second.NoisePrivateKey) ||
		hex.EncodeToString(first.SigningSeed) == hex.EncodeToString(second.SigningSeed) ||
		hex.EncodeToString(first.DeviceSeed) == hex.EncodeToString(second.DeviceSeed) {
		t.Fatal("different keys produced the same BitChat identity")
	}
}

// TestBitChatSubkeysAreDomainSeparated guards against one label leaking into
// another: every 32-byte component must be distinct for the same seed.
func TestBitChatSubkeysAreDomainSeparated(t *testing.T) {
	t.Parallel()
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	keys, err := BitChat(&key)
	if err != nil {
		t.Fatalf("BitChat: %v", err)
	}

	seen := map[string]string{
		"noise":    hex.EncodeToString(keys.NoisePrivateKey),
		"signing":  hex.EncodeToString(keys.SigningSeed),
		"device":   hex.EncodeToString(keys.DeviceSeed),
		"ssh seed": hex.EncodeToString(key.Seed()),
	}
	distinct := make(map[string]struct{}, len(seen))
	for name, value := range seen {
		if _, dup := distinct[value]; dup {
			t.Fatalf("%s duplicates another sub-key", name)
		}
		distinct[value] = struct{}{}
	}
}
