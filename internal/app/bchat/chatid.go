// Package bchat derives Beldex BChat identities from Ed25519 seed material.
//
// A Beldex BChat chat ID is the account's X25519 public key prefixed with the
// DJB/Curve25519 type tag 0xBD, hex-encoded lowercase:
//
//	chatID = hex(0xBD || x25519_public_key)   // 66 hex chars, starts "bd"
//
// This matches bchat-android's KeyPairUtilities: the app derives an ed25519
// keypair directly from the raw 32-byte seed (libsodium crypto_sign_seed_keypair,
// no scReduce32) and converts the public key to X25519 with libsodium's
// crypto_sign_ed25519_pk_to_curve25519 (u = (1+y)/(1-y) mod p), then stores
// Base64(x25519_pub.serialize()) where serialize prepends the 0xBD type byte.
// The 66-hex string is what BChat users share and what the app's report-issue
// account uses (REPORT_ISSUE_ID in build.gradle: "bd27b58b...3952").
package bchat

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"filippo.io/edwards25519"
)

// chatIDTypeTag is the DJB/Curve25519 type byte (Curve.DJB_TYPE = 189 = 0xBD)
// that bchat-android prepends when serializing an X25519 public key.
const chatIDTypeTag = byte(0xBD)

// DeriveChatID derives the Beldex BChat chat ID from a raw 32-byte Ed25519
// seed. The seed is the same one meltify emits; no scReduce32 is applied here
// (unlike the CryptoNote legacy seed).
func DeriveChatID(seed []byte) (string, error) {
	if len(seed) != ed25519.SeedSize {
		return "", fmt.Errorf("bchat chat id: expected %d-byte seed, got %d", ed25519.SeedSize, len(seed))
	}

	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	point, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return "", fmt.Errorf("bchat chat id: invalid ed25519 public key: %w", err)
	}
	// BytesMontgomery maps the Edwards point to the Curve25519 u-coordinate
	// (u = (1+y)/(1-y)), the same map libsodium uses. The coordinate depends
	// only on y, so the ed25519 sign bit is irrelevant, matching libsodium's
	// crypto_sign_ed25519_pk_to_curve25519 output.
	x25519Pub := point.BytesMontgomery()

	out := make([]byte, 0, 1+len(x25519Pub))
	out = append(out, chatIDTypeTag)
	out = append(out, x25519Pub...)
	return hex.EncodeToString(out), nil
}
