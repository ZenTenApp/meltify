package derive

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/tyler-smith/go-bip39"
)

// Wallet V4R2 (ton-blockchain/wallet-contract) constants.
// Code hash is the published root cell hash; depth is of that same BOC root.
const (
	tonV4R2WalletID    = 698983191 // 0x29a9a317, mainnet default
	tonV4R2CodeDepth   = 7
	tonUQTag           = 0x51 // non-bounceable, mainnet
	tonStateInitBits   = 5
	tonStateInitPadded = 0x34 // bits 00110 + completion 1
	tonDataBitLen      = 321  // 32 seqno + 32 wallet_id + 256 pubkey + 1 empty dict
	tonDataCellBytes   = 41
	tonWalletIDOffset  = 4
	tonPubKeyOffset    = 8
	tonPubKeyEnd       = 40
	tonDataPadOffset   = 40
	tonDataPadByte     = 0x40 // leftover 0 bit + completion 1
	tonAddrBytes       = 36
	tonAddrBodyBytes   = 34
	tonCRCOffset       = 34
	tonByteBits        = 8
)

// Published Wallet V4R2 code cell hash:
// feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0
var tonV4R2CodeHash = [32]byte{
	0xfe, 0xb5, 0xff, 0x68, 0x20, 0xe2, 0xff, 0x0d,
	0x94, 0x83, 0xe7, 0xe0, 0xd6, 0x2c, 0x81, 0x7d,
	0x84, 0x67, 0x89, 0xfb, 0x4a, 0xe5, 0x80, 0xc8,
	0x78, 0x86, 0x6d, 0x95, 0x9d, 0xab, 0xd5, 0xc0,
}

type tonRef struct {
	hash  [32]byte
	depth uint16
}

// Ton derives a TON Wallet V4R2 non-bounceable (UQ) mainnet address
// from a BIP39 mnemonic at SLIP-0010 path m/44'/607'/0'.
//
// This is the TEP-0003 "multichain mnemonic" scheme used by Trust Wallet,
// not the TON-native PBKDF2("TON default seed") KDF.
func Ton(mnemonic, bip39Passphrase string) (string, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}
	key := deriveEd25519Key(seed, []uint32{44, 607, 0}) //nolint:mnd
	privateKey := ed25519.NewKeyFromSeed(key)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return encodeTonV4R2UQ(publicKey), nil
}

func encodeTonV4R2UQ(publicKey ed25519.PublicKey) string {
	accountID := tonV4R2AccountID(publicKey)
	payload := make([]byte, tonAddrBytes)
	payload[0] = tonUQTag
	copy(payload[2:tonAddrBodyBytes], accountID[:])
	crc := crc16xmodem(payload[:tonAddrBodyBytes])
	payload[tonCRCOffset] = byte(crc >> tonByteBits)
	payload[tonCRCOffset+1] = byte(crc)
	return base64.RawURLEncoding.EncodeToString(payload)
}

func tonV4R2AccountID(publicKey ed25519.PublicKey) [32]byte {
	dataHash := tonV4R2DataHash(publicKey)
	return tonHashCell(tonStateInitBits, []byte{tonStateInitPadded}, []tonRef{
		{hash: tonV4R2CodeHash, depth: tonV4R2CodeDepth},
		{hash: dataHash},
	})
}

func tonV4R2DataHash(publicKey ed25519.PublicKey) [32]byte {
	raw := make([]byte, tonDataCellBytes)
	binary.BigEndian.PutUint32(raw[tonWalletIDOffset:tonPubKeyOffset], tonV4R2WalletID)
	copy(raw[tonPubKeyOffset:tonPubKeyEnd], publicKey)
	raw[tonDataPadOffset] = tonDataPadByte
	return tonHashCell(tonDataBitLen, raw, nil)
}

func tonHashCell(bitLen int, data []byte, refs []tonRef) [32]byte {
	d1 := byte(len(refs)) // ordinary cell, level 0
	d2 := byte(bitLen/tonByteBits + (bitLen+tonByteBits-1)/tonByteBits)
	h := sha256.New()
	h.Write([]byte{d1, d2})
	h.Write(data)
	for _, r := range refs {
		var depth [2]byte
		binary.BigEndian.PutUint16(depth[:], r.depth)
		h.Write(depth[:])
	}
	for _, r := range refs {
		h.Write(r.hash[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
