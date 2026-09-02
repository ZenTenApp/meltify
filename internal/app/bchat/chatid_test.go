package bchat

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Reference vectors generated with libsodium 1.0.20, the exact library call
// bchat-android makes via LazySodiumAndroid.convertKeyPairEd25519ToCurve25519:
//
//	crypto_sign_seed_keypair(seed, ed_pub, ed_priv)
//	crypto_sign_ed25519_pk_to_curve25519(x25519_pub, ed_pub)
//	chat_id = "bd" + hex(x25519_pub)
//
// See /tmp/bchat_ref/bchat_ref.c for the generator.
func TestDeriveChatID(t *testing.T) {
	tests := []struct {
		name string
		seed string
		want string
	}{
		{
			name: "counter seed",
			seed: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			want: "bd4701d08488451f545a409fb58ae3e58581ca40ac3f7f114698cd71deac73ca01",
		},
		{
			name: "all ff",
			seed: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			want: "bdd1fa3f01826bd8b78e057c086c7b22c7ad4358ca918099cd7b7e5d3acd7e285b",
		},
		{
			name: "ascii plus pattern",
			seed: "4a6f686e206973206120746573742121babecafe00112233445566778899aabb",
			want: "bdae0d9e41689509267c9c50c814cfe0995c8c8249586db7e487687aebc3bc9310",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seed, err := hex.DecodeString(tt.seed)
			if err != nil {
				t.Fatalf("bad test seed: %v", err)
			}
			got, err := DeriveChatID(seed)
			if err != nil {
				t.Fatalf("DeriveChatID returned error: %v", err)
			}
			if got != tt.want {
				t.Errorf("DeriveChatID = %s, want %s", got, tt.want)
			}
			if !strings.HasPrefix(got, "bd") || len(got) != 66 {
				t.Errorf("DeriveChatID = %s: want 66-hex id starting with bd", got)
			}
		})
	}
}

func TestDeriveChatIDRejectsBadSeed(t *testing.T) {
	for _, n := range []int{0, 1, 31, 33, 64} {
		if _, err := DeriveChatID(make([]byte, n)); err == nil {
			t.Errorf("DeriveChatID(%d bytes) expected error, got nil", n)
		}
	}
}
