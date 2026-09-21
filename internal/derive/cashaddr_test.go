package derive

import (
	"encoding/hex"
	"testing"
)

func TestEncodeCashAddrSpecVectors(t *testing.T) {
	tests := []struct {
		hashHex string
		want    string
	}{
		{"76a04053bda0a88bda5177b86a15c3b29f559873", "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"},
	}
	for _, tt := range tests {
		hash, err := hex.DecodeString(tt.hashHex)
		if err != nil {
			t.Fatal(err)
		}
		got, err := encodeCashAddr("bitcoincash", 0, hash)
		if err != nil {
			t.Fatal(err)
		}
		if got != tt.want {
			t.Errorf("cashaddr(%s) = %s, want %s", tt.hashHex, got, tt.want)
		}
	}
}

func TestBitcoinCashGoldenMnemonic(t *testing.T) {
	got, err := BitcoinCash(GoldenMnemonic24, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != GoldenBitcoinCash {
		t.Errorf("BitcoinCash = %s, want %s", got, GoldenBitcoinCash)
	}
}
