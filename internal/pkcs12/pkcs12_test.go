package pkcs12

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func testCertificate(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "zenten"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(86400, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return key, cert
}

func TestEncodeRoundTrip(t *testing.T) {
	t.Parallel()
	key, cert := testCertificate(t)

	pfx, err := Encode(rand.Reader, key, cert, "zenten", "changeit")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	decodedKey, decodedCert, caCerts, err := pkcs12.DecodeChain(pfx, "changeit")
	if err != nil {
		t.Fatalf("DecodeChain: %v", err)
	}
	if len(caCerts) != 0 {
		t.Fatalf("CA certificate count = %d, want 0", len(caCerts))
	}
	if !bytes.Equal(decodedCert.Raw, cert.Raw) {
		t.Fatal("decoded certificate does not match")
	}
	decodedRSA, ok := decodedKey.(*rsa.PrivateKey)
	if !ok || decodedRSA.D.Cmp(key.D) != 0 {
		t.Fatalf("decoded key = %T, want the encoded RSA key", decodedKey)
	}

	blocks, err := pkcs12.ToPEM(pfx, "changeit")
	if err != nil {
		t.Fatalf("ToPEM: %v", err)
	}
	for _, block := range blocks {
		if got := block.Headers["friendlyName"]; got != "zenten" {
			t.Fatalf("friendlyName = %q, want %q", got, "zenten")
		}
	}
}

func TestEncodeRejectsBadInput(t *testing.T) {
	t.Parallel()
	_, cert := testCertificate(t)

	tests := []struct {
		name string
		args func() (any, *x509.Certificate, string, string)
		want string
	}{
		{
			name: "nil certificate",
			args: func() (any, *x509.Certificate, string, string) { return nil, nil, "zenten", "changeit" },
			want: "certificate is required",
		},
		{
			name: "empty alias",
			args: func() (any, *x509.Certificate, string, string) { return nil, cert, "", "changeit" },
			want: "alias cannot be empty",
		},
		{
			name: "empty password",
			args: func() (any, *x509.Certificate, string, string) { return nil, cert, "zenten", "" },
			want: "password cannot be empty",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			key, certificate, alias, password := tt.args()
			_, err := Encode(rand.Reader, key, certificate, alias, password)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}

	if _, err := Encode(nil, nil, cert, "zenten", "changeit"); err == nil {
		t.Fatal("Encode with nil random source succeeded, want error")
	}
}
