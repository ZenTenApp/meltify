package sshkey

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const openSSHBcryptKDFRounds = 1

// Material contains a parsed Ed25519 OpenSSH private key and its original PEM bytes.
type Material struct {
	Key           *ed25519.PrivateKey
	PrivateKeyPEM []byte
	SourcePass    []byte
}

// ReadKey reads an OpenSSH private key from path, or stdin when path is empty or -.
func ReadKey(path string, stdin io.Reader) ([]byte, error) {
	if path == "" || path == "-" {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("could not read key from stdin: %w", err)
		}
		return b, nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // User-provided key path.
	if err != nil {
		return nil, fmt.Errorf("could not read key %s: %w", path, err)
	}
	return b, nil
}

// LoadEd25519Key reads and parses an optionally encrypted Ed25519 OpenSSH private key.
func LoadEd25519Key(path string, stdin io.Reader) (*Material, error) {
	keyBytes, err := ReadKey(path, stdin)
	if err != nil {
		return nil, err
	}

	key, sourcePass, err := ParsePossiblyEncryptedEd25519Key(keyBytes, path)
	if err != nil {
		return nil, err
	}

	return &Material{
		Key:           key,
		PrivateKeyPEM: keyBytes,
		SourcePass:    sourcePass,
	}, nil
}

// ParsePossiblyEncryptedEd25519Key parses an optionally encrypted Ed25519 OpenSSH private key.
func ParsePossiblyEncryptedEd25519Key(keyBytes []byte, keyPath string) (*ed25519.PrivateKey, []byte, error) {
	key, err := parsePrivateKey(keyBytes, nil)
	var pass []byte
	if err != nil && isPasswordError(err) {
		pass, err = askKeyPassphrase(keyPath)
		if err != nil {
			return nil, nil, err
		}
		key, err = parsePrivateKey(keyBytes, pass)
		if err != nil {
			return nil, nil, fmt.Errorf("could not parse key with passphrase: %w", err)
		}
	} else if err != nil {
		return nil, nil, fmt.Errorf("could not parse key: %w", err)
	}

	edKey, ok := key.(*ed25519.PrivateKey)
	if !ok {
		return nil, nil, unsupportedKeyTypeError(key)
	}
	return edKey, pass, nil
}

func parsePrivateKey(bts, pass []byte) (interface{}, error) {
	if len(pass) == 0 {
		return ssh.ParseRawPrivateKey(bts) //nolint:wrapcheck // Callers add parse context.
	}
	return ssh.ParseRawPrivateKeyWithPassphrase(bts, pass) //nolint:wrapcheck // Callers add parse context.
}

func isPasswordError(err error) bool {
	var kerr *ssh.PassphraseMissingError
	return errors.As(err, &kerr)
}

func askKeyPassphrase(keyPath string) ([]byte, error) {
	label := keyPath
	if label == "" || label == "-" {
		label = "stdin"
	}
	fmt.Fprintf(os.Stderr, "Enter passphrase for %s: ", label)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("could not read passphrase: %w", err)
	}
	return pass, nil
}

func unsupportedKeyTypeError(key interface{}) error {
	msg := fmt.Sprintf("only Ed25519 SSH keys are supported (got %T)", key)
	if _, ok := key.(*rsa.PrivateKey); ok {
		msg += "; RSA keys are not supported by meltify"
	}
	return errors.New(msg)
}

// ActivateSubaccount derives a deterministic Ed25519 subaccount key and encodes it with the source key passphrase.
func (m *Material) ActivateSubaccount(subaccount string) error {
	if subaccount == "" {
		return nil
	}
	if len(m.SourcePass) == 0 {
		return errors.New("--subaccount requires the source key to be password-protected so meltify can keep the same passphrase")
	}

	derivedKey := DeriveSubaccountKey(m.Key, subaccount)
	pemBlock, err := MarshalOpenSSHEd25519PrivateKeyWithPassphraseKDFRounds(derivedKey, "", m.SourcePass, openSSHBcryptKDFRounds)
	if err != nil {
		return fmt.Errorf("could not encode subaccount SSH key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(pemBlock)
	if privateKeyPEM == nil {
		return errors.New("could not encode subaccount SSH key PEM")
	}
	m.Key = &derivedKey
	m.PrivateKeyPEM = privateKeyPEM
	return nil
}

// DeriveSubaccountKey derives a deterministic Ed25519 subaccount key from a source key and subaccount name.
func DeriveSubaccountKey(sourceKey *ed25519.PrivateKey, subaccount string) ed25519.PrivateKey {
	subaccountHash := sha256.Sum256([]byte(subaccount))
	seedMaterial := append(subaccountHash[:], sourceKey.Seed()...)
	derivedSeed := sha256.Sum256(seedMaterial)
	return ed25519.NewKeyFromSeed(derivedSeed[:])
}
