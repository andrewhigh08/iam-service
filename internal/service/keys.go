package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// Sizes of RSA signing keys: generated keys have rsaKeyBits, and keys supplied by the operator
// must have at least minRSAKeyBits.
const (
	rsaKeyBits    = 2048
	minRSAKeyBits = 2048
)

// LoadRSAKeyPair reads a PEM-encoded RSA private key (PKCS #8 or PKCS #1) and public key
// (PKIX or PKCS #1), verifies that they belong together and rejects keys shorter than 2048
// bits. A missing file is reported with an error satisfying errors.Is(err, fs.ErrNotExist).
func LoadRSAKeyPair(privPath, pubPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := loadPrivateKey(privPath)
	if err != nil {
		return nil, nil, err
	}
	if bits := priv.N.BitLen(); bits < minRSAKeyBits {
		return nil, nil, fmt.Errorf("%s: RSA key has %d bits, at least %d are required", privPath, bits, minRSAKeyBits)
	}
	pub, err := loadPublicKey(pubPath)
	if err != nil {
		return nil, nil, err
	}
	if !priv.PublicKey.Equal(pub) {
		return nil, nil, fmt.Errorf("public key %s does not match private key %s", pubPath, privPath)
	}
	return priv, pub, nil
}

// GenerateRSAKeyPair creates a 2048-bit RSA key pair and writes it as a PKCS #8 PEM file with
// mode 0600 and a PKIX PEM file with mode 0644. Existing files are never overwritten.
func GenerateRSAKeyPair(privPath, pubPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, nil, fmt.Errorf("generate RSA key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("encode private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encode public key: %w", err)
	}
	if err := writePEM(privPath, "PRIVATE KEY", privDER, 0o600); err != nil {
		return nil, nil, err
	}
	if err := writePEM(pubPath, "PUBLIC KEY", pubDER, 0o644); err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

// loadPrivateKey parses a PKCS #8 private key, falling back to PKCS #1.
func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	der, err := readPEM(path)
	if err != nil {
		return nil, err
	}
	if key, pkcs8Err := x509.ParsePKCS8PrivateKey(der); pkcs8Err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s: not an RSA private key", path)
		}
		return rsaKey, nil
	}
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse private key %s: %w", path, err)
	}
	return key, nil
}

// loadPublicKey parses a PKIX public key, falling back to PKCS #1.
func loadPublicKey(path string) (*rsa.PublicKey, error) {
	der, err := readPEM(path)
	if err != nil {
		return nil, err
	}
	if key, pkixErr := x509.ParsePKIXPublicKey(der); pkixErr == nil {
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%s: not an RSA public key", path)
		}
		return rsaKey, nil
	}
	key, err := x509.ParsePKCS1PublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key %s: %w", path, err)
	}
	return key, nil
}

// readPEM returns the DER bytes of the first PEM block in the file at path.
func readPEM(path string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: key paths come from the configuration
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block found", path)
	}
	return block.Bytes, nil
}

// writePEM creates path with mode, creating parent directories, and writes der as a PEM block.
func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec // G304: key paths come from the configuration
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}
