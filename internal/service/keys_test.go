package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keyPaths returns the private and public key paths inside a fresh temporary directory.
func keyPaths(t *testing.T) (privPath, pubPath string) {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem")
}

// pemBytes encodes der as a PEM block of the given type.
func pemBytes(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

// pkcs8PEM encodes key as a PKCS #8 "PRIVATE KEY" block.
func pkcs8PEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return pemBytes("PRIVATE KEY", der)
}

// pkixPEM encodes key as a PKIX "PUBLIC KEY" block.
func pkixPEM(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)
	return pemBytes("PUBLIC KEY", der)
}

// writeFile writes data to path with a private mode.
func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

// pemType returns the type of the first PEM block in the file at path.
func pemType(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	return block.Type
}

func TestGenerateRSAKeyPair_WritesLoadableFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	privPath := filepath.Join(dir, "nested", "keys", "private.pem")
	pubPath := filepath.Join(dir, "nested", "keys", "public.pem")

	priv, pub, err := GenerateRSAKeyPair(privPath, pubPath)

	require.NoError(t, err)
	assert.True(t, priv.PublicKey.Equal(pub))
	assert.Equal(t, rsaKeyBits, priv.N.BitLen())
	privInfo, err := os.Stat(privPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), privInfo.Mode().Perm())
	pubInfo, err := os.Stat(pubPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), pubInfo.Mode().Perm())
	assert.Equal(t, "PRIVATE KEY", pemType(t, privPath))
	assert.Equal(t, "PUBLIC KEY", pemType(t, pubPath))

	loadedPriv, loadedPub, err := LoadRSAKeyPair(privPath, pubPath)
	require.NoError(t, err)
	assert.True(t, priv.Equal(loadedPriv))
	assert.True(t, pub.Equal(loadedPub))
}

func TestGenerateRSAKeyPair_NeverOverwrites(t *testing.T) {
	t.Parallel()
	t.Run("existing private key", func(t *testing.T) {
		t.Parallel()
		privPath, pubPath := keyPaths(t)
		writeFile(t, privPath, []byte("keep me"))

		_, _, err := GenerateRSAKeyPair(privPath, pubPath)

		require.ErrorContains(t, err, "create key file")
		require.ErrorIs(t, err, fs.ErrExist)
		content, readErr := os.ReadFile(privPath)
		require.NoError(t, readErr)
		assert.Equal(t, "keep me", string(content))
		assert.NoFileExists(t, pubPath)
	})
	t.Run("existing public key", func(t *testing.T) {
		t.Parallel()
		privPath, pubPath := keyPaths(t)
		writeFile(t, pubPath, []byte("keep me"))

		_, _, err := GenerateRSAKeyPair(privPath, pubPath)

		require.ErrorIs(t, err, fs.ErrExist)
		content, readErr := os.ReadFile(pubPath)
		require.NoError(t, readErr)
		assert.Equal(t, "keep me", string(content))
	})
}

func TestLoadRSAKeyPair_ReportsMissingFiles(t *testing.T) {
	t.Parallel()
	priv, _ := testKeys(t)
	t.Run("private key", func(t *testing.T) {
		t.Parallel()
		privPath, pubPath := keyPaths(t)
		writeFile(t, pubPath, pkixPEM(t, &priv.PublicKey))

		_, _, err := LoadRSAKeyPair(privPath, pubPath)

		require.ErrorIs(t, err, fs.ErrNotExist)
	})
	t.Run("public key", func(t *testing.T) {
		t.Parallel()
		privPath, pubPath := keyPaths(t)
		writeFile(t, privPath, pkcs8PEM(t, priv))

		_, _, err := LoadRSAKeyPair(privPath, pubPath)

		require.ErrorIs(t, err, fs.ErrNotExist)
	})
}

func TestLoadRSAKeyPair_RejectsMismatchedKeys(t *testing.T) {
	t.Parallel()
	priv, _ := testKeys(t)
	_, foreignPub := foreignKeys(t)
	privPath, pubPath := keyPaths(t)
	writeFile(t, privPath, pkcs8PEM(t, priv))
	writeFile(t, pubPath, pkixPEM(t, foreignPub))

	loadedPriv, loadedPub, err := LoadRSAKeyPair(privPath, pubPath)

	require.ErrorContains(t, err, "does not match")
	assert.Nil(t, loadedPriv)
	assert.Nil(t, loadedPub)
}

func TestLoadRSAKeyPair_RejectsShortKeys(t *testing.T) {
	t.Parallel()
	priv, pub := shortKeys(t)
	privPath, pubPath := keyPaths(t)
	writeFile(t, privPath, pkcs8PEM(t, priv))
	writeFile(t, pubPath, pkixPEM(t, pub))

	loadedPriv, loadedPub, err := LoadRSAKeyPair(privPath, pubPath)

	require.ErrorContains(t, err, "1024 bits, at least 2048 are required")
	assert.Contains(t, err.Error(), privPath)
	assert.Nil(t, loadedPriv)
	assert.Nil(t, loadedPub)
}

func TestLoadRSAKeyPair_AcceptsEveryEncoding(t *testing.T) {
	t.Parallel()
	priv, pub := testKeys(t)
	pkcs1Priv := pemBytes("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv))
	pkcs1Pub := pemBytes("RSA PUBLIC KEY", x509.MarshalPKCS1PublicKey(pub))
	tests := []struct {
		name string
		priv []byte
		pub  []byte
	}{
		{"PKCS #8 with PKIX", pkcs8PEM(t, priv), pkixPEM(t, pub)},
		{"PKCS #1 with PKCS #1", pkcs1Priv, pkcs1Pub},
		{"PKCS #8 with PKCS #1", pkcs8PEM(t, priv), pkcs1Pub},
		{"PKCS #1 with PKIX", pkcs1Priv, pkixPEM(t, pub)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			privPath, pubPath := keyPaths(t)
			writeFile(t, privPath, tc.priv)
			writeFile(t, pubPath, tc.pub)

			loadedPriv, loadedPub, err := LoadRSAKeyPair(privPath, pubPath)

			require.NoError(t, err)
			assert.True(t, priv.Equal(loadedPriv))
			assert.True(t, pub.Equal(loadedPub))
		})
	}
}

func TestLoadRSAKeyPair_RejectsInvalidFiles(t *testing.T) {
	t.Parallel()
	priv, pub := testKeys(t)
	validPriv := pkcs8PEM(t, priv)
	validPub := pkixPEM(t, pub)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecPrivDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)
	ecPubDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	require.NoError(t, err)
	garbage := []byte{0x30, 0x03, 0x02, 0x01}

	tests := []struct {
		name string
		priv []byte
		pub  []byte
		want string
	}{
		{"private file without a PEM block", []byte("not pem"), validPub, "no PEM block found"},
		{"private PEM with invalid DER", pemBytes("PRIVATE KEY", garbage), validPub, "parse private key"},
		{"private key that is not RSA", pemBytes("PRIVATE KEY", ecPrivDER), validPub, "not an RSA private key"},
		{"public file without a PEM block", validPriv, []byte("not pem"), "no PEM block found"},
		{"public PEM with invalid DER", validPriv, pemBytes("PUBLIC KEY", garbage), "parse public key"},
		{"public key that is not RSA", validPriv, pemBytes("PUBLIC KEY", ecPubDER), "not an RSA public key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			privPath, pubPath := keyPaths(t)
			writeFile(t, privPath, tc.priv)
			writeFile(t, pubPath, tc.pub)

			loadedPriv, loadedPub, loadErr := LoadRSAKeyPair(privPath, pubPath)

			require.ErrorContains(t, loadErr, tc.want)
			assert.Nil(t, loadedPriv)
			assert.Nil(t, loadedPub)
		})
	}
}
