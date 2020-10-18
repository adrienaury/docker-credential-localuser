package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	masterPasswordEnvVarName    = "DOCKER_CREDENTIAL_MASTER_PASSWORD" // #nosec
	keyDerivationIterationCount = 64000
	keyByteLength               = 32
	splitLength                 = 2
)

func encryptSecret(secret string) (string, error) {
	masterPassword, err := retrievePassword()
	if err != nil {
		return secret, err
	}

	salt := make([]byte, 32)
	_, err = rand.Read(salt)
	if err != nil {
		return secret, err
	}

	key := pbkdf2.Key([]byte(masterPassword), salt, keyDerivationIterationCount, keyByteLength, sha256.New)
	ciphersecret, err := encrypt([]byte(secret), key)
	if err != nil {
		return secret, err
	}

	return base64.StdEncoding.EncodeToString(ciphersecret) + "." + base64.StdEncoding.EncodeToString(salt), nil
}

func decryptSecret(secret string) (string, error) {
	masterPassword, err := retrievePassword()
	if err != nil {
		return secret, err
	}

	values := strings.Split(secret, ".")
	if len(values) != splitLength {
		return secret, ErrInvalidStorage.wrap(errors.New("unexpected format"))
	}

	ciphersecret, err := base64.StdEncoding.DecodeString(values[0])
	if err != nil {
		return secret, ErrInvalidStorage.wrap(err)
	}

	salt, err := base64.StdEncoding.DecodeString(values[1])
	if err != nil {
		return secret, ErrInvalidStorage.wrap(err)
	}

	key := pbkdf2.Key([]byte(masterPassword), salt, keyDerivationIterationCount, keyByteLength, sha256.New)

	plaintext, err := decrypt(ciphersecret, key)
	if err != nil {
		return secret, ErrPermissionDenied.wrap(err)
	}

	return string(plaintext), nil
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func retrievePassword() (string, error) {
	masterPassword := os.Getenv(masterPasswordEnvVarName)
	if masterPassword == "" {
		return "", ErrInvalidParameters.wrap(errors.New("master password is uninitialiazed"))
	}
	return masterPassword, nil
}
