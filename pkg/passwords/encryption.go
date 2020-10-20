package passwords

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh/terminal"
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

	key := pbkdf2.Key(masterPassword, salt, keyDerivationIterationCount, keyByteLength, sha256.New)
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
		return secret, fmt.Errorf("%w : unexpected format", ErrInvalidStorage)
	}

	ciphersecret, err := base64.StdEncoding.DecodeString(values[0])
	if err != nil {
		return secret, ErrInvalidStorage.wrap(err)
	}

	salt, err := base64.StdEncoding.DecodeString(values[1])
	if err != nil {
		return secret, ErrInvalidStorage.wrap(err)
	}

	key := pbkdf2.Key(masterPassword, salt, keyDerivationIterationCount, keyByteLength, sha256.New)

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
		return nil, fmt.Errorf("%w : ciphertext too short", ErrInvalidParameters)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func retrievePassword() ([]byte, error) {
	_, isMasterPasswordSet := os.LookupEnv(masterPasswordEnvVarName)
	var masterPassword []byte
	if !isMasterPasswordSet {
		masterPassword = askPassword()
	} else {
		masterPassword = []byte(os.Getenv(masterPasswordEnvVarName))
	}
	if masterPassword == nil {
		return nil, fmt.Errorf("%w : master password environment variable is uninitialiazed", ErrMasterPassword)
	}
	return masterPassword, nil
}

func askPassword() []byte {
	if terminal.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(os.Stdout, "enter master password: ")
		bytePassword, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stdout)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return bytePassword
	}
	return nil
}
