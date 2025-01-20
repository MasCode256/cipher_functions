package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

type EncryptedMessage struct {
	IV      string `json:"iv"`      // Изменено на string
	Key     string `json:"key"`
	Message string `json:"message"`
}

func NewEncryptedMessage(jsonStr string) (EncryptedMessage, error) {
	var this EncryptedMessage

	err := json.Unmarshal([]byte(jsonStr), &this)
	if err != nil {
		log.Fatal(err)
		return this, err
	}

	return this, nil
}

func generateRandomString(length int) (string, error) {
	// Генерируем случайные байты
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Кодируем байты в строку Base64
	return base64.RawStdEncoding.EncodeToString(bytes)[:length], nil
}

// Генерация пары ключей RSA
func generateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privKey, &privKey.PublicKey, nil
}

// Кодирование приватного ключа в Base64
func encodePrivateKey(priv *rsa.PrivateKey) string {
	privASN1 := x509.MarshalPKCS1PrivateKey(priv)
	return base64.StdEncoding.EncodeToString(privASN1)
}

// Кодирование публичного ключа в Base64
func encodePublicKey(pub *rsa.PublicKey) string {
	pubASN1 := x509.MarshalPKCS1PublicKey(pub)
	return base64.StdEncoding.EncodeToString(pubASN1)
}

// Декодирование приватного ключа из Base64
func decodePrivateKey(encoded string) (*rsa.PrivateKey, error) {
	privASN1, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(privASN1)
}

// Декодирование публичного ключа из Base64
func decodePublicKey(encoded string) (*rsa.PublicKey, error) {
	pubASN1, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PublicKey(pubASN1)
}

// Функция для дополнения данных до размера блока
func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// Функция для удаления дополнения
func unpad(data []byte) ([]byte, error) {
	length := len(data)
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, errors.New("invalid padding")
	}
	return data[:(length - unpadding)], nil
}

// Шифрование сообщения с использованием AES
func encryptAES(key []byte, plaintext []byte) (string, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", nil, err
	}

	// Дополнение текста перед шифрованием
	paddedText := pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(paddedText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedText)

	return base64.StdEncoding.EncodeToString(ciphertext), iv, nil
}

// Расшифрование сообщения с использованием AES
func decryptAES(key []byte, ciphertext string, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertextBytes, _ := base64.StdEncoding.DecodeString(ciphertext)
	if len(ciphertextBytes)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(ciphertextBytes))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertextBytes)

	// Удаление дополнения после расшифрования
	return unpad(plaintext)
}

// Шифрование AES ключа с использованием RSA
func encryptRSA(pub *rsa.PublicKey, aesKey []byte) (string, error) {
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encryptedKey), nil
}

// Расшифрование AES ключа с использованием RSA
func decryptRSA(priv *rsa.PrivateKey, encryptedKey string) ([]byte, error) {
	encryptedKeyBytes, _ := base64.StdEncoding.DecodeString(encryptedKey)
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedKeyBytes, nil)
}

func encrypt(pk *rsa.PublicKey, str []byte) (string, error) {
	aesKey, err := generateRandomString(32)
	if err != nil {
		return "", err
	}

	encryptedKey, err := encryptRSA(pk, []byte(aesKey))
	if err != nil {
		return "", err
	}

	encryptedStr, iv, err := encryptAES([]byte(aesKey), str)
	if err != nil {
		return "", err
	}

	// Кодируем IV в Base64 и формируем JSON
	encryptedMessage := EncryptedMessage{
		Key:     encryptedKey,
		IV:      base64.StdEncoding.EncodeToString(iv), // Кодируем IV
		Message: encryptedStr,
	}

	jsonResult, err := json.Marshal(encryptedMessage)
	if err != nil {
		return "", err
	}

	return string(jsonResult), nil
}

func decrypt(sk *rsa.PrivateKey, str string) (string, error) {
	encryptedMessage, err := NewEncryptedMessage(str)
	if err != nil {
		return "", err
	}

	aesKey, err := decryptRSA(sk, encryptedMessage.Key)
	if err != nil {
		return "", err
	}

	// Декодируем IV из Base64
	ivBytes, err := base64.StdEncoding.DecodeString(encryptedMessage.IV)
	if err != nil {
		return "", err
	}

	decryptedMessage, err := decryptAES(aesKey, encryptedMessage.Message, ivBytes)
	if err != nil {
		return "", err
	}

	return string(decryptedMessage), nil
}

// Создание цифровой подписи
func createSignature(priv *rsa.PrivateKey, message []byte) (string, error) {
	hash := sha256.New()
	hash.Write(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash.Sum(nil))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// Проверка цифровой подписи
func verifySignature(pub *rsa.PublicKey, message []byte, signature string) error {
	hash := sha256.New()
	hash.Write(message)
	signatureBytes, _ := base64.StdEncoding.DecodeString(signature)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash.Sum(nil), signatureBytes)
}

func test() {
	// Генерация ключей
	privKey, pubKey, err := generateKeyPair(2048)
	if err != nil {
		fmt.Println("Ошибка генерации ключей:", err)
		return
	}

	encrypted, err := encrypt(pubKey, []byte("Привет, Россия!")); if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("Зашифрованное сообщение:", encrypted)

	decrypted, err := decrypt(privKey, encrypted); if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("Расшифрованное сообщение:", decrypted)
}

func in(filename string) string {
	file, err := os.Open(filename)
	if err != nil {
		return ""
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return ""
	}

	return string(data)
}