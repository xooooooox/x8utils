package x8utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net/url"
)

// 常见加密算法
// BASE64 HASH SHA HMAC-SHA AES DES RABBIT RC4 TRIPLE-DES URL-ENCODE URL-DECODE

// 对称加密(加解密都使用的是同一个密钥): AES
// 非对称加密(加解密使用不同的密钥): RSA
// 签名算法: MD5, SHA1, HMAC等 主要用于验证,防止信息被修改, 如: 文件校验 数字签名 鉴权协议

// Base64Encrypt base64 encrypt
func Base64Encrypt(unencrypted []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(unencrypted))
}

// Base64Decrypt base64 decrypt
func Base64Decrypt(encrypted []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(encrypted))
}

// Md5 md5 加密
func Md5(unencrypted []byte) string {
	hash := md5.New()
	hash.Write(unencrypted)
	return hex.EncodeToString(hash.Sum(nil))
}

// Sha1 sha1 加密
func Sha1(unencrypted []byte) string {
	hash := sha1.New()
	hash.Write(unencrypted)
	return hex.EncodeToString(hash.Sum(nil))
}

// Sha256 sha256 加密
func Sha256(unencrypted []byte) string {
	hash := sha256.New()
	hash.Write(unencrypted)
	return hex.EncodeToString(hash.Sum(nil))
}

// Sha512 sha512 加密
func Sha512(unencrypted []byte) string {
	hash := sha512.New()
	hash.Write(unencrypted)
	return hex.EncodeToString(hash.Sum(nil))
}

// HmacMd5
func HmacMd5(unencrypted []byte, secret []byte) string {
	hash := hmac.New(md5.New, secret)
	hash.Write(unencrypted)
	return hex.EncodeToString(hash.Sum(nil))
}

// HmacSha1 HMAC-SHA1 加密
func HmacSha1(unencrypted []byte, secret []byte) string {
	hash := hmac.New(sha1.New, secret)
	hash.Write(unencrypted)
	return hex.EncodeToString(hash.Sum(nil))
}

// HmacSha256 HMAC-SHA256 加密
func HmacSha256(unencrypted []byte, secret []byte) string {
	hash := hmac.New(sha256.New, secret)
	hash.Write(unencrypted)
	return hex.EncodeToString(hash.Sum(nil))
}

// HmacSha512 HMAC-SHA512 加密
func HmacSha512(unencrypted []byte, secret []byte) string {
	hash := hmac.New(sha512.New, secret)
	hash.Write(unencrypted)
	return hex.EncodeToString(hash.Sum(nil))
}

// UrlEncode UrlEncode 加密
func UrlEncode(unencrypted string) string {
	return url.QueryEscape(unencrypted)
}

// UrlDecode UrlDecode 解密
func UrlDecode(encrypted string) (string, error) {
	return url.QueryUnescape(encrypted)
}

// AES: 高级加密标准(Advanced Encryption Standard),又称Rijndael加密法,这个标准用来替代原先的DES.AES加密数据块分组长度必须为128bit(byte[16]),密钥长度可以是128bit(byte[16]),192bit(byte[24]),256bit(byte[32])中的任意一个.
//
// 块: 对明文进行加密的时候,先要将明文按照128bit进行划分.
//
// 填充方式: 因为明文的长度不一定总是128的整数倍,所以要进行补位,我们这里采用的是PKCS7填充方式
//
// AES实现的方式多样, 其中包括ECB,CBC,CFB,OFB等
//
// 1.电码本模式(Electronic Codebook Book (ECB))
// 将明文分组加密之后的结果直接称为密文分组.
//
// 2.密码分组链接模式(Cipher Block Chaining (CBC))
// 将明文分组与前一个密文分组进行XOR运算,然后再进行加密.每个分组的加解密都依赖于前一个分组.而第一个分组没有前一个分组,因此需要一个初始化向量
//
// 3.计算器模式(Counter (CTR))
//
// 4.密码反馈模式(Cipher FeedBack (CFB))
// 前一个密文分组会被送回到密码算法的输入端.
// 在CBC和EBC模式中,明文分组都是通过密码算法进行加密的.而在CFB模式中,明文分组并没有通过加密算法直接进行加密,明文分组和密文分组之间只有一个XOR.
//
// 5.输出反馈模式(Output FeedBack (OFB))
//
// 加密模式	对应加解密方法
// CBC	NewCBCDecrypter, NewCBCEncrypter
// CTR	NewCTR
// CFB	NewCFBDecrypter, NewCFBEncrypter
// OFB	NewOFB
// 相关示例见: https://golang.org/src/crypto/cipher/example_test.go

type CipherAes struct {
	secret []byte // 秘钥
	iv     []byte // 向量
}

// NewCipherAes
func NewCipherAes(secret []byte) *CipherAes {
	return &CipherAes{
		secret: secret,
	}
}

// SetSecret
func (ca *CipherAes) SetSecret(secret []byte) {
	ca.secret = secret
}

// SetIv
func (ca *CipherAes) SetIv(iv []byte) {
	ca.iv = iv
}

// GetSecret
func (ca *CipherAes) GetSecret() []byte {
	return ca.secret
}

// GetIv
func (ca *CipherAes) GetIv() []byte {
	return ca.iv
}

// 补码
// AES加密数据块分组长度必须为128bit(byte[16]); 密钥长度可以是128bit(byte[16]), 192bit(byte[24]), 256bit(byte[32])中的任意一个!
func (ca *CipherAes) Pkcs7Padding(content []byte, blockSize int) []byte {
	padding := blockSize - len(content)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(content, padText...)
}

// 去码
func (ca *CipherAes) Pkcs7UnPadding(content []byte) []byte {
	length := len(content)
	unPadding := int(content[length-1])
	return content[:(length - unPadding)]
}

// AesCbcEncrypt aes cbc encrypt , The most common method of aes encryption
func (ca *CipherAes) AesCbcEncrypt(unencrypted []byte) ([]byte, error) {
	block, err := aes.NewCipher(ca.secret)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	unencrypted = ca.Pkcs7Padding(unencrypted, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, ca.iv)
	crypt := make([]byte, len(unencrypted))
	// encode
	blockMode.CryptBlocks(crypt, unencrypted)
	return crypt, nil
}

// AesCbcDecrypt aes cbc decrypt
func (ca *CipherAes) AesCbcDecrypt(encrypted []byte) ([]byte, error) {
	block, err := aes.NewCipher(ca.secret)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, ca.iv)
	plainText := make([]byte, len(encrypted))
	// decode
	blockMode.CryptBlocks(plainText, encrypted)
	return ca.Pkcs7UnPadding(plainText), nil
}

// AesEcbEncrypt aes ecb encrypt
func (ca *CipherAes) AesEcbEncrypt(unencrypted []byte) (encrypted []byte, err error) {
	cipherText, err := aes.NewCipher(ca.GenerateKey(ca.secret))
	if err != nil {
		return nil, err
	}
	length := (len(unencrypted) + aes.BlockSize) / aes.BlockSize
	plain := make([]byte, length*aes.BlockSize)
	copy(plain, unencrypted)
	pad := byte(len(plain) - len(unencrypted))
	for i := len(unencrypted); i < len(plain); i++ {
		plain[i] = pad
	}
	encrypted = make([]byte, len(plain))
	// block encryption 分组分块加密
	for bs, be := 0, cipherText.BlockSize(); bs <= len(unencrypted); bs, be = bs+cipherText.BlockSize(), be+cipherText.BlockSize() {
		cipherText.Encrypt(encrypted[bs:be], plain[bs:be])
	}
	return encrypted, nil
}

// AesEcbDecrypt aes ecb decrypt
func (ca *CipherAes) AesEcbDecrypt(encrypted []byte) (decrypted []byte, err error) {
	cipherText, err := aes.NewCipher(ca.GenerateKey(ca.secret))
	if err != nil {
		return nil, err
	}
	decrypted = make([]byte, len(encrypted))
	for bs, be := 0, cipherText.BlockSize(); bs < len(encrypted); bs, be = bs+cipherText.BlockSize(), be+cipherText.BlockSize() {
		cipherText.Decrypt(decrypted[bs:be], encrypted[bs:be])
	}
	trim := 0
	if len(decrypted) > 0 {
		trim = len(decrypted) - int(decrypted[len(decrypted)-1])
	}
	return decrypted[:trim], nil
}

// GenerateKey generate key
func (ca *CipherAes) GenerateKey(key []byte) (genKey []byte) {
	genKey = make([]byte, 16)
	copy(genKey, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			genKey[j] ^= key[i]
		}
	}
	return genKey
}

// AesCfbEncrypt aes cfb encrypt
func (ca *CipherAes) AesCfbEncrypt(unencrypted []byte) ([]byte, error) {
	if len(ca.iv) < 16 {
		return nil, errors.New("iv length at least 16")
	}
	block, err := aes.NewCipher(ca.secret)
	if err != nil {
		return nil, err
	}
	cipherText := make([]byte, aes.BlockSize+len(unencrypted))
	_, err = io.ReadFull(rand.Reader, ca.iv)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, ca.iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], unencrypted)
	return cipherText, nil
}

// AesCfbEncrypt aes cfb decrypt
func (ca *CipherAes) AesCfbDecrypt(encrypted []byte) ([]byte, error) {
	if len(ca.iv) < 16 {
		return nil, errors.New("iv length at least 16")
	}
	block, err := aes.NewCipher(ca.secret)
	if err != nil {
		panic(err)
	}
	encrypted = encrypted[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, ca.iv)
	stream.XORKeyStream(encrypted, encrypted)
	return encrypted, nil
}

// AesCtr aes ctr encrypt and decrypt
func (ca *CipherAes) AesCtr(bts []byte) ([]byte, error) {
	if len(ca.iv) < 16 {
		return nil, errors.New("iv length at least 16")
	}
	// 指定加密,解密算法为AES,返回一个AES的Block接口对象
	block, err := aes.NewCipher(ca.secret)
	if err != nil {
		return nil, err
	}
	// 指定分组模式
	blockMode := cipher.NewCTR(block, ca.iv)
	// 执行加密,解密操作
	message := make([]byte, len(bts))
	blockMode.XORKeyStream(message, bts)
	// 返回明文或密文
	return message, nil
}

// AesOfb aes ofb encrypt and decrypt
func (ca *CipherAes) AesOfb(bts []byte) ([]byte, error) {
	if len(ca.iv) < 16 {
		return nil, errors.New("iv length at least 16")
	}
	// 指定加密,解密算法为AES,返回一个AES的Block接口对象
	block, err := aes.NewCipher(ca.secret)
	if err != nil {
		return nil, err
	}
	// 指定分组模式
	blockMode := cipher.NewOFB(block, ca.iv)
	// 执行加密,解密操作
	message := make([]byte, len(bts))
	blockMode.XORKeyStream(message, bts)
	// 返回明文或密文
	return message, nil
}

// for example rsa private secret
// 创建私钥: openssl genrsa -out rsa_private_key.pem 1024
/*
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDcGsUIIAINHfRTdMmgGwLrjzfMNSrtgIf4EGsNaYwmC1GjF/bM
h0Mcm10oLhNrKNYCTTQVGGIxuc5heKd1gOzb7bdTnCDPPZ7oV7p1B9Pud+6zPaco
qDz2M24vHFWYY2FbIIJh8fHhKcfXNXOLovdVBE7Zy682X1+R1lRK8D+vmQIDAQAB
AoGAeWAZvz1HZExca5k/hpbeqV+0+VtobMgwMs96+U53BpO/VRzl8Cu3CpNyb7HY
64L9YQ+J5QgpPhqkgIO0dMu/0RIXsmhvr2gcxmKObcqT3JQ6S4rjHTln49I2sYTz
7JEH4TcplKjSjHyq5MhHfA+CV2/AB2BO6G8limu7SheXuvECQQDwOpZrZDeTOOBk
z1vercawd+J9ll/FZYttnrWYTI1sSF1sNfZ7dUXPyYPQFZ0LQ1bhZGmWBZ6a6wd9
R+PKlmJvAkEA6o32c/WEXxW2zeh18sOO4wqUiBYq3L3hFObhcsUAY8jfykQefW8q
yPuuL02jLIajFWd0itjvIrzWnVmoUuXydwJAXGLrvllIVkIlah+lATprkypH3Gyc
YFnxCTNkOzIVoXMjGp6WMFylgIfLPZdSUiaPnxby1FNM7987fh7Lp/m12QJAK9iL
2JNtwkSR3p305oOuAz0oFORn8MnB+KFMRaMT9pNHWk0vke0lB1sc7ZTKyvkEJW0o
eQgic9DvIYzwDUcU8wJAIkKROzuzLi9AvLnLUrSdI6998lmeYO9x7pwZPukz3era
zncjRK3pbVkv0KrKfczuJiRlZ7dUzVO0b6QJr8TRAA==
-----END RSA PRIVATE KEY-----
*/

// for example rsa public secret
// 创建公钥: openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
/*
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDcGsUIIAINHfRTdMmgGwLrjzfM
NSrtgIf4EGsNaYwmC1GjF/bMh0Mcm10oLhNrKNYCTTQVGGIxuc5heKd1gOzb7bdT
nCDPPZ7oV7p1B9Pud+6zPacoqDz2M24vHFWYY2FbIIJh8fHhKcfXNXOLovdVBE7Z
y682X1+R1lRK8D+vmQIDAQAB
-----END PUBLIC KEY-----
*/

// RsaEncrypt rsa encrypt
func RsaEncrypt(unencrypted, secret []byte) (result []byte, err error) {
	// decrypt the public key in pem format
	if len(secret) == 0 {
		err = errors.New("public secret key is empty")
		return
	}
	block, _ := pem.Decode(secret)
	if block == nil {
		return nil, errors.New("public key error")
	}
	// parsing the public key
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// types of assertions
	pub := pubInterface.(*rsa.PublicKey)
	// encode
	return rsa.EncryptPKCS1v15(rand.Reader, pub, unencrypted)
}

// RsaDecrypt rsa decrypt
func RsaDecrypt(encrypted, secret []byte) (result []byte, err error) {
	// decode
	if len(secret) == 0 {
		err = errors.New("private secret key is empty")
		return
	}
	block, _ := pem.Decode(secret)
	if block == nil {
		return nil, errors.New("private key error")
	}
	// parse private keys in PKCS1 format
	private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// decode
	return rsa.DecryptPKCS1v15(rand.Reader, private, encrypted)
}
