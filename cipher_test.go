package x8utils

import (
	"fmt"
	"log"
	"testing"
)

const (
	TestContent   = "123456"
	SecretContent = "0933e54e76b24731a2d84b6b463ec04c"
)

func TestBase64Encrypt(t *testing.T) {
	should := "MTIzNDU2"
	result := Base64Encrypt([]byte(TestContent))
	fmt.Println(string(result) == should)
	fmt.Println(string(result))
}

func TestBase64Decrypt(t *testing.T) {
	should := "123456"
	result, err := Base64Decrypt([]byte("MTIzNDU2"))
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(result) == should)
	fmt.Println(string(result))
}

func TestMd5(t *testing.T) {
	should := "e10adc3949ba59abbe56e057f20f883e"
	result := Md5([]byte(TestContent))
	fmt.Println(result == should)
	fmt.Println(result)
}

func TestHmacMd5(t *testing.T) {
	should := "2f1ebe52608d9deac735dcac9bfafb04"
	result := HmacMd5([]byte(TestContent), []byte(SecretContent))
	fmt.Println(result == should)
	fmt.Println(result)
}

func TestHmacSha1(t *testing.T) {
	should := "20c523ac6ae618260f35292197fc26c9aafbe55a"
	result := HmacSha1([]byte(TestContent), []byte(SecretContent))
	fmt.Println(result == should)
	fmt.Println(result)
}

func TestHmacSha256(t *testing.T) {
	should := "9977992d6bd7bed322e9a13c4bc69615aa985c926ce4df5d8d43f596f06c96b1"
	result := HmacSha256([]byte(TestContent), []byte(SecretContent))
	fmt.Println(result == should)
	fmt.Println(result)
}

func TestHmacSha512(t *testing.T) {
	should := "2f66349c030c874fc5fc2e3b8091dd66ba63b7c17362ae7b5ca88656bb36c02028c2e92e240a814ff226bab8cc5a5cce78f4fda499fbb4af5f069b1e357170aa"
	result := HmacSha512([]byte(TestContent), []byte(SecretContent))
	fmt.Println(result == should)
	fmt.Println(result)
}

func TestUrlEncode(t *testing.T) {
	should := "https%3A%2F%2Fwww.baidu.com%2F"
	result := UrlEncode("https://www.baidu.com/")
	fmt.Println(result == should)
	fmt.Println(result)
}

func TestUrlDecode(t *testing.T) {
	should := "https://www.baidu.com/"
	result, err := UrlDecode("https%3A%2F%2Fwww.baidu.com%2F")
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(result == should)
	fmt.Println(result)
}

func TestSha1(t *testing.T) {
	should := "7c4a8d09ca3762af61e59520943dc26494f8941b"
	result := Sha1([]byte(TestContent))
	fmt.Println(result == should)
	fmt.Println(result)
}

func TestSha256(t *testing.T) {
	should := "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
	result := Sha256([]byte(TestContent))
	fmt.Println(result == should)
	fmt.Println(result)
}

func TestSha512(t *testing.T) {
	should := "ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413"
	result := Sha512([]byte(TestContent))
	fmt.Println(result == should)
	fmt.Println(result)
}

func TestCipherAes_AesCbcEncrypt(t *testing.T) {
	secret := []byte("0933e54e76b24731a2d84b6b463ec04c")
	iv := []byte("2f1ebe52608d9dea")
	aes := NewCipherAes(secret)
	aes.SetIv(iv)
	result, err := aes.AesCbcEncrypt([]byte(TestContent))
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(result)
	fmt.Println(string(result))
	old, err := aes.AesCbcDecrypt(result)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(old) == TestContent)
	fmt.Println(string(old))
}

func TestCipherAes_AesEcbEncrypt(t *testing.T) {
	secret := []byte("0933e54e76b24731a2d84b6b463ec04c")
	iv := []byte("2f1ebe52608d9dea")
	aes := NewCipherAes(secret)
	aes.SetIv(iv)
	result, err := aes.AesEcbEncrypt([]byte(TestContent))
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(result)
	fmt.Println(string(result))
	old, err := aes.AesEcbDecrypt(result)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(old) == TestContent)
	fmt.Println(string(old))
}

func TestCipherAes_AesCfbEncrypt(t *testing.T) {
	secret := []byte("0933e54e76b24731a2d84b6b463ec04c")
	iv := []byte("2f1ebe52608d9dea")
	aes := NewCipherAes(secret)
	aes.SetIv(iv)
	result, err := aes.AesCfbEncrypt([]byte(TestContent))
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(result)
	fmt.Println(string(result))
	old, err := aes.AesCfbDecrypt(result)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(old) == TestContent)
	fmt.Println(string(old))
}

func TestCipherAes_AesCtr(t *testing.T) {
	secret := []byte("0933e54e76b24731a2d84b6b463ec04c")
	iv := []byte("2f1ebe52608d9dea")
	aes := NewCipherAes(secret)
	aes.SetIv(iv)
	result, err := aes.AesCtr([]byte(TestContent))
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(result)
	fmt.Println(string(result))
	old, err := aes.AesCtr(result)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(old) == TestContent)
	fmt.Println(string(old))
}

func TestCipherAes_AesOfb(t *testing.T) {
	secret := []byte("0933e54e76b24731a2d84b6b463ec04c")
	iv := []byte("2f1ebe52608d9dea")
	aes := NewCipherAes(secret)
	aes.SetIv(iv)
	result, err := aes.AesOfb([]byte(TestContent))
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(result)
	fmt.Println(string(result))
	old, err := aes.AesOfb(result)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(old) == TestContent)
	fmt.Println(string(old))
}

func TestRsaEncrypt(t *testing.T) {
	result, err := RsaEncrypt([]byte(TestContent), []byte(`
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDcGsUIIAINHfRTdMmgGwLrjzfM
NSrtgIf4EGsNaYwmC1GjF/bMh0Mcm10oLhNrKNYCTTQVGGIxuc5heKd1gOzb7bdT
nCDPPZ7oV7p1B9Pud+6zPacoqDz2M24vHFWYY2FbIIJh8fHhKcfXNXOLovdVBE7Z
y682X1+R1lRK8D+vmQIDAQAB
-----END PUBLIC KEY-----`))
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(result)
	fmt.Println(string(result))
	old, err := RsaDecrypt(result, []byte(`
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
-----END RSA PRIVATE KEY-----`))
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(old) == TestContent)
	fmt.Println(string(old))
}
