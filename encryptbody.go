// Package plugin_encrypt_body a plugin to encrypt and rewrite response body.
package plugin_encrypt_body

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm4"
	"github.com/tjfoc/gmsm/x509"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// Rewrite holds one rewrite body configuration.
type Rewrite struct {
	Regex       string `json:"regex,omitempty"`
	Replacement string `json:"replacement,omitempty"`
}

// Config holds the plugin configuration.
type Config struct {
	LastModified bool      `json:"lastModified,omitempty"`
	Rewrites     []Rewrite `json:"rewrites,omitempty"`
}

// CreateConfig creates and initializes the plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

type rewrite struct {
	regex       *regexp.Regexp
	replacement []byte
}

type rewriteBody struct {
	name         string
	next         http.Handler
	rewrites     []rewrite
	lastModified bool
}

var key = []byte("1234567890123456")

const (
	sm2PrivateKeyFile = "sm2_private_key.pem"
	sm2PublicKeyFile  = "sm2_public_key.pem"
)

// New creates and returns a new rewrite body plugin instance.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	rewrites := make([]rewrite, len(config.Rewrites))

	for i, rewriteConfig := range config.Rewrites {
		regex, err := regexp.Compile(rewriteConfig.Regex)
		if err != nil {
			return nil, fmt.Errorf("error compiling regex %q: %w", rewriteConfig.Regex, err)
		}

		rewrites[i] = rewrite{
			regex:       regex,
			replacement: []byte(rewriteConfig.Replacement),
		}
	}

	return &rewriteBody{
		name:         name,
		next:         next,
		rewrites:     rewrites,
		lastModified: config.LastModified,
	}, nil
}

func (r *rewriteBody) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	wrappedWriter := &responseWriter{
		lastModified:   r.lastModified,
		ResponseWriter: rw,
	}
	bodyWritten := false
	r.next.ServeHTTP(wrappedWriter, req)
	bodyBytes := wrappedWriter.buffer.Bytes()

	defer func() {
		if !bodyWritten {
			writeResponse(rw, bodyBytes, &bodyWritten)
		}
	}()

	if verifyNeedRewrite(wrappedWriter) {
		writeResponse(rw, bodyBytes, &bodyWritten)
		bodyWritten = true
		return
	}

	var resultMap map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &resultMap); err != nil {
		log.Printf("json:%v, 解析失败: %s", bodyBytes, err.Error())
		writeResponse(rw, bodyBytes, &bodyWritten)
		return
	}
	matchFlag := false
	var newBytes []byte
	for _, rwt := range r.rewrites {
		// 获取 data 属性的值
		regexStr := rwt.regex.String()
		dataValue, ok := resultMap[regexStr]
		if !ok {
			log.Println(regexStr, "属性不存在, \n json:", resultMap)
			continue
		}

		log.Println("match result: ", dataValue)
		jsonStr, err := json.Marshal(dataValue)
		if err != nil {
			log.Printf("traefik-encrypt-body：json解析失败%v\n", err.Error())
			continue
		}
		log.Printf("jsonStr is: %q \n", jsonStr)

		// 对 属性的值进行 AES 加密
		//ciphertext := AesEncryptByCBC(base64Str, key)
		// 对 属性的值进行 SM2 加密
		ciphertext, err := EncryptByBySM2(jsonStr)
		if err != nil {
			log.Printf("encrptbody#EncryptByBySM2 加密失败:%v\n", err)
			continue
		}
		// 将加密后的值放回到属性中
		resultMap[regexStr] = base64.StdEncoding.EncodeToString(ciphertext)
		matchFlag = true
	}
	if !matchFlag {
		log.Printf("未匹配到属性：%v, json：%q", r.rewrites, resultMap)
		writeResponse(rw, bodyBytes, &bodyWritten)
		return
	}
	log.Println("new json is:", resultMap)
	writeResponse(rw, newBytes, &bodyWritten)
}

// SM4Encrypt encrypts the input byte array using SM4
func SM4Encrypt(plainText []byte) ([]byte, error) {
	ecbMsg, err := sm4.Sm4Ecb(key, plainText, true) //sm4Ecb模式pksc7填充加密
	if err != nil {
		log.Fatalf("sm4 enc error:%s", err)
		return nil, err
	}
	fmt.Printf("cbdMsg = %x\n", ecbMsg)

	return ecbMsg, nil
}

// SM4Decrypt decrypts the input byte array using SM4
func SM4Decrypt(cipherText []byte) ([]byte, error) {
	ecbDec, err := sm4.Sm4Ecb(key, cipherText, false) //sm4Ecb模式pksc7填充解密
	if err != nil {
		log.Fatalf("sm4 cbc error:%s", err)
		return nil, err
	}
	fmt.Printf("cbcDec = %x\n", ecbDec)
	return ecbDec, nil
}

func writeResponse(rw http.ResponseWriter, bodyBytes []byte, bodyWritten *bool) {
	if _, err := rw.Write(bodyBytes); err != nil {
		log.Printf("unable to write body: %v", err)
	}
	*bodyWritten = true
}

func verifyNeedRewrite(wrappedWriter *responseWriter) bool {
	contentEncoding := wrappedWriter.Header().Get("Content-Encoding")
	log.Printf("the header is %v", wrappedWriter.Header())
	if contentEncoding != "" && contentEncoding != "identity" {
		return true
	}

	contentType := wrappedWriter.Header().Get("Content-Type")
	log.Printf("the Content-Type is %v", wrappedWriter.Header())
	if !strings.Contains(contentType, "application/json") {
		return true
	}
	return false
}

func decryptWithAES(ciphertext []byte) ([]byte, error) {
	// 创建一个新的 AES 加密块
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// 创建一个用于解密的 GCM 模式的实例
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	// 获取 nonce 大小
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		panic("ciphertext too short")
	}

	// 分离 nonce 和密文
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// 解密数据
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Plaintext: %s\n", string(plaintext))

	return plaintext, nil
}

func EncryptByBySM2(plaintext []byte) ([]byte, error) {
	//1.打开公钥文件读取公钥
	file, err := os.Open(sm2PublicKeyFile)
	if err != nil {
		log.Fatalf("获取公钥文件失败 %v\n", err)
		return nil, err
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		log.Fatalf("读取公钥文件信息失败 %v\n", err)
		return nil, err
	}
	buf := make([]byte, fileInfo.Size())
	_, err = file.Read(buf)
	if err != nil {
		log.Fatalf("读取公钥文件信息失败 %v\n", err)
		return nil, err
	}
	//2.将pem格式公钥解码并反序列化
	publicKeyPem, err := x509.ReadPublicKeyFromPem(buf)
	if err != nil {
		log.Fatalf("x509反序列化公钥文件失败 %v\n", err)
		return nil, err
	}

	// 使用公钥加密数据
	//cipherText, err := publicKeyPem.EncryptAsn1(plaintext, rand.Reader)
	encrypt, err := sm2.Encrypt(publicKeyPem, plaintext, nil, sm2.C1C3C2)
	if err != nil {
		println(err)
	}
	return encrypt, nil
}

func decryptBySM2(cipher []byte) ([]byte, error) {
	//1.打开私钥文件读取私钥
	file, err := os.Open(sm2PrivateKeyFile)
	if err != nil {
		log.Fatalf("读取私钥文件失败 %v\n", err)
		return nil, err
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		if err != nil {
			log.Fatalf("读取私钥文件信息失败 %v\n", err)
			return nil, err
		}
	}
	buf := make([]byte, fileInfo.Size())
	_, err = file.Read(buf)
	if err != nil {
		if err != nil {
			log.Fatalf("读取私钥文件信息失败 %v\n", err)
			return nil, err
		}
	}
	//2.将pem格式私钥文件解码并反序列话
	privateKeyFromPem, err := x509.ReadPrivateKeyFromPem(buf, nil)
	if err != nil {
		log.Fatalf("x509反序列化公钥文件失败 %v\n", err)
		return nil, err
	}

	//3.解密
	//planiText, err := privateKeyFromPem.DecryptAsn1(cipher)
	planiText, err := sm2.Decrypt(privateKeyFromPem, cipher, sm2.C1C3C2)
	if err != nil {
		log.Fatalf("解密失败 密文：%v,密钥文件路径:%s err:%v\n", cipher, sm2PrivateKeyFile, err)
		return nil, err
	}

	fmt.Printf("planiText text: %s\n", planiText)
	return planiText, nil
}

// AES加密
func AesEncryptByCBC(dataValue string, key []byte) string {
	decodeString, _ := base64.StdEncoding.DecodeString(dataValue)
	log.Printf("decodeString is%q\n", decodeString)
	// 创建一个cipher.Block接口。参数key为密钥，长度只能是16、24、32字节
	block, _ := aes.NewCipher(key)
	// 获取秘钥长度
	blockSize := block.BlockSize()
	// 补码填充
	originDataByte := PKCS7Padding(decodeString, blockSize)
	// 选用加密模式
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	// 创建数组，存储加密结果
	encrypted := make([]byte, len(originDataByte))
	// 加密
	blockMode.CryptBlocks(encrypted, originDataByte)
	log.Println("加密后的字符串:", encrypted)

	// 将加密后的字节数组编码为Base64字符串
	encodeToString := base64.StdEncoding.EncodeToString(encrypted)
	log.Println("加密字符串转base64字符串:", encodeToString)
	return encodeToString
}

// 解密
func AesDecryptByCBC(encrypted string, key []byte) string {
	// encrypted密文反解base64
	decodeString, _ := base64.StdEncoding.DecodeString(encrypted)
	log.Printf("Decrypt decodeString is%v\n", decodeString)
	// key 转[]byte
	keyByte := key
	// 创建一个cipher.Block接口。参数key为密钥，长度只能是16、24、32字节
	block, _ := aes.NewCipher(keyByte)
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 选择加密模式
	blockMode := cipher.NewCBCDecrypter(block, keyByte[:blockSize])

	// 创建数组，存储解密结果
	decodeResult := make([]byte, len(decodeString))
	// 解密
	blockMode.CryptBlocks(decodeResult, decodeString)

	// 解码
	padding := PKCS7UNPadding(decodeResult)
	println("the decrypt str is ", string(padding))
	return string(padding)
}

// 解码
func PKCS7UNPadding(originDataByte []byte) []byte {
	length := len(originDataByte)
	unpadding := int(originDataByte[length-1])
	return originDataByte[:(length - unpadding)]
}

// 补码
func PKCS7Padding(originByte []byte, blockSize int) []byte {
	// 计算补码长度
	padding := blockSize - len(originByte)%blockSize
	// 生成补码
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	// 追加补码
	return append(originByte, padText...)
}

func encryptWithAES(plaintext []byte) ([]byte, error) {
	// 创建一个新的 AES 加密块
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
		//panic(err)
	}
	// 创建一个用于加密的 GCM 模式的实例
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// 创建一个随机的 nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// 加密数据
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	fmt.Printf("Ciphertext: %s\n", ciphertext)
	return ciphertext, nil
}

type responseWriter struct {
	buffer       bytes.Buffer
	lastModified bool
	wroteHeader  bool

	http.ResponseWriter
}

func (r *responseWriter) WriteHeader(statusCode int) {
	if !r.lastModified {
		r.ResponseWriter.Header().Del("Last-Modified")
	}

	r.wroteHeader = true

	// Delegates the Content-Length Header creation to the final body write.
	r.ResponseWriter.Header().Del("Content-Length")

	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseWriter) Write(p []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}

	return r.buffer.Write(p)
}

func (r *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("%T is not a http.Hijacker", r.ResponseWriter)
	}

	return hijacker.Hijack()
}

func (r *responseWriter) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
