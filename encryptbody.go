// Package plugin_encrypt_body a plugin to encrypt and rewrite response body.
package plugin_encrypt_body

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
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

	r.next.ServeHTTP(wrappedWriter, req)

	bodyBytes := wrappedWriter.buffer.Bytes()

	contentEncoding := wrappedWriter.Header().Get("Content-Encoding")

	if contentEncoding != "" && contentEncoding != "identity" {
		if _, err := rw.Write(bodyBytes); err != nil {
			log.Printf("unable to write body: %v", err)
		}

		return
	}

	//if contentEncoding == "application/json" {
	// 解析 JSON 数据
	var resultMap map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &resultMap); err != nil {
		log.Printf("json:%s, 解析失败: %s", bodyBytes, err.Error())
		return
	}

	// 获取 data 属性的值
	dataValue, ok := resultMap["result"].(string)
	if !ok {
		log.Printf("result 属性不是字符串")
		return
	}
	fmt.Printf("match result:%v\n", dataValue)
	// 对 data 属性的值进行 AES 加密
	ciphertext, err := encryptWithAES([]byte(dataValue))
	if err != nil {
		log.Printf("traefik-encrypt-body：加密失败%v", err.Error())
		return
	}

	// 将加密后的值放回到 data 属性中
	resultMap["result"] = hex.EncodeToString(ciphertext)

	fmt.Printf("json by encrypted:%v\n", resultMap)
	// 将修改后的 JSON 数据编码为字节数组
	bodyBytes, err = json.Marshal(resultMap)

	var testmap map[string]interface{}
	err = json.Unmarshal(bodyBytes, &testmap)

	testv, ok := testmap["result"].(string)

	fmt.Printf("test match result:%v\n", testv)
	// 对 result 属性的值进行
	res, err := decryptWithAES([]byte(testv))
	fmt.Printf("res is %x", res)

	if err != nil {
		log.Printf("traefik-encrypt-body：加密失败%v", err.Error())
		return
	}
	//} else {
	//	for _, rwt := range r.rewrites {
	//		bodyBytes = rwt.regex.ReplaceAll(bodyBytes, rwt.replacement)
	//		//matches := rwt.regex.FindAllSubmatch(bodyBytes, -1)
	//		//if len(matches) > 0 {
	//		//	for _, match := range matches {
	//		//		encryptedText, err := encryptWithAES(match[0])
	//		//		if err != nil {
	//		//			log.Printf("unable to encrypt match: %v", err)
	//		//			continue
	//		//		}
	//		//
	//		//		fmt.Printf("bodyBytes before: %x\n", hex.EncodeToString(bodyBytes))
	//		//		bodyBytes = bytes.ReplaceAll(bodyBytes, match[0], encryptedText)
	//		//	}
	//		//}
	//	}
	//
	//}

	if _, err := rw.Write(bodyBytes); err != nil {
		log.Printf("unable to write rewrited body: %v", err)
	}
}

// ====== encrypt ======
var key = []byte("1234567890123456")

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

func encryptWithAES(plaintext []byte) ([]byte, error) {
	//key := []byte("shuyo-2024061819474202")
	// 创建一个新的 AES 加密块
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// 创建一个用于加密的 GCM 模式的实例
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	// 创建一个随机的 nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	// 加密数据
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	fmt.Printf("Ciphertext: %x\n", ciphertext)

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
