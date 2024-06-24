package plugin_encrypt_body

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestServeHTTP(t *testing.T) {
	tests := []struct {
		desc            string
		contentEncoding string
		rewrites        []Rewrite
		lastModified    bool
		resBody         string
		expResBody      string
		expLastModified bool
		contentType     string
	}{
		{
			desc: "should replace foo by bar",
			rewrites: []Rewrite{
				{
					Regex:       "result",
					Replacement: "bar",
				},
				{
					Regex: "msg",
				},
			},
			//resBody: "{\"foo\":200, \"msg\": \"is the new bar\", \"result\": \"shuyo\" }",
			resBody:    "{\"foo\":200, \"msg\": \"is the new bar\", \"result\": {\"user\": \"zhai\", \"中文@!#$131ffA\": \"shuyo\"} }",
			expResBody: "{\"foo\":200, \"msg\": \"is the new bar\", \"result\": {\\\"user\\\": \\\"zhai\\\", \\\"中文@!#$131ffA\\\": \\\"shuyo\\\"} }",
			//expResBody: "{\"foo\":200,\"msg\":\"is the new bar\",\"result\":\"shuyo\"}",
			contentType: "application/json",
		},
		{
			desc: "should replace foo by bar, then by foo",
			rewrites: []Rewrite{
				{
					Regex:       "foo",
					Replacement: "bar",
				},
				{
					Regex:       "bar",
					Replacement: "foo",
				},
			},
			resBody:    "foo is the new bar",
			expResBody: "foo is the new foo",
		},
		{
			desc: "should not replace anything if content encoding is not identity or empty",
			rewrites: []Rewrite{
				{
					Regex:       "foo",
					Replacement: "bar",
				},
			},
			contentEncoding: "gzip",
			resBody:         "foo is the new bar",
			expResBody:      "foo is the new bar",
		},
		{
			desc: "should replace foo by bar if content encoding is identity",
			rewrites: []Rewrite{
				{
					Regex:       "foo",
					Replacement: "bar",
				},
			},
			contentEncoding: "identity",
			resBody:         "foo is the new bar",
			expResBody:      "bar is the new bar",
		},
		{
			desc: "should not remove the last modified header",
			rewrites: []Rewrite{
				{
					Regex:       "foo",
					Replacement: "bar",
				},
			},
			contentEncoding: "identity",
			lastModified:    true,
			resBody:         "foo is the new bar",
			expResBody:      "bar is the new bar",
			expLastModified: true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			config := &Config{
				LastModified: test.lastModified,
				Rewrites:     test.rewrites,
			}

			next := func(rw http.ResponseWriter, req *http.Request) {
				rw.Header().Set("Content-Encoding", test.contentEncoding)
				rw.Header().Set("Content-Type", test.contentType)
				rw.Header().Set("Last-Modified", "Thu, 02 Jun 2016 06:01:08 GMT")
				rw.Header().Set("Content-Length", strconv.Itoa(len(test.resBody)))
				rw.WriteHeader(http.StatusOK)

				_, _ = fmt.Fprintf(rw, test.resBody)
			}

			rewriteBody, err := New(context.Background(), http.HandlerFunc(next), config, "rewriteBody")
			if err != nil {
				t.Fatal(err)
			}

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)

			rewriteBody.ServeHTTP(recorder, req)

			if _, exists := recorder.Result().Header["Last-Modified"]; exists != test.expLastModified {
				t.Errorf("got last-modified header %v, want %v", exists, test.expLastModified)
			}

			if _, exists := recorder.Result().Header["Content-Length"]; exists {
				t.Error("The Content-Length Header must be deleted")
			}
			body := recorder.Body.Bytes()

			fmt.Printf("body:%q \n", body)
			var resultMap map[string]interface{}
			err = json.Unmarshal(body, &resultMap)
			if err != nil {
				log.Printf("json:%s, \n 解析失败: %s\n", body, err.Error())
				return
			}
			dataValue, _ := resultMap["result"].(string)

			fmt.Printf("match result: %s\n", dataValue)
			// 对 result 属性的值进行解密
			decodeString, _ := base64.StdEncoding.DecodeString(dataValue)

			decryptStr, err := decryptBySM2(decodeString)
			log.Println("解密后的明文：", string(decryptStr))

			resultMap["result"] = string(decryptStr)
			resultJson, err := json.Marshal(resultMap)
			if !bytes.Equal(resultJson, []byte(test.expResBody)) {
				t.Errorf("got body %s\n but want %s", resultJson, test.expResBody)
			}
		})
	}
}

func TestSm4(t *testing.T) {
	text := "112333"
	encrypt, err := SM4Encrypt([]byte(text))
	if err != nil {
		println(err)
	}
	log.Printf("encrypt text is %x \n", encrypt)
	log.Printf("encrypt base64 is %s\n", base64.StdEncoding.EncodeToString(encrypt))

	decrypt, err := SM4Decrypt(encrypt)
	if err != nil {
		println(err)
	}
	log.Printf("decrypt text is %s \n", decrypt)
}

// sm2解密
func TestDecryptSM2(t *testing.T) {
	text := "BKq0igwhiZMcGy1Ow1pKZHizX3aGGYrkB/vQMCZg4UocS9hSphcxbNSWLoao91H61ZQfLmfBYxfQiP+jKJ0q1DtzqgmHTZ1URL1eQvx6PNof7i3VKCUDMLiI7CzWowNEiJ0gcE5fJw=="
	decodeString, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		println(err)
	}

	fmt.Printf("待解密文案: %s \n", decodeString)
	decrypt, err := decryptBySM2(decodeString)
	if err != nil {
		println(err)
	}
	fmt.Printf("encrpyt is %s\n", decrypt)
}
func TestEncryptByBySM2(t *testing.T) {
	str := "ffff112233"
	cipherText, err := EncryptByBySM2([]byte(str))
	if err != nil {
		log.Println(err)
	}
	log.Printf("text is :%v\n", cipherText)
	toString := base64.StdEncoding.EncodeToString(cipherText)
	log.Printf("cipher base64 is: %s\n", toString)
	sm2, err := decryptBySM2(cipherText)
	log.Printf("decrypt text: %s \n", sm2)
}

// AES解密
func TestAesDecryptByCBC(t *testing.T) {
	text := "FxkN9RuqSdvJOirKz/xqDA=="
	fmt.Printf("待解密文案: %v \n", text)
	decrypt := AesDecryptByCBC(text, key)
	fmt.Printf("解密结果: %v \n", decrypt)
}
func TestBase64(t *testing.T) {
	data := "ff112233"
	encrypt := EncryptStrSM2([]byte(data))
	log.Printf("encrypt str is %x \n", encrypt)
	encodeToString := base64.StdEncoding.EncodeToString(encrypt)
	fmt.Println(encodeToString)

}

func TestNew(t *testing.T) {
	tests := []struct {
		desc     string
		rewrites []Rewrite
		expErr   bool
	}{
		{
			desc: "should return no error",
			rewrites: []Rewrite{
				{
					Regex:       "foo",
					Replacement: "bar",
				},
				{
					Regex:       "bar",
					Replacement: "foo",
				},
			},
			expErr: false,
		},
		{
			desc: "should return an error",
			rewrites: []Rewrite{
				{
					Regex:       "*",
					Replacement: "bar",
				},
			},
			expErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			config := &Config{
				Rewrites: test.rewrites,
			}

			_, err := New(context.Background(), nil, config, "rewriteBody")
			if test.expErr && err == nil {
				t.Fatal("expected error on bad regexp format")
			}
		})
	}
}
