package xproject

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"time"

	"github.com/haruno-bot/haruno/util"
)

type AuthenticationEntity struct {
	Token     string `json:"token"`
	Key       string `json:"key"`
	Timestamp int64  `json:"timestamp"`
}

type HTTPClient struct {
	http.Client
	Header http.Header
}

// GetVoucher
func GetVoucher(key []byte, token, publickeyURL, authURL string) (string, error) {
	client := new(HTTPClient)
	// 设置默认的请求头
	client.Header = make(http.Header)
	client.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.62 Safari/537.36")
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	client.Transport = transport
	req, err := http.NewRequest(http.MethodGet, publickeyURL, nil)
	req.Header.Set("Content-Type", "Content-Type: text/plain")
	if err != nil {
		return "", err
	}
	if client.Header != nil {
		req.Header = client.Header
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if buf.Bytes()[0] == 60 {
		return "", errors.New("could not get public key")
	}
	publicKey, err := util.ParseBase64RAWPKIXPublicKey(string(buf.Bytes()))
	if err != nil {
		return "", err
	}
	authEntity := new(AuthenticationEntity)
	authEntity.Token = token
	authEntity.Key = base64.StdEncoding.EncodeToString(key)
	authEntity.Timestamp = getJSTimestamp()
	msg, _ := json.Marshal(authEntity)
	cipherBody, err := util.PublicEncrypt(msg, publicKey)
	if err != nil {
		return "", err
	}
	req, err = http.NewRequest(http.MethodPost,
		authURL,
		ioutil.NopCloser(bytes.NewReader([]byte(base64.StdEncoding.EncodeToString(cipherBody)))))
	req.Header.Set("Content-Type", "Content-Type: text/plain")
	if err != nil {
		return "", err
	}
	if client.Header != nil {
		req.Header = client.Header
	}
	resp, err = client.Do(req)
	if err != nil {
		return "", err
	}
	webResponseProto := new(WebResponseProto)
	buf = new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	err = json.Unmarshal(buf.Bytes(), webResponseProto)
	if err != nil {
		return "", err
	}
	if webResponseProto.ResultType != SUCCESS {
		return "", fmt.Errorf("authentication failed with: %s", webResponseProto.Msg)
	}
	voucher, err := base64.StdEncoding.DecodeString(webResponseProto.Data)
	if err != nil {
		return "", err
	}
	_voucher, err := util.AESGCMDecrypt(voucher, key)
	if err != nil {
		return "", err
	}
	return string(_voucher), nil
}

func getJSTimestamp() int64 {
	return (time.Now().Unix() + (60 * 60 * 9)) * 1000
}
