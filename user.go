package alipay_user

import (
	"alipay_user/requests"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/go-resty/resty/v2"
	"net/url"
	"sort"
	"strings"
	"time"
)

var AlipayOpenapiGateway = "https://openapi.alipay.com/gateway.do"

type UserOption struct {
	f func(*Options)
}

type Options struct {
	Debug bool
}

func IsDebug(debug bool) UserOption {
	return UserOption{func(op *Options) {
		op.Debug = debug
	}}
}

type AlipayUser struct {
	AppID      string
	PrivateKey string
	Options    *Options
}

// NewAlipayUser init
func NewAlipayUser(appid, privateKey string, options ...UserOption) (*AlipayUser, error) {
	if appid == "" {
		return nil, errors.New("appid can not be empty")
	}
	if privateKey == "" {
		return nil, errors.New("privateKey can not be empty")
	}
	// init
	conf := &AlipayUser{
		AppID:      appid,
		PrivateKey: privateKey,
		Options:    &Options{Debug: false},
	}

	for _, option := range options {
		option.f(conf.Options)
	}
	return conf, nil
}

// rSA2Sign 使用RSA2算法对数据进行签名
func (s *AlipayUser) rSA2Sign(data, privateKey string) (string, error) {
	// 解析私钥
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return "", fmt.Errorf("private key error")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	// 确保私钥是*rsa.PrivateKey类型
	rsaPrivKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key is not of type *rsa.PrivateKey")
	}
	// 计算数据的SHA256哈希值
	hash := sha256.New()
	hash.Write([]byte(data))
	hashed := hash.Sum(nil)
	// 使用PKCS1v15进行签名
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivKey, crypto.SHA256, hashed)
	if err != nil {
		return "", err
	}
	// 对签名进行Base64编码
	return base64.StdEncoding.EncodeToString(signature), nil
}

// buildSignData 构建待签名的数据
func (s *AlipayUser) buildSignData(params map[string]string) string {
	// 排序参数
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// 构建待签名字符串
	var signData strings.Builder
	for i, k := range keys {
		if i > 0 {
			signData.WriteByte('&')
		}
		signData.WriteString(k)
		signData.WriteByte('=')
		signData.WriteString(params[k])

	}
	return signData.String()
}

func (s *AlipayUser) UserInfo(code string) (*requests.AlipayOauthTokenResponse, error) {
	if code == "" {
		return nil, errors.New("code can not be empty")
	}
	req := map[string]string{
		"app_id":     s.AppID,
		"charset":    "UTF-8",
		"method":     "alipay.system.oauth.token",
		"sign_type":  "RSA2",
		"timestamp":  time.Now().Format("2006-01-02 15:04:05"),
		"version":    "1.0",
		"grant_type": "authorization_code", // 或者 "refresh_token"
		"code":       code,
	}
	// 构建待签名字符串
	signData := s.buildSignData(req)
	// 生成签名
	sign, err := s.rSA2Sign(signData, s.PrivateKey)
	if err != nil {
		fmt.Printf("签名失败: %v\n", err)
		return nil, err
	}

	req["sign"] = sign
	requestData := ""
	and := ""
	for i, i2 := range req {
		requestData += and + i + "=" + url.QueryEscape(i2)
		and = "&"
	}

	resp, err := resty.New().SetDebug(s.Options.Debug).R().
		SetBody(map[string]string{
			"grant_type": "authorization_code", // 或者 "refresh_token"
			"code":       code,
		}).
		SetHeader("Content-Type", "application/json;charset=UTF-8").
		Post(AlipayOpenapiGateway + "?" + requestData)
	if err != nil {
		return nil, err
	}
	var alipayUserInfo *requests.AlipayOauthTokenResponse
	err = json.Unmarshal(resp.Body(), &alipayUserInfo)
	if err != nil {
		return nil, err
	}
	if alipayUserInfo.AlipaySystemOAuthTokenResponse.OpenID == "" {
		var errResp requests.AlipayOauthTokenErrorResponse
		err1 := json.Unmarshal(resp.Body(), &errResp)
		if err1 != nil {
			return nil, err1
		}
		if errResp.ErrorResponse.Code != "" {
			return nil, errors.New(errResp.ErrorResponse.Msg)
		}

		return nil, errors.New("获取用户信息失败")
	}

	return alipayUserInfo, nil
}
