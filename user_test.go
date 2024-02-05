package alipay_user

import (
	"fmt"
	"testing"
)

func TestUserInfo(t *testing.T) {
	AlipayAppPrivateKey := `-----BEGIN RSA PRIVATE KEY-----
xxxxx
-----END RSA PRIVATE KEY-----`
	u, err := NewAlipayUser("1234",
		AlipayAppPrivateKey,
		IsDebug(false))
	fmt.Println(u, err)
	res, err := u.UserInfo("11")
	fmt.Println("231313123", res, err)
}
