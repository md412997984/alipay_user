package requests

// AlipayOauthTokenResponse 响应结构体
type AlipayOauthTokenResponse struct {
	AlipaySystemOAuthTokenResponse AlipaySystemOAuthTokenResponse `json:"alipay_system_oauth_token_response"`
	Sign                           string                         `json:"sign"`
}
type ErrorResponseData struct {
	Code    string `json:"code"`
	Msg     string `json:"msg"`
	SubCode string `json:"sub_code"`
	SubMsg  string `json:"sub_msg"`
}

type AlipayOauthTokenErrorResponse struct {
	ErrorResponse ErrorResponseData `json:"error_response"`
	Sign          string            `json:"sign"`
}
type AlipaySystemOAuthTokenResponse struct {
	UserID       string `json:"user_id"`
	OpenID       string `json:"open_id"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	ReExpiresIn  int    `json:"re_expires_in"`
	AuthStart    string `json:"auth_start"`
}
