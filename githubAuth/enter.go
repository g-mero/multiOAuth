// GitHub OAuth 认证
// 需要提供 GitHub Oauth应用 的 client_id 和 client_secret
// 前端请求链接类似
// https://github.com/login/oauth/authorize?client_id=b8976230f95a22dd12ae&redirect_uri=http://127.0.0.1:8888/auth/github&scope=user:email

package githubAuth

import (
	"errors"
	"github.com/bytedance/sonic"
	"github.com/imroc/req/v3"
)

type GithubAuth struct {
	ClientID     string
	ClientSecret string
}

var (
	client         = req.C().SetCommonHeader("Accept", "application/json")
	apiTokenUrl    = "https://github.com/login/oauth/access_token"
	apiUserInfoUrl = "https://api.github.com/user"
	apiUserEmails  = "https://api.github.com/user/emails"
)

func NewGithubAuth(clientID, clientSecret string) *GithubAuth {
	return &GithubAuth{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
}

func (that *GithubAuth) GetAccessToken(code string) (string, error) {
	resp, err := client.R().SetQueryParam("client_id", that.ClientID).
		SetQueryParam("client_secret", that.ClientSecret).
		SetQueryParam("code", code).
		Post(apiTokenUrl)
	if err != nil {
		return "", err
	}

	if resp.IsErrorState() {
		return "", errors.New("github api error: " + resp.Status)
	}

	node, err := sonic.Get(resp.Bytes(), "access_token")
	if err != nil {
		return "", err
	}

	accessToken, err := node.String()

	return accessToken, err
}

func (that *GithubAuth) GetUserInfo(accessToken string) ([]byte, error) {
	resp, err := client.R().
		SetHeader("Authorization", "Bearer "+accessToken).
		Get(apiUserInfoUrl)
	if err != nil {
		return nil, err
	}

	if resp.IsErrorState() {
		return nil, errors.New("github api error: " + resp.Status)
	}

	return resp.Bytes(), nil
}

// GetUserEmails get user emails
func (that *GithubAuth) GetUserEmails(accessToken string) ([]string, error) {
	resp, err := client.R().SetHeader("Authorization", "Bearer "+accessToken).Get(apiUserEmails)
	if err != nil {
		return nil, err
	}
	if resp.IsErrorState() {
		return nil, errors.New("github api error: " + resp.Status)
	}

	var emailStruct []struct {
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	}

	err = sonic.Unmarshal(resp.Bytes(), &emailStruct)
	if err != nil {
		return nil, err
	}

	emails := make([]string, len(emailStruct))
	index := len(emailStruct) - 1
	// 将主邮箱放在第一位，其他邮箱放在后面
	for _, email := range emailStruct {
		if email.Primary {
			emails[0] = email.Email
		} else {
			emails[index] = email.Email
			index--
		}
	}

	return emails, nil
}
