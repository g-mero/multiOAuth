// Gitee Oauth2 认证
// https://gitee.com/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code

package giteeAuth

import (
	"errors"
	"github.com/bytedance/sonic"
	"github.com/imroc/req/v3"
)

type GiteeAuth struct {
	ClientID     string
	ClientSecret string
}

var (
	client         = req.C().SetCommonHeader("Accept", "application/json")
	apiTokenUrl    = "https://gitee.com/oauth/token"
	apiUserInfoUrl = "https://gitee.com/api/v5/user"
	apiUserEmails  = "https://gitee.com/api/v5/emails"
)

func NewGiteeAuth(clientID, clientSecret string) *GiteeAuth {
	return &GiteeAuth{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
}

func (that *GiteeAuth) GetAccessToken(code, redirectUri string) (string, error) {
	resp, err := client.R().SetQueryParam("grant_type", "authorization_code").
		SetQueryParam("code", code).SetQueryParam("client_id", that.ClientID).
		SetQueryParam("redirect_uri", redirectUri).
		SetQueryParam("client_secret", that.ClientSecret).Post(apiTokenUrl)
	if err != nil {
		return "", err
	}
	if resp.IsErrorState() {
		return "", errors.New("gitee api error: " + resp.Status)
	}
	node, err := sonic.Get(resp.Bytes(), "access_token")
	if err != nil {
		return "", err
	}

	return node.String()
}

// GetUserInfo get user info
func (that *GiteeAuth) GetUserInfo(accessToken string) ([]byte, error) {
	resp, err := client.R().SetQueryParam("access_token", accessToken).Get(apiUserInfoUrl)
	if err != nil {
		return nil, err
	}
	if resp.IsErrorState() {
		return nil, errors.New("gitee api error: " + resp.Status)
	}
	return resp.Bytes(), nil
}

// GetUserEmails get user emails
func (that *GiteeAuth) GetUserEmails(accessToken string) ([]string, error) {
	resp, err := client.R().SetQueryParam("access_token", accessToken).Get(apiUserEmails)
	if err != nil {
		return nil, err
	}
	if resp.IsErrorState() {
		return nil, errors.New("gitee api error: " + resp.Status)
	}

	var emailStruct []struct {
		Email string `json:"email"`
	}

	err = sonic.Unmarshal(resp.Bytes(), &emailStruct)
	if err != nil {
		return nil, err
	}

	emails := make([]string, len(emailStruct))
	for i, v := range emailStruct {
		emails[i] = v.Email
	}

	return emails, nil
}
