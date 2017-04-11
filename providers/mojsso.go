package providers

import (
	"errors"
	"fmt"
	"github.com/bitly/oauth2_proxy/api"
	"log"
	"net/http"
	"net/url"
)

type MoJSSOProvider struct {
	*ProviderData
}

func NewMoJSSOProvider(p *ProviderData) *MoJSSOProvider {
	p.ProviderName = "Ministry of Justice Sign On"
	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "signon.service.justice.gov.uk",
			Path:   "/oauth/authorize",
		}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "signon.service.justice.gov.uk",
			Path:   "/oauth/token",
		}
	}
	if p.ProfileURL == nil || p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{
			Scheme: "https",
			Host:   "signon.service.justice.gov.uk",
			Path:   "/api/user_details",
		}
	}
	return &MoJSSOProvider{ProviderData: p}
}

func (p *MoJSSOProvider) GetEmailAddress(s *SessionState) (string, error) {
	var email string
	var err error

	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}

	header := make(http.Header)
	header.Set("Authorization", fmt.Sprintf("Bearer %s", s.AccessToken))
	req.Header = header

	json, err := api.Request(req)

	if err != nil {
		return "", err
	}

	email, err = getEmailFromJSON(json)

	if err == nil && email != "" {
		return email, err
	}

	email, err = json.Get("email").String()

	if err != nil {
		log.Printf("failed making request %s", err)
		return "", err
	}

	if email == "" {
		log.Printf("failed to get email address")
		return "", err
	}

	return email, err
}
