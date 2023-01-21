package pkce

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func newConf(url string) *Config {
	return &Config{
		oauth2.Config{
			ClientID:     "CLIENT_ID",
			ClientSecret: "CLIENT_SECRET",
			RedirectURL:  "REDIRECT_URL",
			Scopes:       []string{"scope1", "scope2"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  url + "/auth",
				TokenURL: url + "/token",
			},
		},
	}
}

func TestAuthCodeURL(t *testing.T) {
	conf := newConf("server")
	url := conf.AuthCodeURL("foo", "PERIBnViNq771HEmJfNqXWOzkjnpjwbGXVwNXzIzmA0", oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	expected := "server/auth?access_type=offline&client_id=CLIENT_ID&code_challenge=PERIBnViNq771HEmJfNqXWOzkjnpjwbGXVwNXzIzmA0&code_challenge_method=S256&prompt=consent&redirect_uri=REDIRECT_URL&response_type=code&scope=scope1+scope2&state=foo"

	assert.Equal(t, expected, url)
}

func TestExchange(t *testing.T) {
	verifier := "SOlCo_vVnPOGFAVIZey49j5Sx5Hk_spigKFvFu5LLqQ"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, verifier, r.FormValue(ParamCodeVerifier))

		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte("access_token=90d64460d14870c08c81352a05dedd3465940a7c&scope=user&token_type=bearer"))
	}))

	defer srv.Close()
	conf := newConf(srv.URL)
	_, err := conf.Exchange(context.Background(), "exchange-code", verifier)

	assert.NoError(t, err)
}
