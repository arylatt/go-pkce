package pkce

import (
	"context"

	"golang.org/x/oauth2"
)

// Config is a wrapper around oauth2.Config.
// See https://pkg.go.dev/golang.org/x/oauth2#Config.
type Config struct {
	oauth2.Config
}

// AuthCodeURL is a wrapper around oauth2's Config.AuthCodeURL, and injects the code_challenge_method of S256
// and the provided challenge value into the request.
func (c *Config) AuthCodeURL(state, challenge string, opts ...oauth2.AuthCodeOption) string {
	opts = append([]oauth2.AuthCodeOption{oauth2.SetAuthURLParam(ParamCodeChallengeMethod, MethodS256)}, opts...)
	opts = append([]oauth2.AuthCodeOption{oauth2.SetAuthURLParam(ParamCodeChallenge, challenge)}, opts...)

	return c.Config.AuthCodeURL(state, opts...)
}

// Exchange is a wrapper around oauth2's Config.Exchange, and injects the provided verifier value into the request.
func (c *Config) Exchange(ctx context.Context, code, verifier string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	opts = append([]oauth2.AuthCodeOption{oauth2.SetAuthURLParam(ParamCodeVerifier, verifier)}, opts...)

	return c.Config.Exchange(ctx, code, opts...)
}
