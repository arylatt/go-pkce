# PKCE Library for Go

`go-pkce` provides a PKCE library for Go, implementing the `S256` challenge
method.

Functions are provided for generating verifiers, challenges from verifiers, and
validating a challenge matches a verifier.

Additionally a wrapper around
[golang.org/x/oauth2.Config](https://pkg.go.dev/golang.org/x/oauth2#Config) has
been provided, which adds the additional parameters to be sent to the server.

## Usage

Some usage examples.

### Generate a new code verifier, challenge, and send to the server

```go
func ExampleConfig() {
  ctx := context.Background()
  conf := &pkce.Config{
    oauth2.Config{
      ClientID:     "YOUR_CLIENT_ID",
      ClientSecret: "YOUR_CLIENT_SECRET",
      Scopes:       []string{"SCOPE1", "SCOPE2"},
      Endpoint: oauth2.Endpoint{
        AuthURL:  "https://provider.com/o/oauth2/auth",
        TokenURL: "https://provider.com/o/oauth2/token",
      },
    },
  }

  verifier, _ := pkce.NewCodeVerifier(32)
  challenge, _ := pkce.CodeChallenge(verifier)

  url := conf.AuthCodeURL("state", challenge, oauth2.AccessTypeOffline)

  fmt.Printf("Visit the URL and log in: %s\n", url)
  fmt.Print("Enter code from return URI: ")

  code := ""
  if _, err := fmt.Scan(&code); err != nil {
    log.Fatal(err)
  }
  tok, err := conf.Exchange(ctx, code, verifier)
  if err != nil {
    log.Fatal(err)
  }

  client := conf.Client(ctx, tok)
}
```
