# Example Client

This small Go program implements an extremely bare-bones OAuth2 server using
the [fosite](https://github.com/ory/fosite) package. The OAuth2 server should
always generate a token for a given authorization request. The `/login` flow
will use the PKCE wrapper to ensure a code verifier and challenge code are
created and appropriately sent. The fosite OAuth2 library ensures that they are
valid and match.

Running the program will launch a browser, clicking the login link will take
you to the authorize page on the OAuth2 instance, and send you back.

You can switch the commented lines to revert to non-PKCE calls in the `main.go`
and see the OAuth2 server reject the requests.
