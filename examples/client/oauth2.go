package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/storage"
)

var (
	fsConfig = &fosite.Config{
		EnforcePKCE:         true,
		MinParameterEntropy: 0,
		GlobalSecret:        secret,
	}

	fsStore       = storage.NewExampleStore()
	secret        = []byte("some-cool-secret-that-is-32bytes")
	privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)

	fsOAuth2 = compose.ComposeAllEnabled(fsConfig, fsStore, privateKey)
)

func authGet(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("content-type", "text/html")
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte(`
		<p>Click Login</p>
		<form method="post">
			<input type="submit" value="Login" />
		</form>
	`))
}

func authPost(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ar, err := fsOAuth2.NewAuthorizeRequest(ctx, r)
	if err != nil {
		log.Printf("NewAuthorizeRequest error: %+v", err)
		fsOAuth2.WriteAuthorizeError(ctx, rw, ar, err)
		return
	}

	resp, err := fsOAuth2.NewAuthorizeResponse(ctx, ar, &fosite.DefaultSession{Username: "anon"})
	if err != nil {
		log.Printf("NewAuthorizeResponse error: %+v", err)
		fsOAuth2.WriteAuthorizeError(ctx, rw, ar, err)
		return
	}

	fsOAuth2.WriteAuthorizeResponse(ctx, rw, ar, resp)
}

func token(rw http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := &fosite.DefaultSession{}

	ar, err := fsOAuth2.NewAccessRequest(ctx, r, session)
	if err != nil {
		log.Printf("NewAccessRequest error: %+v", err)
		fsOAuth2.WriteAccessError(ctx, rw, ar, err)
		return
	}

	resp, err := fsOAuth2.NewAccessResponse(ctx, ar)
	if err != nil {
		log.Printf("NewAccessResponse error: %+v", err)
		fsOAuth2.WriteAccessError(ctx, rw, ar, err)
		return
	}

	fsOAuth2.WriteAccessResponse(ctx, rw, ar, resp)
}

func oauth2Routes(r *mux.Router) {
	subRouter := r.PathPrefix("/oauth2").Subrouter()

	subRouter.Path("/auth").Methods(http.MethodGet).HandlerFunc(authGet)
	subRouter.Path("/auth").Methods(http.MethodPost).HandlerFunc(authPost)
	subRouter.Path("/token").HandlerFunc(token)
}
