package main

import (
	"log"
	"net/http"
	"os"

	"github.com/arylatt/go-pkce"
	"github.com/gorilla/mux"
	"github.com/ory/fosite"
	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

var (
	config *pkce.Config

	authed        = false
	codeVerifier  = ""
	codeChallenge = ""
)

func main() {
	port := "8081"
	if portStr := os.Getenv("PORT"); portStr != "" {
		port = portStr
	}

	router := mux.NewRouter()

	oauth2Routes(router)
	router.Path("/").HandlerFunc(homeHandler)
	router.Path("/login").HandlerFunc(loginHandler)
	router.Path("/logout").HandlerFunc(logoutHandler)
	router.Path("/callback").HandlerFunc(callbackHandler)

	config = &pkce.Config{
		Config: oauth2.Config{
			ClientID:     "my-client",
			ClientSecret: "foobar",
			RedirectURL:  "http://localhost:" + port + "/callback",
			Scopes:       []string{"offline"},
			Endpoint: oauth2.Endpoint{
				TokenURL: "http://localhost:" + port + "/oauth2/token",
				AuthURL:  "http://localhost:" + port + "/oauth2/auth",
			},
		},
	}

	fsStore.Clients["my-client"].(*fosite.DefaultClient).RedirectURIs = []string{config.RedirectURL}

	browser.OpenURL("http://localhost:" + port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}

func homeHandler(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("content-type", "text/html")
	rw.WriteHeader(http.StatusOK)

	if !authed {
		rw.Write([]byte(`
			<p>Not logged in. <a href="/login">Login?</a></p>
		`))
		return
	}

	rw.Write([]byte(`
		<p>Logged in. <a href="/logout">Logout?</a></p>
	`))
}

func loginHandler(rw http.ResponseWriter, r *http.Request) {
	if authed {
		http.Redirect(rw, r, "/", http.StatusTemporaryRedirect)
		return
	}

	var err error

	codeVerifier, err = pkce.NewCodeVerifier(32)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	codeChallenge, err = pkce.CodeChallenge(codeVerifier)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	// Switch the lines below to bypass PKCE
	// http.Redirect(rw, r, config.Config.AuthCodeURL("some-random-state-foobar"), http.StatusTemporaryRedirect)
	http.Redirect(rw, r, config.AuthCodeURL("some-random-state-foobar", codeChallenge), http.StatusTemporaryRedirect)
}

func logoutHandler(rw http.ResponseWriter, r *http.Request) {
	authed = false
	codeVerifier = ""
	codeChallenge = ""

	http.Redirect(rw, r, "/", http.StatusTemporaryRedirect)
}

func callbackHandler(rw http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	// Switch the lines below to bypass PKCE
	// token, err := config.Config.Exchange(r.Context(), code)
	token, err := config.Exchange(r.Context(), code, codeVerifier)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("got token: %+v", token)

	authed = true
	codeVerifier = ""
	codeChallenge = ""

	http.Redirect(rw, r, "/", http.StatusTemporaryRedirect)
}
