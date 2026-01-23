package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
)

var (
	ServerPort = 63355

	LauncherArch = "amd64"
	LauncherOS   = "win"
)

type Profile struct {
	Id               uuid.UUID `json:"uuid"`
	CreatedAt        time.Time `json:"createdAt"`
	Entitlements     []string  `json:"entitlements"`
	NextNameChangeAt time.Time `json:"nextNameChangeAt"`
	Skin             string    `json:"skin"` // Parse later
	Username         string    `json:"username"`
}

type AccountData struct {
	Owner    uuid.UUID
	Profiles []*Profile
}

type AuthClient struct {
	codeChannel   chan string
	codeChallenge string
	codeVerifier  string
	state         string

	server *http.Server

	Authenticated bool
	Credentials   *Credentials
	AccountData   *AccountData
}

func (a *AuthClient) CodeServer() {
	creds, err := LoadCredentials()
	if creds != nil && err == nil {
		a.Credentials = creds
		a.Authenticated = true

		a.codeChannel <- "yes"
		return
	}

	mux := http.NewServeMux()

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", ServerPort),
		Handler: mux,
	}

	mux.HandleFunc("/authorization-callback", func(w http.ResponseWriter, req *http.Request) {
		q := req.URL.Query()
		code := q.Get("code")
		a.codeChannel <- code

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := server.Shutdown(ctx); err != nil {
				fmt.Println(err)
			}
		}()
	})

	fmt.Println("Started listening on port " + strconv.Itoa(ServerPort))
	err = server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
	}
}

func NewAuthClient() *AuthClient {
	a := &AuthClient{
		codeChannel: make(chan string),
	}
	go a.CodeServer()
	return a
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	IdToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

func (a *AuthClient) Authenticate() error {
	code := <-a.codeChannel

	if !a.Authenticated {
		token, err := a.ExchangeCode(code)
		if err != nil {
			return err
		}

		a.Authenticated = true
		a.Credentials = &Credentials{
			AccessToken:  token.AccessToken,
			IdToken:      token.AccessToken,
			RefreshToken: token.RefreshToken,
			ExpiresIn:    token.ExpiresIn,
		}
		a.Credentials.Save()
	}

	err := a.RefreshAccountData()
	if err != nil {
		return err
	}

	return nil
}

func (a *AuthClient) RefreshAccountData() error {
	data := url.Values{}
	data.Set("arch", LauncherArch)
	data.Set("os", LauncherOS)

	url := "https://account-data.hytale.com/my-account/get-launcher-data?" + data.Encode()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.Credentials.AccessToken))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return errors.New("unexpected status code: " + strconv.Itoa(res.StatusCode))
	}

	decoder := json.NewDecoder(res.Body)
	ad := &AccountData{}
	if err := decoder.Decode(ad); err != nil {
		return err
	}

	a.AccountData = ad

	return nil
}

func (a *AuthClient) ExchangeCode(code string) (*TokenResponse, error) {
	u := url.URL{
		Scheme: "https",
		Host:   "oauth.accounts.hytale.com",
		Path:   "/oauth2/token",
	}

	d := url.Values{}
	d.Set("grant_type", "authorization_code")
	d.Set("client_id", "hytale-launcher")
	d.Set("code", code)
	d.Set("redirect_uri", "https://accounts.hytale.com/consent/client")
	d.Set("code_verifier", a.codeVerifier)

	resp, err := http.PostForm(u.String(), d)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	j := json.NewDecoder(resp.Body)
	tr := &TokenResponse{}
	if err = j.Decode(tr); err != nil {
		return nil, err
	}

	return tr, nil
}

func (a *AuthClient) GetAuthenticationURL() string {
	a.GenerateCodeChallenge()
	a.GenerateState()

	u := url.URL{
		Scheme: "https",
		Host:   "oauth.accounts.hytale.com",
		Path:   "/oauth2/auth",
	}

	queryParams := u.Query()
	queryParams.Set("access_type", "offline")
	queryParams.Set("client_id", "hytale-launcher")
	queryParams.Set("code_challenge", a.codeChallenge)
	queryParams.Set("code_challenge_method", "S256")
	queryParams.Set("redirect_uri", "https://accounts.hytale.com/consent/client")
	queryParams.Set("response_type", "code")
	queryParams.Set("scope", "openid offline auth:launcher")
	queryParams.Set("state", a.state)

	return u.String() + "?" + queryParams.Encode()
}

func (a *AuthClient) GetProfiles() ([]*Profile, error) {
	if !a.Authenticated {
		return nil, errors.New("client not authenticated")
	}

	return a.AccountData.Profiles, nil
}

func (a *AuthClient) GenerateCodeChallenge() {
	src := rand.NewSource(time.Now().UnixNano())
	b := make([]byte, 32)
	for i := 0; i < 32; i++ {
		b[i] = byte(src.Int63() & 0xff)
	}

	a.codeVerifier = base64.RawURLEncoding.EncodeToString(b)

	hash := sha256.Sum256([]byte(a.codeVerifier))
	a.codeChallenge = base64.RawURLEncoding.EncodeToString(hash[:])
}

func (a *AuthClient) GenerateState() {
	runes := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	s := make([]rune, 26)
	for i := range s {
		s[i] = runes[rand.Intn(len(runes))]
	}

	obj := map[string]interface{}{
		"state": string(s),
		"port":  ServerPort,
	}

	js, _ := json.Marshal(obj)
	a.state = base64.StdEncoding.EncodeToString(js)
}
