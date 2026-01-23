package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
)

type SessionClient struct {
	authClient *AuthClient
	baseURL    string
}

func NewSessionClient(authClient *AuthClient) *SessionClient {
	return &SessionClient{
		authClient: authClient,
		baseURL:    "https://sessions.hytale.com",
	}
}

type GameSession struct {
	ExpiresAt     time.Time `json:"expiresAt"`
	IdentityToken string    `json:"identityToken"`
	SessionToken  string    `json:"sessionToken"`
}

func (c *SessionClient) NewGameSession(profile uuid.UUID) (*GameSession, error) {
	data := map[string]uuid.UUID{"uuid": profile}
	j, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.baseURL+"/game-session/new", bytes.NewBuffer(j))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.authClient.Credentials.AccessToken))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, errors.New("unexpected status code: " + strconv.Itoa(res.StatusCode))
	}

	decoder := json.NewDecoder(res.Body)
	gs := &GameSession{}
	if err := decoder.Decode(gs); err != nil {
		return nil, err
	}

	fmt.Println("[SessionToken] ", gs.SessionToken)

	return gs, nil
}

type AccessTokenResponse struct {
	AccessToken string `json:"accessToken"`
}

func (c *SessionClient) ExchangeAuthToken(fingerprint, grant, sessionToken string) (string, error) {
	data := map[string]string{"x509Fingerprint": fingerprint, "authorizationGrant": grant}
	j, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", c.baseURL+"/server-join/auth-token", bytes.NewBuffer(j))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sessionToken))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", errors.New("unexpected status code: " + strconv.Itoa(res.StatusCode))
	}

	decoder := json.NewDecoder(res.Body)
	at := &AccessTokenResponse{}
	if err := decoder.Decode(at); err != nil {
		return "", err
	}

	return at.AccessToken, nil
}

type AuthorizationGrantResponse struct {
	AuthorizationGrant string `json:"authorizationGrant"`
}

func (c *SessionClient) ExchangeAuthGrant(identityToken, sessionToken string) (string, error) {
	data := map[string]string{"identityToken": identityToken, "aud": "hytale-client"}
	j, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", c.baseURL+"/server-join/auth-grant", bytes.NewBuffer(j))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sessionToken))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", errors.New("unexpected status code: " + strconv.Itoa(res.StatusCode))
	}

	decoder := json.NewDecoder(res.Body)
	at := &AuthorizationGrantResponse{}
	if err := decoder.Decode(at); err != nil {
		return "", err
	}

	return at.AuthorizationGrant, nil
}
