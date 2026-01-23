package auth

import (
	"encoding/json"
	"os"
)

type Credentials struct {
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

func LoadCredentials() (*Credentials, error) {
	bytes, err := os.ReadFile("credentials.json")
	if err != nil {
		return nil, err
	}

	var out Credentials
	if err := json.Unmarshal(bytes, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

func (c *Credentials) Save() error {
	bytes, err := json.Marshal(c)
	if err != nil {
		return err
	}

	if err := os.WriteFile("credentials.json", bytes, 0644); err != nil {
		return err
	}

	return nil
}
