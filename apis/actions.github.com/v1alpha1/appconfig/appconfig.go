package appconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"
)

type AppConfig struct {
	AppID             int64  `json:"github_app_id"`
	AppInstallationID int64  `json:"github_app_installation_id"`
	AppPrivateKey     string `json:"github_app_private_key"`

	Token string `json:"github_token"`
}

func (c *AppConfig) Validate() error {
	hasToken := len(c.Token) > 0
	hasGitHubAppAuth := c.hasGitHubAppAuth()
	if hasToken && hasGitHubAppAuth {
		return fmt.Errorf("both PAT and GitHub App credentials provided. should only provide one")
	}
	if !hasToken && !hasGitHubAppAuth {
		return fmt.Errorf("no credentials provided: either a PAT or GitHub App credentials should be provided")
	}

	return nil
}

func (c *AppConfig) hasGitHubAppAuth() bool {
	return c.AppID > 0 && c.AppInstallationID > 0 && len(c.AppPrivateKey) > 0
}

func FromSecret(secret *corev1.Secret) (*AppConfig, error) {
	token := string(secret.Data["github_token"])
	hasToken := len(token) > 0

	appID := string(secret.Data["github_app_id"])
	appInstallationID := string(secret.Data["github_app_installation_id"])
	appPrivateKey := string(secret.Data["github_app_private_key"])
	hasGitHubAppAuth := len(appID) > 0 && len(appInstallationID) > 0 && len(appPrivateKey) > 0

	if hasToken && hasGitHubAppAuth {
		return nil, fmt.Errorf("must provide secret with only PAT or GitHub App Auth to avoid ambiguity in client behavior")
	}

	if hasToken {
		return &AppConfig{
			Token: token,
		}, nil
	}

	parsedAppID, err := strconv.ParseInt(appID, 10, 64)
	if err != nil {
		return nil, err
	}

	parsedAppInstallationID, err := strconv.ParseInt(appInstallationID, 10, 64)
	if err != nil {
		return nil, err
	}

	return &AppConfig{
		AppID:             parsedAppID,
		AppInstallationID: parsedAppInstallationID,
		AppPrivateKey:     appPrivateKey,
	}, err
}

func FromString(v string) (*AppConfig, error) {
	var appConfig AppConfig
	if err := json.NewDecoder(bytes.NewBufferString(v)).Decode(&appConfig); err != nil {
		return nil, err
	}

	hasToken := len(appConfig.Token) > 0

	if !hasToken && !appConfig.hasGitHubAppAuth() {
		return nil, fmt.Errorf("neither PAT nor GitHub App Auth credentials provided in secret")
	}

	if hasToken {
		return &AppConfig{Token: appConfig.Token}, nil
	}

	appConfig.Token = ""
	return &appConfig, nil
}
