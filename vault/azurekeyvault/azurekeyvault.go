package azurekeyvault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/actions/actions-runner-controller/proxyconfig"
)

type AzureKeyVault struct {
	client *azsecrets.Client
}

func New(cfg Config) (*AzureKeyVault, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate config: %v", err)
	}

	client, err := cfg.Client()
	if err != nil {
		return nil, fmt.Errorf("failed to create azsecrets client from config: %v", err)
	}

	return &AzureKeyVault{client: client}, nil
}

func FromEnv(prefix string) (*AzureKeyVault, error) {
	cfg := Config{
		TenantID:     os.Getenv(prefix + "TENANT_ID"),
		ClientID:     os.Getenv(prefix + "CLIENT_ID"),
		URL:          os.Getenv(prefix + "URL"),
		CertPath:     os.Getenv(prefix + "CERT_PATH"),
		CertPassword: os.Getenv(prefix + "CERT_PASSWORD"),
		JWT:          os.Getenv(prefix + "JWT"),
	}

	proxyConfig, err := proxyconfig.ReadFromEnv(prefix + "CONTROLLER_MANAGER_AZURE_VAULT_")
	if err != nil {
		return nil, fmt.Errorf("failed to read proxy config: %v", err)
	}
	cfg.Proxy = proxyConfig

	return New(cfg)
}

func FromPath(configFilePath string) (*AzureKeyVault, error) {
	var cfg Config
	f, err := os.Open(configFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file %q: %v", configFilePath, err)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to read configuration from file %q: %v", configFilePath, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate config: %v", err)
	}

	return New(cfg)
}

func (v *AzureKeyVault) GetSecret(ctx context.Context, name string) (string, error) {
	secret, err := v.client.GetSecret(ctx, name, "", nil)
	if err != nil {
		return "", fmt.Errorf("failed to get secret: %w", err)
	}
	if secret.Value == nil {
		return "", fmt.Errorf("secret value is nil")
	}

	return *secret.Value, nil
}
