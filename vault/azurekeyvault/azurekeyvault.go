package azurekeyvault

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
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

func (v *AzureKeyVault) GetSecret(ctx context.Context, name, version string) (string, error) {
	secret, err := v.client.GetSecret(ctx, name, version, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get secret: %w", err)
	}
	if secret.Value == nil {
		return "", fmt.Errorf("secret value is nil")
	}

	return *secret.Value, nil
}
