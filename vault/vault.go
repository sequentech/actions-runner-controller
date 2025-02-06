package vault

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/actions/actions-runner-controller/vault/azurekeyvault"
)

type Vault interface {
	GetSecret(ctx context.Context, name string) (string, error)
}

type vaultError string

func (e vaultError) Error() string {
	return string(e)
}

func (e vaultError) String() string {
	return string(e)
}

const (
	ErrTypeUnknown = vaultError("vault type unknown")
	ErrNoType      = vaultError("vault type not set")
)

const (
	VaultTypeAzureKeyVault = "azure_key_vault"
)

func InitAll(prefix string) (map[string]Vault, error) {
	envs := os.Environ()

	result := make(map[string]Vault)
	for _, env := range envs {
		if strings.HasPrefix(env, prefix+"AZURE_KEY_VAULT_") {
			if path, ok := os.LookupEnv(prefix + "AZURE_KEY_VAULT_CONFIG_PATH"); ok {
				akv, err := azurekeyvault.FromPath(path)
				if err != nil {
					return nil, fmt.Errorf("failed to instantiate azure key vault from path: %v", err)
				}
				result[VaultTypeAzureKeyVault] = akv
			} else {
				akv, err := azurekeyvault.FromEnv(prefix + "AZURE_KEY_VAULT_")
				if err != nil {
					return nil, fmt.Errorf("failed to instantiate azure key vault from env: %v", err)
				}
				result[VaultTypeAzureKeyVault] = akv
			}
		}
	}

	return result, nil
}
