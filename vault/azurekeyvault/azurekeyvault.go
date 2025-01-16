package azurekeyvault

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/net/http/httpproxy"
)

type AzureKeyVault struct {
	client *azsecrets.Client
}

type Config struct {
	ClientID string       `json:"client_id"`
	TenantID string       `json:"tenant_id"`
	JWT      string       `json:"jwt"`
	URL      string       `json:"url"`
	Proxy    *ProxyConfig `json:"proxy,omitempty"`
}

func (c *Config) validate() error {
	panic("not implemented")
}

func (c *Config) ProxyConfig() (*httpproxy.Config, error) {
	if c.Proxy == nil {
		return nil, nil
	}

	config := &httpproxy.Config{
		NoProxy: strings.Join(c.Proxy.NoProxy, ","),
	}
	if c.Proxy.HTTP != nil {
		u, err := c.Proxy.HTTP.proxyURL()
		if err != nil {
			return nil, fmt.Errorf("failed to create proxy http url: %w", err)
		}
		config.HTTPProxy = u.String()
	}

	if c.Proxy.HTTPS != nil {
		u, err := c.Proxy.HTTPS.proxyURL()
		if err != nil {
			return nil, fmt.Errorf("failed to create proxy https url: %w", err)
		}
		config.HTTPSProxy = u.String()
	}

	return config, nil
}

type ProxyConfig struct {
	HTTP    *ProxyServerConfig `json:"http,omitempty"`
	HTTPS   *ProxyServerConfig `json:"https,omitempty"`
	NoProxy []string           `json:"noProxy,omitempty"`
}

type ProxyServerConfig struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c *ProxyServerConfig) proxyURL() (*url.URL, error) {
	u, err := url.Parse(c.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy url %q: %w", c.URL, err)
	}

	u.User = url.UserPassword(
		c.Username,
		c.Password,
	)

	return u, nil
}

func (c *Config) getAssertion(ctx context.Context) (string, error) {
	return c.JWT, nil
}

func New(cfg Config) (*AzureKeyVault, error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("failed to validate config: %v", err)
	}

	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 4
	retryClient.RetryWaitMax = 30 * time.Second
	retryClient.HTTPClient.Timeout = 5 * time.Minute

	transport, ok := retryClient.HTTPClient.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("failed to get http transport")
	}
	if cfg.Proxy != nil {
		pc, err := cfg.ProxyConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to create proxy config: %v", err)
		}
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			return pc.ProxyFunc()(req.URL)
		}
	}
	httpClient := retryClient.StandardClient()

	cred, err := azidentity.NewClientAssertionCredential(
		cfg.TenantID,
		cfg.ClientID,
		cfg.getAssertion,
		&azidentity.ClientAssertionCredentialOptions{
			ClientOptions: azcore.ClientOptions{
				Transport: httpClient,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create client assertion credential: %w", err)
	}

	client, err := azsecrets.NewClient(cfg.URL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize keyvault client: %w", err)
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
