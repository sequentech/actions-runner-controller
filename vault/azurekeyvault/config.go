package azurekeyvault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/actions/actions-runner-controller/proxyconfig"
	"github.com/hashicorp/go-retryablehttp"
)

type Config struct {
	TenantID     string                   `json:"tenant_id"`
	ClientID     string                   `json:"client_id"`
	URL          string                   `json:"url"`
	CertPath     string                   `json:"cert_path"`
	CertPassword string                   `json:"cert_password"`
	JWT          string                   `json:"jwt"`
	Proxy        *proxyconfig.ProxyConfig `json:"proxy,omitempty"`
}

func (c *Config) Validate() error {
	if c.TenantID == "" {
		return errors.New("tenant_id is not set")
	}
	if c.ClientID == "" {
		return errors.New("client_id is not set")
	}
	if _, err := url.Parse(c.URL); err != nil {
		return fmt.Errorf("failed to parse url: %v", err)
	}

	if c.JWT != "" && c.CertPath != "" {
		return errors.New("both jwt and cert_path provided")
	}

	if c.JWT == "" {
		fi, err := os.Stat(c.CertPath)
		if err != nil {
			return fmt.Errorf("failed to stat cert_path: %v", err)
		}
		if fi.IsDir() {
			return errors.New("cert_path must not be a directory")
		}
	}

	if err := c.Proxy.Validate(); err != nil {
		return fmt.Errorf("proxy validation failed: %v", err)
	}

	return nil
}

func (c *Config) getJWTAsswrtion(ctx context.Context) (string, error) {
	return c.JWT, nil
}

func (c *Config) Client() (*azsecrets.Client, error) {
	if c.JWT != "" {
		return c.jwtClient()
	}
	return c.certClient()
}

func (c *Config) jwtClient() (*azsecrets.Client, error) {
	httpClient, err := c.httpClient()
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate http client: %v", err)
	}
	cred, err := azidentity.NewClientAssertionCredential(
		c.TenantID,
		c.ClientID,
		c.getJWTAsswrtion,
		&azidentity.ClientAssertionCredentialOptions{
			ClientOptions: azcore.ClientOptions{
				Transport: httpClient,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create client assertion credential: %w", err)
	}

	client, err := azsecrets.NewClient(c.URL, cred, &azsecrets.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Transport: httpClient,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize keyvault client: %w", err)
	}

	return client, nil
}

func (c *Config) certClient() (*azsecrets.Client, error) {
	data, err := os.ReadFile(c.CertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert file from path %q: %v", c.CertPath, err)
	}

	certs, key, err := azidentity.ParseCertificates(data, []byte(c.CertPassword))

	httpClient, err := c.httpClient()
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate http client: %v", err)
	}

	cred, err := azidentity.NewClientCertificateCredential(
		c.TenantID,
		c.ClientID,
		certs,
		key,
		&azidentity.ClientCertificateCredentialOptions{
			ClientOptions: policy.ClientOptions{
				Transport: httpClient,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate credential: %v", err)
	}

	client, err := azsecrets.NewClient(c.URL, cred, &azsecrets.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Transport: httpClient,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate client for azsecrets: %v", err)
	}

	return client, nil
}

func (c *Config) httpClient() (*http.Client, error) {
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 4
	retryClient.RetryWaitMax = 30 * time.Second
	retryClient.HTTPClient.Timeout = 5 * time.Minute

	transport, ok := retryClient.HTTPClient.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("failed to get http transport")
	}
	if c.Proxy != nil {
		pc, err := c.ProxyConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to create proxy config: %v", err)
		}
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			return pc.ProxyFunc()(req.URL)
		}
	}

	return retryClient.StandardClient(), nil
}
