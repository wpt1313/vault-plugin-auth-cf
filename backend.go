// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package cf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	cfclient "github.com/cloudfoundry/go-cfclient/v3/client"
	cfconfig "github.com/cloudfoundry/go-cfclient/v3/config"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/hashicorp/vault-plugin-auth-cf/models"
)

const (
	// EnvVarInstanceCertificate env vars are used frequently to pull the client
	// certificate and private key from CF containers; thus are placed here for ease
	// of discovery and use from outside packages.
	EnvVarInstanceCertificate = "CF_INSTANCE_CERT"
	EnvVarInstanceKey         = "CF_INSTANCE_KEY"

	// operationPrefixCloudFoundry is used as a prefix for OpenAPI operation id's.
	operationPrefixCloudFoundry = "cloud-foundry"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{}
	b.Backend = &framework.Backend{
		AuthRenew: b.pathLoginRenew,
		Help:      backendHelp,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{"config"},
			Unauthenticated: []string{"login"},
		},
		Paths: []*framework.Path{
			b.pathConfig(),
			b.pathListRoles(),
			b.pathRoles(),
			b.pathLogin(),
		},
		BackendType: logical.TypeCredential,
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend
	mu              sync.RWMutex
	cfClient        *cfclient.Client
	cfClientMu      sync.RWMutex
	lastConfigHash  *[32]byte
	cfClientTainted bool
}

const backendHelp = `
The CF auth backend supports logging in using CF's identity service.
Once a CA certificate is configured, and Vault is configured to consume
CF's API, CF's instance identity credentials can be used to authenticate.'
`

var errCFClientNotInitialized = fmt.Errorf("client is not initialized")

func (b *backend) getCFClient(_ context.Context) (*cfclient.Client, error) {
	b.cfClientMu.RLock()
	defer b.cfClientMu.RUnlock()
	if b.cfClient == nil {
		return nil, errCFClientNotInitialized
	}

	return b.cfClient, nil
}

func (b *backend) updateCFClient(ctx context.Context, config *models.Configuration) (bool, error) {
	b.cfClientMu.Lock()
	defer b.cfClientMu.Unlock()

	configHash, err := config.Hash()
	if err != nil {
		return false, err
	}

	if !b.cfClientTainted && b.lastConfigHash != nil && b.cfClient != nil {
		if *b.lastConfigHash == configHash {
			return false, nil
		}
	}

	b.cfClientTainted = false
	if b.cfClient != nil {
		if httpClient := b.cfClient.HTTPClient(); httpClient != nil {
			httpClient.CloseIdleConnections()
		}
	}

	cfClient, err := b.newCFClient(ctx, config)
	if err != nil {
		return false, err
	}

	b.cfClient = cfClient
	b.lastConfigHash = &configHash

	return true, nil
}

func (b *backend) getCFClientOrRefresh(ctx context.Context, config *models.Configuration) (*cfclient.Client, error) {
	if config == nil {
		return nil, fmt.Errorf("configuration is nil")
	}

	client, err := b.getCFClient(ctx)
	if err != nil {
		if errors.Is(err, errCFClientNotInitialized) {
			if _, err := b.updateCFClient(ctx, config); err != nil {
				return nil, err
			}
			return b.getCFClient(ctx)
		}
		return nil, err
	}

	return client, nil
}

func (b *backend) newCFClient(_ context.Context, config *models.Configuration) (*cfclient.Client, error) {
	if config == nil {
		return nil, fmt.Errorf("configuration is nil")
	}

	httpClient := cleanhttp.DefaultClient()

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	for idx, certificate := range config.CFAPICertificates {
		if ok := rootCAs.AppendCertsFromPEM([]byte(certificate)); !ok {
			return nil, fmt.Errorf(
				"failed to append CF API cert to cert pool, index=%d, err=%w", idx, err,
			)
		}
	}
	tlsConfig := &tls.Config{
		RootCAs: rootCAs,
	}

	if config.CFMutualTLSCertificate != "" && config.CFMutualTLSKey != "" {
		cert, err := tls.X509KeyPair(
			[]byte(config.CFMutualTLSCertificate),
			[]byte(config.CFMutualTLSKey),
		)
		if err != nil {
			return nil, fmt.Errorf("could not parse X509 key pair for mutual TLS")
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	httpClient.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
		// IdleConnTimeout bounds how long idle keep-alive connections linger in
		// the per-request transport before being closed. Without this, abandoned
		// transports accumulate open connections until the GC runs.
		// 90s matches Go's DefaultTransport.
		IdleConnTimeout: 90 * time.Second,
	}

	options := []cfconfig.Option{
		cfconfig.HttpClient(httpClient),
	}
	if config.CFTimeout > 0 {
		options = append(options, cfconfig.RequestTimeout(config.CFTimeout))
	}
	// Client credentials take priority over username/password, matching the
	// previous (v2) client's auth precedence, so operators relying on the
	// client_id/client_secret grant continue to get it even if cf_username
	// and cf_password are also present in storage (e.g. left over from a
	// prior configuration).
	switch {
	case config.CFClientID != "" && config.CFClientSecret != "":
		options = append(options, cfconfig.ClientCredentials(config.CFClientID, config.CFClientSecret))
	case config.CFUsername != "" && config.CFPassword != "":
		options = append(options, cfconfig.UserPassword(config.CFUsername, config.CFPassword))
	}

	// cfconfig.New() reaches out to the CF API to discover its UAA/login
	// endpoints (and, for the password grant, to exchange credentials for a
	// token). That means the CF API must be reachable at the time of the
	// call. client.New() itself, however, performs no I/O.
	cfg, err := cfconfig.New(config.CFAPIAddr, options...)
	if err != nil {
		return nil, err
	}

	if config.CFTimeout <= 0 {
		// A non-positive CFTimeout means "no timeout". cfconfig.RequestTimeout
		// rejects values <= 0 and falls back to its own default, so restore
		// the "no timeout" behavior on the clients it built for us.
		cfg.HTTPClient().Timeout = 0
		cfg.HTTPAuthClient().Timeout = 0
	}

	return cfclient.New(cfg)
}
