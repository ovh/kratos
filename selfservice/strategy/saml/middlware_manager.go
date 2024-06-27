package saml

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	samlidp "github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/ory/herodot"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/x/fetcher"
	dsig "github.com/russellhaering/goxmldsig"
	"io"
	"net/url"
	"strings"
	"sync"
)

type (
	middlewareManagerDependencies interface {
		config.Provider
		ContinuitySessionRequestTrackerProvider
	}
	MiddlewareManagerProvider interface {
		SAMLMiddlewareManager() *MiddlewareManager
	}
	MiddlewareManager struct {
		rwl         sync.RWMutex
		d           middlewareManagerDependencies
		middlewares map[string]*samlsp.Middleware
	}
)

func NewMiddlewareManager(d middlewareManagerDependencies) *MiddlewareManager {
	return &MiddlewareManager{
		d:           d,
		middlewares: make(map[string]*samlsp.Middleware),
	}
}

// GetMiddleware Return the singleton MiddleWare
func (m *MiddlewareManager) GetMiddleware(ctx context.Context, pid string) (*samlsp.Middleware, error) {
	m.rwl.Lock()
	defer m.rwl.Unlock()

	middleware, exists := m.middlewares[pid]
	if !exists {
		var err error
		middleware, err = m.instantiateMiddleware(ctx, pid)
		if err != nil {
			return nil, err
		}
		m.middlewares[pid] = middleware
	}
	return middleware, nil
}

// Instantiate the middleware SAML from the information in the configuration file
func (m *MiddlewareManager) instantiateMiddleware(ctx context.Context, pid string) (*samlsp.Middleware, error) {
	providerConfig, err := CreateSAMLProviderConfig(*m.d.Config(), ctx, pid)
	if err != nil {
		return nil, err
	}

	// Key pair to encrypt and sign SAML requests
	keyPair, err := tls.LoadX509KeyPair(strings.Replace(providerConfig.PublicCertPath, "file://", "", 1), strings.Replace(providerConfig.PrivateKeyPath, "file://", "", 1))
	if err != nil {
		return nil, herodot.ErrInternalServerError.WithReason("An error occurred while retrieving the key pair used by SAML")
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, herodot.ErrInternalServerError.WithReason("An error occurred while using the certificate associated with SAML")
	}

	var idpMetadata *samlidp.EntityDescriptor

	// We check if the metadata file is provided
	if providerConfig.IDPInformation["idp_metadata_url"] != "" {
		// The metadata file is provided
		metadataURL := providerConfig.IDPInformation["idp_metadata_url"]

		metadataBuffer, err := fetcher.NewFetcher().Fetch(metadataURL)
		if err != nil {
			return nil, herodot.ErrNotFound.WithTrace(err)
		}

		metadata, err := io.ReadAll(metadataBuffer)
		if err != nil {
			return nil, herodot.ErrInternalServerError.WithTrace(err)
		}

		idpMetadata, err = samlsp.ParseMetadata(metadata)
		if err != nil {
			return nil, ErrInvalidSAMLMetadataError.WithTrace(err)
		}

	} else {
		// The metadata file is not provided
		// So were are creating a minimalist IDP metadata based on what is provided by the user on the config file
		entityIDURL, err := url.Parse(providerConfig.IDPInformation["idp_entity_id"])
		if err != nil {
			return nil, herodot.ErrNotFound.WithTrace(err)
		}

		// The IDP SSO URL
		IDPSSOURL, err := url.Parse(providerConfig.IDPInformation["idp_sso_url"])
		if err != nil {
			return nil, herodot.ErrNotFound.WithTrace(err)
		}

		// The IDP Logout URL
		IDPlogoutURL, err := url.Parse(providerConfig.IDPInformation["idp_logout_url"])
		if err != nil {
			return nil, herodot.ErrNotFound.WithTrace(err)
		}

		// The certificate of the IDP
		certificateBuffer, err := fetcher.NewFetcher().Fetch(providerConfig.IDPInformation["idp_certificate_path"])
		if err != nil {
			return nil, herodot.ErrNotFound.WithTrace(err)
		}

		certificate, err := io.ReadAll(certificateBuffer)
		if err != nil {
			return nil, herodot.ErrInternalServerError.WithTrace(err)
		}

		// We parse it into a x509.Certificate object
		IDPCertificate, err := MustParseCertificate(certificate)
		if err != nil {
			return nil, ErrInvalidCertificateError.WithTrace(err)
		}

		// Because the metadata file is not provided, we need to simulate an IDP to create artificial metadata from the data entered in the conf file
		tempIDP := samlidp.IdentityProvider{
			Certificate: IDPCertificate,
			MetadataURL: *entityIDURL,
			SSOURL:      *IDPSSOURL,
			LogoutURL:   *IDPlogoutURL,
		}

		// Now we assign our reconstructed metadata to our SP
		idpMetadata = tempIDP.Metadata()
	}

	// The main URL
	rootURL, err := url.Parse(m.d.Config().SelfServiceBrowserDefaultReturnTo(ctx).String())
	if err != nil {
		return nil, herodot.ErrNotFound.WithTrace(err)
	}

	// Here we create a MiddleWare to transform Kratos into a Service Provider
	samlMiddleWare, err := samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
		SignRequest: true,
	})
	if err != nil {
		return nil, herodot.ErrInternalServerError.WithTrace(err)
	}

	// It's better to use SHA256 than SHA1
	samlMiddleWare.ServiceProvider.SignatureMethod = dsig.RSASHA256SignatureMethod

	var publicUrlString = m.d.Config().SelfPublicURL(ctx).String()

	// Sometimes there is an issue with double slash into the url, so we prevent it
	// Crewjam library use default route for ACS and metadata, but we want to overwrite them
	RouteSamlAcsWithSlash := strings.Replace(RouteAcs, ":provider", providerConfig.ID, 1)
	if publicUrlString[len(publicUrlString)-1] != '/' {

		u, err := url.Parse(publicUrlString + RouteSamlAcsWithSlash)
		if err != nil {
			return nil, herodot.ErrNotFound.WithTrace(err)
		}
		samlMiddleWare.ServiceProvider.AcsURL = *u

	} else if publicUrlString[len(publicUrlString)-1] == '/' {

		publicUrlString = publicUrlString[:len(publicUrlString)-1]
		u, err := url.Parse(publicUrlString + RouteSamlAcsWithSlash)
		if err != nil {
			return nil, herodot.ErrNotFound.WithTrace(err)
		}
		samlMiddleWare.ServiceProvider.AcsURL = *u
	}

	// Crewjam library use default route for ACS and metadata, but we want to overwrite them
	metadata, err := url.Parse(publicUrlString + strings.Replace(RouteMetadata, ":provider", providerConfig.ID, 1))
	if err != nil {
		return nil, herodot.ErrNotFound.WithTrace(err)
	}
	samlMiddleWare.ServiceProvider.MetadataURL = *metadata

	// The EntityID in the AuthnRequest is the Metadata URL
	samlMiddleWare.ServiceProvider.EntityID = samlMiddleWare.ServiceProvider.MetadataURL.String()

	// The issuer format is unspecified
	samlMiddleWare.ServiceProvider.AuthnNameIDFormat = samlidp.UnspecifiedNameIDFormat

	samlMiddleWare.RequestTracker = m.d.ContinuitySessionRequestTracker()

	return samlMiddleWare, nil
}
