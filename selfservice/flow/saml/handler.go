package saml

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/crewjam/saml/samlsp"
	"github.com/julienschmidt/httprouter"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/selfservice/errorx"

	samlidp "github.com/crewjam/saml"
	samlstrategy "github.com/ory/kratos/selfservice/strategy/saml"

	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
	"github.com/ory/x/decoderx"
	"github.com/ory/x/jsonx"
)

const (
	RouteSamlMetadata  = "/self-service/methods/saml/metadata"
	RouteSamlLoginInit = "/self-service/methods/saml/auth" // Redirect to the IDP
	RouteSamlAcs       = "/self-service/methods/saml/acs"
)

var ErrNoSession = errors.New("saml: session not present")
var samlMiddleware *samlsp.Middleware

type (
	handlerDependencies interface {
		x.WriterProvider
		x.CSRFProvider
		session.ManagementProvider
		session.PersistenceProvider
		errorx.ManagementProvider
		config.Provider
	}
	HandlerProvider interface {
		LogoutHandler() *Handler
	}
	Handler struct {
		d  handlerDependencies
		dx *decoderx.HTTP
	}
)

type CookieSessionProvider struct {
	Name     string
	Domain   string
	HTTPOnly bool
	Secure   bool
	SameSite http.SameSite
	MaxAge   time.Duration
	Codec    samlsp.SessionCodec
}

func NewHandler(d handlerDependencies) *Handler {
	return &Handler{
		d:  d,
		dx: decoderx.NewHTTP(),
	}
}

// swagger:model selfServiceSamlUrl
type selfServiceSamlUrl struct {
	// SamlMetadataURL is a get endpoint to get the metadata
	//
	// format: uri
	// required: true
	SamlMetadataURL string `json:"saml_metadata_url"`

	// SamlAcsURL is a post endpoint to handle SAML Response
	//
	// format: uri
	// required: true
	SamlAcsURL string `json:"saml_acs_url"`
}

func (h *Handler) RegisterPublicRoutes(router *x.RouterPublic) {

	h.d.CSRFHandler().IgnorePath(RouteSamlLoginInit)
	h.d.CSRFHandler().IgnorePath(RouteSamlAcs)

	router.GET(RouteSamlMetadata, h.serveMetadata)
	router.GET(RouteSamlLoginInit, h.loginWithIdp)
}

// Handle /selfservice/methods/saml/metadata
func (h *Handler) serveMetadata(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	config := h.d.Config(r.Context())
	if samlMiddleware == nil {
		if err := h.instantiateMiddleware(*config); err != nil {
			h.d.SelfServiceErrorManager().Forward(r.Context(), w, r, err)
		}
	}

	samlMiddleware.ServeMetadata(w, r)
}

// swagger:route GET /self-service/methods/saml/auth v0alpha2 initializeSelfServiceSamlFlowForBrowsers
//
// Initialize Authentication Flow for SAML (Either the login or the register)
//
// If you already have a session, it will redirect you to the main page.
//
//     Schemes: http, https
//
//     Responses:
//       200: selfServiceRegistrationFlow
//       400: jsonError
//       500: jsonError
func (h *Handler) loginWithIdp(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	// Middleware is a singleton so we have to verify that it exist
	if samlMiddleware == nil {
		config := h.d.Config(r.Context())
		if err := h.instantiateMiddleware(*config); err != nil {
			h.d.SelfServiceErrorManager().Forward(r.Context(), w, r, err)
		}
	}

	conf := h.d.Config(r.Context())

	// Checks if the user already have an active session
	if e := new(session.ErrNoActiveSessionFound); errors.As(e, &e) {
		// No session exists yet, we start the auth flow and create the session
		samlMiddleware.HandleStartAuthFlow(w, r)
	} else {
		// A session already exist, we redirect to the main page
		http.Redirect(w, r, conf.SelfServiceBrowserDefaultReturnTo().Path, http.StatusTemporaryRedirect)
	}
}

func DestroyMiddlewareIfExists() {
	if samlMiddleware != nil {
		samlMiddleware = nil
	}
}

func (h *Handler) instantiateMiddleware(config config.Config) error {
	// Create a SAMLProvider object from the config file
	var c samlstrategy.ConfigurationCollection
	conf := config.SelfServiceStrategy("saml").Config
	if err := jsonx.
		NewStrictDecoder(bytes.NewBuffer(conf)).
		Decode(&c); err != nil {
		return errors.Wrapf(err, "Unable to decode config %v", string(conf))
	}

	// Key pair to encrypt and sign SAML requests
	keyPair, err := tls.LoadX509KeyPair(strings.Replace(c.SAMLProviders[len(c.SAMLProviders)-1].PublicCertPath, "file://", "", 1), strings.Replace(c.SAMLProviders[len(c.SAMLProviders)-1].PrivateKeyPath, "file://", "", 1))
	if err != nil {
		return err
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return err
	}

	var idpMetadata *samlidp.EntityDescriptor

	// We check if the metadata file is provided
	if c.SAMLProviders[len(c.SAMLProviders)-1].IDPInformation["idp_metadata_url"] != "" {

		metadataURL := c.SAMLProviders[len(c.SAMLProviders)-1].IDPInformation["idp_metadata_url"]
		// The metadata file is provided
		if strings.HasPrefix(metadataURL, "file://") {
			metadataURL = strings.Replace(metadataURL, "file://", "", 1)

			metadataPlainText, err := ioutil.ReadFile(metadataURL)
			if err != nil {
				return err
			}

			idpMetadata, err = samlsp.ParseMetadata([]byte(metadataPlainText))
			if err != nil {
				return err
			}

		} else {
			idpMetadataURL, err := url.Parse(metadataURL)
			if err != nil {
				return err
			}
			// Parse the content of metadata file into a Golang struct
			idpMetadata, err = samlsp.FetchMetadata(context.Background(), http.DefaultClient, *idpMetadataURL)
			if err != nil {
				return err
			}
		}

	} else {

		// The metadata file is not provided
		// So were are creating a minimalist IDP metadata based on what is provided by the user on the config file
		entityIDURL, err := url.Parse(c.SAMLProviders[len(c.SAMLProviders)-1].IDPInformation["idp_entity_id"])
		if err != nil {
			return err
		}

		// The IDP SSO URL
		IDPSSOURL, err := url.Parse(c.SAMLProviders[len(c.SAMLProviders)-1].IDPInformation["idp_sso_url"])
		if err != nil {
			return err
		}

		// The IDP Logout URL
		IDPlogoutURL, err := url.Parse(c.SAMLProviders[len(c.SAMLProviders)-1].IDPInformation["idp_logout_url"])
		if err != nil {
			return err
		}

		// The certificate of the IDP
		certificate, err := ioutil.ReadFile(strings.Replace(c.SAMLProviders[len(c.SAMLProviders)-1].IDPInformation["idp_certificate_path"], "file://", "", 1))
		if err != nil {
			return err
		}

		// We parse it into a x509.Certificate object
		IDPCertificate, err := MustParseCertificate(certificate)
		if err != nil {
			return err
		}

		// Because the metadata file is not provided, we need to simulate an IDP to create artificial metadata from the data entered in the conf file
		tempIDP := samlidp.IdentityProvider{
			Key:         nil,
			Certificate: IDPCertificate,
			Logger:      nil,
			MetadataURL: *entityIDURL,
			SSOURL:      *IDPSSOURL,
			LogoutURL:   *IDPlogoutURL,
		}

		// Now we assign our reconstructed metadata to our SP
		idpMetadata = tempIDP.Metadata()
	}

	// The main URL
	rootURL, err := url.Parse(config.SelfServiceBrowserDefaultReturnTo().String())
	if err != nil {
		return err
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
		return err
	}

	var publicUrlString = config.SelfPublicURL().String()

	// Sometimes there is an issue with double slash into the url so we prevent it
	// Crewjam library use default route for ACS and metadat but we want to overwrite them
	RouteSamlAcsWithSlash := RouteSamlAcs
	if publicUrlString[len(publicUrlString)-1] != '/' {

		u, err := url.Parse(publicUrlString + RouteSamlAcsWithSlash)
		if err != nil {
			return err
		}
		samlMiddleWare.ServiceProvider.AcsURL = *u

	} else if publicUrlString[len(publicUrlString)-1] == '/' {

		publicUrlString = publicUrlString[:len(publicUrlString)-1]
		u, err := url.Parse(publicUrlString + RouteSamlAcsWithSlash)
		if err != nil {
			return err
		}
		samlMiddleWare.ServiceProvider.AcsURL = *u
	}

	// Crewjam library use default route for ACS and metadat but we want to overwrite them
	metadata, err := url.Parse(publicUrlString + RouteSamlMetadata)
	samlMiddleWare.ServiceProvider.MetadataURL = *metadata

	// The EntityID in the AuthnRequest is the Metadata URL
	samlMiddleWare.ServiceProvider.EntityID = samlMiddleWare.ServiceProvider.MetadataURL.String()

	// The issuer format is unspecified
	samlMiddleWare.ServiceProvider.AuthnNameIDFormat = samlidp.UnspecifiedNameIDFormat

	samlMiddleware = samlMiddleWare

	return nil
}

func GetMiddleware() (*samlsp.Middleware, error) {
	if samlMiddleware == nil {
		return nil, errors.Errorf("The MiddleWare for SAML is null (Probably due to a backward step)")
	}
	return samlMiddleware, nil
}

func MustParseCertificate(pemStr []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(pemStr)
	if b == nil {
		return nil, errors.Errorf("Cannot find the next PEM formatted block")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
