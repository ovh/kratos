package saml

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"github.com/ory/kratos/continuity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/strategy"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml/samlsp"
	"github.com/julienschmidt/httprouter"

	"github.com/ory/herodot"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/selfservice/errorx"

	samlidp "github.com/crewjam/saml"

	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
	"github.com/ory/x/decoderx"
	"github.com/ory/x/fetcher"
	"github.com/ory/x/jsonx"
)

var ErrNoSession = errors.New("saml: session not present")

var samlMiddlewares = make(map[string]*samlsp.Middleware)

type ory_kratos_continuity struct{}

type (
	handlerDependencies interface {
		x.WriterProvider
		x.CSRFProvider
		session.ManagementProvider
		session.PersistenceProvider
		errorx.ManagementProvider
		config.Provider
		login.FlowPersistenceProvider
		continuity.ManagementProvider
	}
	HandlerProvider interface {
		LogoutHandler() *Handler
	}
	Handler struct {
		d  handlerDependencies
		dx *decoderx.HTTP
	}
)

type SessionData struct {
	SessionID string
}

func NewHandler(d handlerDependencies) *Handler {
	return &Handler{
		d:  d,
		dx: decoderx.NewHTTP(),
	}
}

func (h *Handler) RegisterPublicRoutes(router *x.RouterPublic) {
	h.d.CSRFHandler().IgnoreGlob(RouteBaseAcs + "/*")

	router.GET(RouteMetadata, h.serveMetadata)
	router.GET(RouteAuth, h.loginWithIdp)
}

func (s *Strategy) setAdminRoutes(r *x.RouterAdmin) {
	wrappedListProviders := strategy.IsDisabled(s.d, s.ID().String(), s.listProviders)
	r.GET(RouteProviderCollection, wrappedListProviders)
}

// Handle /selfservice/methods/saml/metadata
func (h *Handler) serveMetadata(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	config := h.d.Config()
	pid := ps.ByName("provider")

	if samlMiddlewares[pid] == nil {
		if err := h.instantiateMiddleware(r.Context(), *config, pid); err != nil {
			h.d.SelfServiceErrorManager().Forward(r.Context(), w, r, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	buf, _ := xml.MarshalIndent(samlMiddlewares[pid].ServiceProvider.Metadata(), "", "  ")
	w.Header().Set("Content-Type", "text/xml")
	w.Write(buf)
}

// swagger:route GET /self-service/methods/saml/auth v0alpha2 initializeSelfServiceSamlFlowForBrowsers
//
// Initialize Authentication Flow for SAML (Either the login or the register)
//
// If you already have a session, it will redirect you to the main page.
//
//	Schemes: http, https
//
//	Responses:
//	  200: selfServiceRegistrationFlow
//	  400: jsonError
//	  500: jsonError
func (h *Handler) loginWithIdp(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if flowID := r.URL.Query().Get("flow"); flowID != "" {
		f, err := h.d.LoginFlowPersister().GetLoginFlow(r.Context(), x.ParseUUID(flowID))
		if err != nil {
			h.d.SelfServiceErrorManager().Forward(r.Context(), w, r, err)
			return
		}
		if f.GetType() != flow.TypeAPI {
			h.d.SelfServiceErrorManager().Forward(r.Context(), w, r,
				herodot.ErrInternalServerError.WithReason("Expected flow of type API"))
			return
		}
		state := generateState(f.ID.String())
		if err := h.d.ContinuityManager().Pause(r.Context(), w, r, sessionName,
			continuity.WithPayload(&authCodeContainer{
				State:  state,
				FlowID: f.ID.String(),
			}),
			continuity.WithLifespan(time.Minute*30)); err != nil {
			h.d.SelfServiceErrorManager().Forward(r.Context(), w, r, err)
			return
		}
	}

	// Middleware is a singleton so we have to verify that it exists
	config := h.d.Config()
	pid := ps.ByName("provider")

	if samlMiddlewares[pid] == nil {
		if err := h.instantiateMiddleware(r.Context(), *config, pid); err != nil {
			h.d.SelfServiceErrorManager().Forward(r.Context(), w, r, err)
			return
		}
	}

	// Checks if the user already have an active session
	if e := new(session.ErrNoActiveSessionFound); errors.As(e, &e) {
		// No session exists yet, we start the auth flow and create the session
		samlMiddlewares[pid].HandleStartAuthFlow(w, r)
	} else {
		// A session already exist, we redirect to the main page
		http.Redirect(w, r, config.SelfServiceBrowserDefaultReturnTo(r.Context()).Path, http.StatusTemporaryRedirect)
	}
}

func DestroyMiddlewareIfExists(pid string) {
	if samlMiddlewares[pid] != nil {
		samlMiddlewares[pid] = nil
	}
}

// Instantiate the middleware SAML from the information in the configuration file
func (h *Handler) instantiateMiddleware(ctx context.Context, config config.Config, pid string) error {

	providerConfig, err := CreateSAMLProviderConfig(config, ctx, pid)
	if err != nil {
		return err
	}

	// Key pair to encrypt and sign SAML requests
	keyPair, err := tls.LoadX509KeyPair(strings.Replace(providerConfig.PublicCertPath, "file://", "", 1), strings.Replace(providerConfig.PrivateKeyPath, "file://", "", 1))
	if err != nil {
		return herodot.ErrInternalServerError.WithReason("An error occurred while retrieving the key pair used by SAML")
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return herodot.ErrInternalServerError.WithReason("An error occurred while using the certificate associated with SAML")
	}

	var idpMetadata *samlidp.EntityDescriptor

	// We check if the metadata file is provided
	if providerConfig.IDPInformation["idp_metadata_url"] != "" {
		// The metadata file is provided
		metadataURL := providerConfig.IDPInformation["idp_metadata_url"]

		metadataBuffer, err := fetcher.NewFetcher().Fetch(metadataURL)
		if err != nil {
			return herodot.ErrNotFound.WithTrace(err)
		}

		metadata, err := ioutil.ReadAll(metadataBuffer)
		if err != nil {
			return herodot.ErrInternalServerError.WithTrace(err)
		}

		idpMetadata, err = samlsp.ParseMetadata(metadata)
		if err != nil {
			return ErrInvalidSAMLMetadataError.WithTrace(err)
		}

	} else {
		// The metadata file is not provided
		// So were are creating a minimalist IDP metadata based on what is provided by the user on the config file
		entityIDURL, err := url.Parse(providerConfig.IDPInformation["idp_entity_id"])
		if err != nil {
			return herodot.ErrNotFound.WithTrace(err)
		}

		// The IDP SSO URL
		IDPSSOURL, err := url.Parse(providerConfig.IDPInformation["idp_sso_url"])
		if err != nil {
			return herodot.ErrNotFound.WithTrace(err)
		}

		// The IDP Logout URL
		IDPlogoutURL, err := url.Parse(providerConfig.IDPInformation["idp_logout_url"])
		if err != nil {
			return herodot.ErrNotFound.WithTrace(err)
		}

		// The certificate of the IDP
		certificateBuffer, err := fetcher.NewFetcher().Fetch(providerConfig.IDPInformation["idp_certificate_path"])
		if err != nil {
			return herodot.ErrNotFound.WithTrace(err)
		}

		certificate, err := ioutil.ReadAll(certificateBuffer)
		if err != nil {
			return herodot.ErrInternalServerError.WithTrace(err)
		}

		// We parse it into a x509.Certificate object
		IDPCertificate, err := MustParseCertificate(certificate)
		if err != nil {
			return ErrInvalidCertificateError.WithTrace(err)
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
	rootURL, err := url.Parse(config.SelfServiceBrowserDefaultReturnTo(ctx).String())
	if err != nil {
		return herodot.ErrNotFound.WithTrace(err)
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
		return herodot.ErrInternalServerError.WithTrace(err)
	}

	// It's better to use SHA256 than SHA1
	samlMiddleWare.ServiceProvider.SignatureMethod = dsig.RSASHA256SignatureMethod

	var publicUrlString = config.SelfPublicURL(ctx).String()

	// Sometimes there is an issue with double slash into the url so we prevent it
	// Crewjam library use default route for ACS and metadata but we want to overwrite them
	RouteSamlAcsWithSlash := strings.Replace(RouteAcs, ":provider", providerConfig.ID, 1)
	if publicUrlString[len(publicUrlString)-1] != '/' {

		u, err := url.Parse(publicUrlString + RouteSamlAcsWithSlash)
		if err != nil {
			return herodot.ErrNotFound.WithTrace(err)
		}
		samlMiddleWare.ServiceProvider.AcsURL = *u

	} else if publicUrlString[len(publicUrlString)-1] == '/' {

		publicUrlString = publicUrlString[:len(publicUrlString)-1]
		u, err := url.Parse(publicUrlString + RouteSamlAcsWithSlash)
		if err != nil {
			return herodot.ErrNotFound.WithTrace(err)
		}
		samlMiddleWare.ServiceProvider.AcsURL = *u
	}

	// Crewjam library use default route for ACS and metadata but we want to overwrite them
	metadata, err := url.Parse(publicUrlString + strings.Replace(RouteMetadata, ":provider", providerConfig.ID, 1))
	if err != nil {
		return herodot.ErrNotFound.WithTrace(err)
	}
	samlMiddleWare.ServiceProvider.MetadataURL = *metadata

	// The EntityID in the AuthnRequest is the Metadata URL
	samlMiddleWare.ServiceProvider.EntityID = samlMiddleWare.ServiceProvider.MetadataURL.String()

	// The issuer format is unspecified
	samlMiddleWare.ServiceProvider.AuthnNameIDFormat = samlidp.UnspecifiedNameIDFormat

	crt, ok := samlMiddleWare.RequestTracker.(samlsp.CookieRequestTracker)
	if ok {
		crt.MaxAge = time.Minute * 30
		crt.SameSite = http.SameSiteNoneMode
		samlMiddleWare.RequestTracker = crt
	}

	samlMiddlewares[pid] = samlMiddleWare

	return nil
}

// Return the singleton MiddleWare
func GetMiddleware(pid string) (*samlsp.Middleware, error) {
	if samlMiddlewares[pid] == nil {
		return nil, errors.Errorf("An error occurred during the connection with SAML.")
	}
	return samlMiddlewares[pid], nil
}

func MustParseCertificate(pemStr []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(pemStr)
	if b == nil {
		return nil, errors.Errorf("Cannot find the next PEM formatted block while parsing the certificate")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// Create a SAMLProvider object from the config file
func CreateSAMLProviderConfig(config config.Config, ctx context.Context, pid string) (*Configuration, error) {
	var c ConfigurationCollection
	conf := config.SelfServiceStrategy(ctx, "saml").Config
	if err := jsonx.
		NewStrictDecoder(bytes.NewBuffer(conf)).
		Decode(&c); err != nil {
		return nil, ErrInvalidSAMLConfiguration.WithReasonf("Unable to decode config %v", string(conf)).WithTrace(err)
	}

	if len(c.SAMLProviders) == 0 {
		return nil, ErrInvalidSAMLConfiguration.WithReason("Please indicate a SAML Identity Provider in your configuration file")
	}

	providerConfig, err := c.ProviderConfig(pid)
	if err != nil {
		return nil, ErrInvalidSAMLConfiguration.WithTrace(err)
	}

	if providerConfig.IDPInformation == nil {
		return nil, ErrInvalidSAMLConfiguration.WithReasonf("Please include your Identity Provider information in the configuration file.").WithTrace(err)
	}

	_, sso_exists := providerConfig.IDPInformation["idp_sso_url"]
	_, entity_id_exists := providerConfig.IDPInformation["idp_entity_id"]
	_, certificate_exists := providerConfig.IDPInformation["idp_certificate_path"]
	_, logout_url_exists := providerConfig.IDPInformation["idp_logout_url"]
	_, metadata_exists := providerConfig.IDPInformation["idp_metadata_url"]

	if (!metadata_exists && (!sso_exists || !entity_id_exists || !certificate_exists || !logout_url_exists)) || len(providerConfig.IDPInformation) > 4 {
		return nil, ErrInvalidSAMLConfiguration.WithReason("Please check your IDP information in the configuration file").WithTrace(err)
	}

	if providerConfig.ID == "" {
		return nil, ErrInvalidSAMLConfiguration.WithReason("Provider must have an ID").WithTrace(err)
	}

	if providerConfig.Label == "" {
		return nil, ErrInvalidSAMLConfiguration.WithReason("Provider must have a label").WithTrace(err)
	}

	if providerConfig.PrivateKeyPath == "" {
		return nil, ErrInvalidSAMLConfiguration.WithReason("Provider must have a private key").WithTrace(err)
	}

	if providerConfig.PublicCertPath == "" {
		return nil, ErrInvalidSAMLConfiguration.WithReason("Provider must have a public certificate").WithTrace(err)
	}

	if providerConfig.AttributesMap == nil || len(providerConfig.AttributesMap) == 0 {
		return nil, ErrInvalidSAMLConfiguration.WithReason("Provider must have an attributes map").WithTrace(err)
	}

	if providerConfig.AttributesMap["id"] == "" {
		return nil, ErrInvalidSAMLConfiguration.WithReason("You must have an ID field in your attribute_map").WithTrace(err)
	}

	if providerConfig.Mapper == "" {
		return nil, ErrInvalidSAMLConfiguration.WithReason("Provider must have a mapper url").WithTrace(err)
	}

	return providerConfig, nil
}

// swagger:route GET /admin/providers/saml provider listProviders
//
// # List Providers
//
// Lists all saml providers in the system.
//
//	Produces:
//	- application/json
//
//	Schemes: http, https
//
//	Security:
//	  oryAccessToken:
//
//	Responses:
//	  200: listProviders
//	  default: errorGeneric
func (s *Strategy) listProviders(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if c, err := s.Config(r.Context()); err != nil {
		s.d.Writer().WriteError(w, r, err)
	} else {
		// Providers configurations using the marshaler for hiding client secret
		l := make([]Configuration, len(c.SAMLProviders))
		for i, configuration := range c.SAMLProviders {
			l[i] = configuration
		}
		s.d.Writer().Write(w, r, l)
	}
}
