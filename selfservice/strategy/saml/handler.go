package saml

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/kratos/continuity"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/strategy"
	"github.com/pkg/errors"
	"net/http"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/selfservice/errorx"

	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
	"github.com/ory/x/decoderx"
	"github.com/ory/x/jsonx"
)

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
		MiddlewareManagerProvider
	}
	HandlerProvider interface {
		SAMLHandler() *Handler
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
}

func (s *Strategy) setAdminRoutes(r *x.RouterAdmin) {
	wrappedListProviders := strategy.IsDisabled(s.d, s.ID().String(), s.listProviders)
	r.GET(RouteProviderCollection, wrappedListProviders)
}

// Handle /selfservice/methods/saml/metadata
func (h *Handler) serveMetadata(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	pid := ps.ByName("provider")

	middleware, err := h.d.SAMLMiddlewareManager().GetMiddleware(r.Context(), pid)
	if err != nil {
		h.d.SelfServiceErrorManager().Forward(r.Context(), w, r, err)
		return
	}

	buf, _ := xml.MarshalIndent(middleware.ServiceProvider.Metadata(), "", "  ")
	w.Header().Set("Content-Type", "text/xml")
	_, err = w.Write(buf)
	if err != nil {
		h.d.SelfServiceErrorManager().Forward(r.Context(), w, r, err)
		return
	}
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

// CreateSAMLProviderConfig Create a SAMLProvider object from the config file
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

	_, ssoExists := providerConfig.IDPInformation["idp_sso_url"]
	_, entityIdExists := providerConfig.IDPInformation["idp_entity_id"]
	_, certificateExists := providerConfig.IDPInformation["idp_certificate_path"]
	_, logoutUrlExists := providerConfig.IDPInformation["idp_logout_url"]
	_, metadataExists := providerConfig.IDPInformation["idp_metadata_url"]

	if (!metadataExists && (!ssoExists || !entityIdExists || !certificateExists || !logoutUrlExists)) || len(providerConfig.IDPInformation) > 4 {
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
		// Providers configurations using the marshaller for hiding client secret
		l := make([]Configuration, len(c.SAMLProviders))
		for i, configuration := range c.SAMLProviders {
			l[i] = configuration
		}
		s.d.Writer().Write(w, r, l)
	}
}
