package strategy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/gofrs/uuid"
	"github.com/julienschmidt/httprouter"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"

	"github.com/ory/herodot"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/container"
	"github.com/ory/kratos/ui/node"

	"github.com/go-playground/validator/v10"

	"github.com/ory/x/decoderx"
	"github.com/ory/x/fetcher"
	"github.com/ory/x/jsonx"

	"github.com/ory/kratos/continuity"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/hash"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/errorx"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"

	"github.com/ory/kratos/selfservice/flow/registration"
	samlflow "github.com/ory/kratos/selfservice/flow/saml"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/kratos/selfservice/strategy"
	samlstrategy "github.com/ory/kratos/selfservice/strategy/saml"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
)

const (
	RouteBase = "/self-service/methods/saml"

	RouteAcs  = RouteBase + "/acs"
	RouteAuth = RouteBase + "/auth"
)

var _ identity.ActiveCredentialsCounter = new(Strategy)

type registrationStrategyDependencies interface {
	x.LoggingProvider
	x.WriterProvider
	x.CSRFTokenGeneratorProvider
	x.CSRFProvider

	config.Provider

	continuity.ManagementProvider
	continuity.ManagementProviderRelayState

	errorx.ManagementProvider
	hash.HashProvider

	registration.HandlerProvider
	registration.HooksProvider
	registration.ErrorHandlerProvider
	registration.HookExecutorProvider
	registration.FlowPersistenceProvider

	login.HooksProvider
	login.ErrorHandlerProvider
	login.HookExecutorProvider
	login.FlowPersistenceProvider
	login.HandlerProvider

	settings.FlowPersistenceProvider
	settings.HookExecutorProvider
	settings.HooksProvider
	settings.ErrorHandlerProvider

	identity.PrivilegedPoolProvider
	identity.ValidationProvider

	session.HandlerProvider
	session.ManagementProvider
}

func (s *Strategy) ID() identity.CredentialsType {
	return identity.CredentialsTypeSAML
}

func (s *Strategy) D() registrationStrategyDependencies {
	return s.d
}

func (s *Strategy) NodeGroup() node.UiNodeGroup {
	return node.SAMLGroup
}

func uid(provider, subject string) string {
	return fmt.Sprintf("%s:%s", provider, subject)
}

func isForced(req interface{}) bool {
	f, ok := req.(interface {
		IsForced() bool
	})
	return ok && f.IsForced()
}

type Strategy struct {
	d  registrationStrategyDependencies
	f  *fetcher.Fetcher
	v  *validator.Validate
	hd *decoderx.HTTP
}

type authCodeContainer struct {
	FlowID string          `json:"flow_id"`
	State  string          `json:"state"`
	Traits json.RawMessage `json:"traits"`
}

func NewStrategy(d registrationStrategyDependencies) *Strategy {
	return &Strategy{
		d:  d,
		f:  fetcher.NewFetcher(),
		v:  validator.New(),
		hd: decoderx.NewHTTP(),
	}
}

// We indicate here that when the ACS endpoint receives a POST request, we call the handleCallback method to process it
func (s *Strategy) setRoutes(r *x.RouterPublic) {
	wrappedHandleCallback := strategy.IsDisabled(s.d, s.ID().String(), s.handleCallback)
	if handle, _, _ := r.Lookup("POST", RouteAcs); handle == nil {
		r.POST(RouteAcs, wrappedHandleCallback)
	} // ACS SUPPORT
}

// Get possible SAML Request IDs
func GetPossibleRequestIDs(r *http.Request, m samlsp.Middleware) []string {
	possibleRequestIDs := []string{}
	if m.ServiceProvider.AllowIDPInitiated {
		possibleRequestIDs = append(possibleRequestIDs, "")
	}

	trackedRequests := m.RequestTracker.GetTrackedRequests(r)
	for _, tr := range trackedRequests {
		possibleRequestIDs = append(possibleRequestIDs, tr.SAMLRequestID)
	}

	return possibleRequestIDs
}

// Retrieves the user's attributes from the SAML Assertion
func (s *Strategy) GetAttributesFromAssertion(assertion *saml.Assertion) (map[string][]string, error) {

	if assertion == nil {
		return nil, errors.New("The assertion is nil")
	}

	attributes := map[string][]string{}

	for _, attributeStatement := range assertion.AttributeStatements {
		for _, attr := range attributeStatement.Attributes {
			claimName := attr.Name
			for _, value := range attr.Values {
				attributes[claimName] = append(attributes[claimName], value.Value)
			}
		}
	}

	return attributes, nil
}

func (s *Strategy) validateFlow(ctx context.Context, r *http.Request, rid uuid.UUID) (flow.Flow, error) {
	if x.IsZeroUUID(rid) {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReason("The session cookie contains invalid values and the flow could not be executed. Please try again."))
	}

	if ar, err := s.d.RegistrationFlowPersister().GetRegistrationFlow(ctx, rid); err == nil {
		if ar.Type != flow.TypeBrowser {
			return ar, samlstrategy.ErrAPIFlowNotSupported
		}

		if err := ar.Valid(); err != nil {
			return ar, err
		}
		return ar, nil
	}

	if ar, err := s.d.LoginFlowPersister().GetLoginFlow(ctx, rid); err == nil {
		if ar.Type != flow.TypeBrowser {
			return ar, samlstrategy.ErrAPIFlowNotSupported
		}

		if err := ar.Valid(); err != nil {
			return ar, err
		}
		return ar, nil
	}

	ar, err := s.d.SettingsFlowPersister().GetSettingsFlow(ctx, rid)
	if err == nil {
		if ar.Type != flow.TypeBrowser {
			return ar, samlstrategy.ErrAPIFlowNotSupported
		}

		sess, err := s.d.SessionManager().FetchFromRequest(ctx, r)
		if err != nil {
			return ar, err
		}

		if err := ar.Valid(sess); err != nil {
			return ar, err
		}
		return ar, nil
	}

	return ar, err // this must return the error
}

func (s *Strategy) alreadyAuthenticated(w http.ResponseWriter, r *http.Request, req interface{}) bool {
	// we assume an error means the user has no session
	if _, err := s.d.SessionManager().FetchFromRequest(r.Context(), r); err == nil {
		if _, ok := req.(*settings.Flow); ok {
			// ignore this if it's a settings flow
		} else if !isForced(req) {
			http.Redirect(w, r, s.d.Config(r.Context()).SelfServiceBrowserDefaultReturnTo().String(), http.StatusSeeOther)
			return true
		}
	}

	return false
}

func (s *Strategy) validateCallback(w http.ResponseWriter, r *http.Request) (flow.Flow, *authCodeContainer, error) {
	var cntnr authCodeContainer
	if _, err := s.d.RelayStateContinuityManager().Continue(r.Context(), w, r, sessionName, continuity.WithPayload(&cntnr)); err != nil {
		return nil, nil, err
	}

	req, err := s.validateFlow(r.Context(), r, x.ParseUUID(cntnr.FlowID))
	if err != nil {
		return nil, &cntnr, err
	}

	if r.URL.Query().Get("error") != "" {
		return req, &cntnr, errors.WithStack(herodot.ErrBadRequest.WithReasonf(`Unable to complete SAML flow because the SAML Provider returned error "%s": %s`, r.URL.Query().Get("error"), r.URL.Query().Get("error_description")))
	}

	return req, &cntnr, nil
}

// Handle /selfservice/methods/saml/acs | Receive SAML response, parse the attributes and start auth flow
func (s *Strategy) handleCallback(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	pid := ps.ByName("provider")

	if err := r.ParseForm(); err != nil {
		s.d.SelfServiceErrorManager().Forward(r.Context(), w, r, s.handleError(w, r, nil, pid, nil, err))
	}

	req, _, err := s.validateCallback(w, r)
	if err != nil {
		if req != nil {
			s.forwardError(w, r, s.handleError(w, r, req, pid, nil, err))
			// TODO add flow param to s.handleError
			// s.forwardError(w, r, req, s.handleError(w, r, req, pid, nil, err))
		} else {
			s.d.SelfServiceErrorManager().Forward(r.Context(), w, r, s.handleError(w, r, nil, pid, nil, err))
		}
		return
	}

	m, err := samlflow.GetMiddleware()
	if err != nil {
		s.forwardError(w, r, err)
	}

	// We get the possible SAML request IDs
	possibleRequestIDs := GetPossibleRequestIDs(r, *m)
	assertion, err := m.ServiceProvider.ParseResponse(r, possibleRequestIDs)
	if err != nil {
		s.forwardError(w, r, err)
	}

	// We get the user's attributes from the SAML Response (assertion)
	attributes, err := s.GetAttributesFromAssertion(assertion)
	if err != nil {
		s.forwardError(w, r, err)
		return
	}

	// We get the provider information from the config file
	provider, err := s.Provider(r.Context())
	if err != nil {
		s.forwardError(w, r, err)
		return
	}

	// We translate SAML Attributes into claims (To create an identity we need these claims)
	claims, err := provider.Claims(r.Context(), s.d.Config(r.Context()), attributes)
	if err != nil {
		s.forwardError(w, r, err)
		return
	}

	switch a := req.(type) {
	case *login.Flow:
		// Now that we have the claims and the provider, we have to decide if we log or register the user
		if ff, err := s.processLoginOrRegister(w, r, a, provider, claims); err != nil {
			if ff != nil {
				s.forwardError(w, r, err)
			}
			s.forwardError(w, r, err)
		}
		return
	}
}

func (s *Strategy) forwardError(w http.ResponseWriter, r *http.Request, err error) {
	s.d.LoginFlowErrorHandler().WriteFlowError(w, r, nil, s.NodeGroup(), err)
}

// Return the SAML Provider
func (s *Strategy) Provider(ctx context.Context) (samlstrategy.Provider, error) {
	c, err := s.Config(ctx)
	if err != nil {
		return nil, err
	}

	provider, err := c.Provider(c.SAMLProviders[len(c.SAMLProviders)-1].ID, c.SAMLProviders[len(c.SAMLProviders)-1].Label)
	if err != nil {
		return nil, err
	}

	return provider, nil
}

// Translate YAML Config file into a SAML Provider struct
func (s *Strategy) Config(ctx context.Context) (*samlstrategy.ConfigurationCollection, error) {
	var c samlstrategy.ConfigurationCollection

	conf := s.d.Config(ctx).SelfServiceStrategy(string(s.ID())).Config
	if err := jsonx.
		NewStrictDecoder(bytes.NewBuffer(conf)).
		Decode(&c); err != nil {
		s.d.Logger().WithError(err).WithField("config", conf)
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to decode SAML Identity Provider configuration: %s", err))
	}

	return &c, nil
}

func (s *Strategy) populateMethod(r *http.Request, c *container.Container, message func(provider string) *text.Message) error {
	conf, err := s.Config(r.Context())
	if err != nil {
		return err
	}

	// does not need sorting because there is only one field
	c.SetCSRF(s.d.GenerateCSRFToken(r))
	AddProviders(c, conf.SAMLProviders, message)

	return nil
}

func (s *Strategy) handleError(w http.ResponseWriter, r *http.Request, f flow.Flow, provider string, traits []byte, err error) error {
	switch rf := f.(type) {
	case *login.Flow:
		return err
	case *registration.Flow:
		// Reset all nodes to not confuse users.
		// This is kinda hacky and will probably need to be updated at some point.

		rf.UI.Nodes = node.Nodes{}

		// Adds the "Continue" button
		rf.UI.SetCSRF(s.d.GenerateCSRFToken(r))
		AddProvider(rf.UI, provider, text.NewInfoRegistrationContinue())

		if traits != nil {
			ds, err := s.d.Config(r.Context()).DefaultIdentityTraitsSchemaURL()
			if err != nil {
				return err
			}

			traitNodes, err := container.NodesFromJSONSchema(r.Context(), node.SAMLGroup, ds.String(), "", nil)
			if err != nil {
				return err
			}

			rf.UI.Nodes = append(rf.UI.Nodes, traitNodes...)
			rf.UI.UpdateNodeValuesFromJSON(traits, "traits", node.SAMLGroup)
		}

		return err
	case *settings.Flow:
		return err
	}

	return err
}

func (s *Strategy) CountActiveCredentials(cc map[identity.CredentialsType]identity.Credentials) (count int, err error) {
	for _, c := range cc {
		if c.Type == s.ID() && gjson.ValidBytes(c.Config) {
			var conf CredentialsConfig
			if err = json.Unmarshal(c.Config, &conf); err != nil {
				return 0, errors.WithStack(err)
			}

			for _, ider := range c.Identifiers {
				parts := strings.Split(ider, ":")
				if len(parts) != 2 {
					continue
				}

				if parts[0] == conf.Providers[0].Provider && parts[1] == conf.Providers[0].Subject && len(conf.Providers[0].Subject) > 1 && len(conf.Providers[0].Provider) > 1 {
					count++
				}

			}
		}
	}
	return
}

func (s *Strategy) CountActiveFirstFactorCredentials(cc map[identity.CredentialsType]identity.Credentials) (count int, err error) {
	for _, c := range cc {
		if c.Type == s.ID() && gjson.ValidBytes(c.Config) {
			// TODO MANAGE THIS
			var conf identity.CredentialsOIDC
			if err = json.Unmarshal(c.Config, &conf); err != nil {
				return 0, errors.WithStack(err)
			}

			for _, ider := range c.Identifiers {
				parts := strings.Split(ider, ":")
				if len(parts) != 2 {
					continue
				}

				for _, prov := range conf.Providers {
					if parts[0] == prov.Provider && parts[1] == prov.Subject && len(prov.Subject) > 1 && len(prov.Provider) > 1 {
						count++
					}
				}
			}
		}
	}
	return
}

func (s *Strategy) CountActiveMultiFactorCredentials(cc map[identity.CredentialsType]identity.Credentials) (count int, err error) {
	return 0, nil
}

func (s *Strategy) CompletedAuthenticationMethod(ctx context.Context) session.AuthenticationMethod {
	return session.AuthenticationMethod{
		Method: s.ID(),
		AAL:    identity.AuthenticatorAssuranceLevel1,
	}
}
