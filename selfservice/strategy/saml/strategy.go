package saml

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/ory/kratos/cipher"
	"github.com/ory/kratos/schema"
	"github.com/ory/kratos/selfservice/sessiontokenexchange"
	"github.com/ory/x/jsonnetsecure"
	"github.com/ory/x/sqlcon"
	"github.com/ory/x/sqlxx"
	"github.com/ory/x/urlx"
	"net/http"
	"net/url"
	"strings"
	"time"

	samlidp "github.com/crewjam/saml"
	"github.com/gofrs/uuid"
	"github.com/julienschmidt/httprouter"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"

	"github.com/ory/herodot"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/container"
	"github.com/ory/kratos/ui/node"

	"github.com/ory/x/decoderx"
	"github.com/ory/x/jsonx"

	"github.com/ory/kratos/continuity"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/errorx"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"

	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/kratos/selfservice/strategy"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
)

const (
	RouteBase = "/self-service/methods/saml"

	RouteBaseAcs      = RouteBase + "/acs"
	RouteBaseAuth     = RouteBase + "/auth"
	RouteBaseMetadata = RouteBase + "/metadata"

	RouteAcs                = RouteBaseAcs + "/:provider"
	RouteAuth               = RouteBaseAuth + "/:provider"
	RouteMetadata           = RouteBaseMetadata + "/:provider"
	RouteProviderCollection = "/providers/saml"
)

var _ identity.ActiveCredentialsCounter = new(Strategy)

type dependencies interface {
	errorx.ManagementProvider

	config.Provider

	x.LoggingProvider
	x.CookieProvider
	x.CSRFProvider
	x.CSRFTokenGeneratorProvider
	x.WriterProvider
	x.HTTPClientProvider
	x.TracingProvider

	identity.ValidationProvider
	identity.PrivilegedPoolProvider
	identity.ActiveCredentialsCounterStrategyProvider
	identity.ManagementProvider

	session.ManagementProvider
	session.HandlerProvider
	sessiontokenexchange.PersistenceProvider

	login.HookExecutorProvider
	login.FlowPersistenceProvider
	login.HooksProvider
	login.StrategyProvider
	login.HandlerProvider
	login.ErrorHandlerProvider

	registration.HookExecutorProvider
	registration.FlowPersistenceProvider
	registration.HooksProvider
	registration.StrategyProvider
	registration.HandlerProvider
	registration.ErrorHandlerProvider

	settings.ErrorHandlerProvider
	settings.FlowPersistenceProvider
	settings.HookExecutorProvider

	continuity.ManagementProvider
	continuity.PersistenceProvider

	cipher.Provider

	jsonnetsecure.VMProvider

	MiddlewareManagerProvider
}

func (s *Strategy) ID() identity.CredentialsType {
	return identity.CredentialsTypeSAML
}

func (s *Strategy) D() dependencies {
	return s.d
}

func (s *Strategy) NodeGroup() node.UiNodeGroup {
	return node.SAMLGroup
}

func isForced(req interface{}) bool {
	f, ok := req.(interface {
		IsForced() bool
	})
	return ok && f.IsForced()
}

type Strategy struct {
	d         dependencies
	validator *schema.Validator
	dec       *decoderx.HTTP
}

type authCodeContainer struct {
	FlowID    string          `json:"flow_id"`
	RequestID string          `json:"request_id"`
	State     string          `json:"state"`
	Traits    json.RawMessage `json:"traits"`
}

func NewStrategy(d dependencies) *Strategy {
	return &Strategy{
		d:         d,
		validator: schema.NewValidator(),
	}
}

// We indicate here that when the ACS endpoint receives a POST request, we call the HandleCallback method to process it
func (s *Strategy) setRoutes(r *x.RouterPublic) {
	wrappedHandleCallback := strategy.IsDisabled(s.d, s.ID().String(), s.HandleCallback)
	if handle, _, _ := r.Lookup("POST", RouteAcs); handle == nil {
		r.POST(RouteAcs, wrappedHandleCallback)
	} // ACS SUPPORT

	if handle, _, _ := r.Lookup("GET", RouteProviderCollection); handle == nil {
		s.d.CSRFHandler().IgnorePath(RouteProviderCollection)
		r.GET(RouteProviderCollection, x.RedirectToAdminRoute(s.d))
	}

	wrappedHandleCallback = strategy.IsDisabled(s.d, s.ID().String(), s.loginWithIdp)
	if handle, _, _ := r.Lookup("GET", RouteAuth); handle == nil {
		r.GET(RouteAuth, wrappedHandleCallback)
	}
}

// Retrieves the user's attributes from the SAML Assertion
func (s *Strategy) GetAttributesFromAssertion(assertion *samlidp.Assertion) (map[string][]string, error) {

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
	if rid.IsNil() {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReason("The session cookie contains invalid values and the flow could not be executed. Please try again."))
	}

	if ar, err := s.d.RegistrationFlowPersister().GetRegistrationFlow(ctx, rid); err == nil {
		if ar.Type != flow.TypeBrowser {
			return ar, ErrAPIFlowNotSupported
		}

		if err := ar.Valid(); err != nil {
			return ar, err
		}
		return ar, nil
	}

	if ar, err := s.d.LoginFlowPersister().GetLoginFlow(ctx, rid); err == nil {
		if err := ar.Valid(); err != nil {
			return ar, err
		}
		return ar, nil
	}

	ar, err := s.d.SettingsFlowPersister().GetSettingsFlow(ctx, rid)
	if err == nil {
		if ar.Type != flow.TypeBrowser {
			return ar, ErrAPIFlowNotSupported
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

// Check if the user is already authenticated
func (s *Strategy) alreadyAuthenticated(w http.ResponseWriter, r *http.Request, req interface{}) bool {
	// we assume an error means the user has no session
	if _, err := s.d.SessionManager().FetchFromRequest(r.Context(), r); err == nil {
		if !isForced(req) {
			http.Redirect(w, r, s.d.Config().SelfServiceBrowserDefaultReturnTo(r.Context()).String(), http.StatusSeeOther)
			return true
		}
	}

	return false
}

func (s *Strategy) validateCallback(_ http.ResponseWriter, r *http.Request) (flow.Flow, *authCodeContainer, error) {
	continuitySessionID := r.PostForm.Get("RelayState")
	if continuitySessionID == "" {
		return nil, nil, errors.WithStack(errors.New("RelayState is not set in request"))
	}

	id, err := uuid.FromString(continuitySessionID)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	continuitySession, err := s.d.ContinuityPersister().GetContinuitySession(r.Context(), id)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	var codeContainer authCodeContainer
	if err := json.NewDecoder(bytes.NewBuffer(continuitySession.Payload)).Decode(&codeContainer); err != nil {
		return nil, nil, errors.WithStack(err)
	}

	req, err := s.validateFlow(r.Context(), r, x.ParseUUID(codeContainer.FlowID))
	if err != nil {
		return nil, &codeContainer, errors.WithStack(err)
	}

	if err := s.d.ContinuityPersister().DeleteContinuitySession(r.Context(), id); err != nil && !errors.Is(err, sqlcon.ErrNoRows) {
		return nil, nil, errors.WithStack(err)
	}

	if r.URL.Query().Get("error") != "" {
		return req, &codeContainer, errors.WithStack(herodot.ErrBadRequest.WithReasonf(`Unable to complete SAML flow because the SAML Provider returned error "%s": %s`, r.URL.Query().Get("error"), r.URL.Query().Get("error_description")))
	}

	return req, &codeContainer, nil
}

// Handle /selfservice/methods/saml/acs/:provider | Receive SAML response, parse the attributes and start auth flow
func (s *Strategy) HandleCallback(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	// We get the provider ID form the URL
	pid := ps.ByName("provider")

	if err := r.ParseForm(); err != nil {
		s.d.SelfServiceErrorManager().Forward(r.Context(), w, r, s.handleError(w, r, nil, pid, nil, err))
		return
	}

	s.d.Logger().WithField("SAMLResponse", r.PostForm.Get("SAMLResponse")).Debug("Received SAML Response")

	req, c, err := s.validateCallback(w, r)
	if err != nil {
		if req != nil {
			s.forwardError(w, r, req, s.handleError(w, r, req, pid, nil, err))
		} else {
			s.d.SelfServiceErrorManager().Forward(r.Context(), w, r, s.handleError(w, r, nil, pid, nil, err))
		}
		return
	}

	m, err := s.d.SAMLMiddlewareManager().GetMiddleware(r.Context(), pid)
	if err != nil {
		s.forwardError(w, r, req, s.handleError(w, r, req, pid, nil, err))
		return
	}

	assertion, err := m.ServiceProvider.ParseResponse(r, []string{c.RequestID})
	if err != nil {
		sErr, ok := err.(*samlidp.InvalidResponseError)
		if ok {
			s.d.Logger().WithError(sErr.PrivateErr).Debug("Error parsing SAML Response")
		}
		s.forwardError(w, r, req, s.handleError(w, r, req, pid, nil, err))
		return
	}

	// We get the user's attributes from the SAML Response (assertion)
	attributes, err := s.GetAttributesFromAssertion(assertion)
	if err != nil {
		s.forwardError(w, r, req, s.handleError(w, r, req, pid, nil, err))
		return
	}

	// We get the provider information from the config file
	provider, err := s.Provider(r.Context(), pid)
	if err != nil {
		s.forwardError(w, r, req, s.handleError(w, r, req, pid, nil, err))
		return
	}

	// We translate SAML Attributes into claims (To create an identity we need these claims)
	claims, err := provider.Claims(r.Context(), s.d.Config(), attributes, pid)
	if err != nil {
		s.forwardError(w, r, req, s.handleError(w, r, req, pid, nil, err))
		return
	}

	switch a := req.(type) {
	case *registration.Flow:
		if err := s.processRegistration(w, r, a, provider, claims); err != nil {
			if errors.Is(err, flow.ErrCompletedByStrategy) {
				return
			}
			// Need to re-fetch flow as it might has been updated
			updatedFlow, innerErr := s.d.LoginFlowPersister().GetLoginFlow(r.Context(), a.ID)
			if innerErr != nil {
				s.forwardError(w, r, a, innerErr)
			}
			s.forwardError(w, r, updatedFlow, err)
		}
		return
	case *login.Flow:
		if _, err := s.processLogin(w, r, a, provider, claims); err != nil {
			if errors.Is(err, flow.ErrCompletedByStrategy) {
				return
			}
			// Need to re-fetch flow as it might has been updated
			updatedFlow, innerErr := s.d.LoginFlowPersister().GetLoginFlow(r.Context(), a.ID)
			if innerErr != nil {
				s.forwardError(w, r, a, innerErr)
			}
			s.forwardError(w, r, updatedFlow, err)
		}
		return
	case *settings.Flow:
		sess, err := s.d.SessionManager().FetchFromRequest(r.Context(), r)
		if err != nil {
			s.forwardError(w, r, a, s.handleError(w, r, a, pid, nil, err))
			return
		}
		if err := s.linkProvider(w, r, &settings.UpdateContext{Session: sess, Flow: a}, claims, provider); err != nil {
			s.forwardError(w, r, a, s.handleError(w, r, a, pid, nil, err))
			return
		}
		return
	default:
		s.forwardError(w, r, req, s.handleError(w, r, req, pid, nil, errors.WithStack(x.PseudoPanic.
			WithDetailf("cause", "Unexpected type in SAML flow: %T", a))))
		return
	}
}

func (s *Strategy) forwardError(w http.ResponseWriter, r *http.Request, f flow.Flow, err error) {
	switch ff := f.(type) {
	case *login.Flow:
		s.d.LoginFlowErrorHandler().WriteFlowError(w, r, ff, s.NodeGroup(), err)
	case *registration.Flow:
		s.d.RegistrationFlowErrorHandler().WriteFlowError(w, r, ff, s.NodeGroup(), err)
	default:
		panic(errors.Errorf("unexpected type: %T", ff))
	}
}

// Return the SAML Provider with the specific ID
func (s *Strategy) Provider(ctx context.Context, id string) (Provider, error) {
	c, err := s.Config(ctx)
	if err != nil {
		return nil, err
	}

	provider, err := c.Provider(id, s.d)
	if err != nil {
		return nil, err
	}

	return provider, nil
}

// Translate YAML Config file into a SAML Provider struct
func (s *Strategy) Config(ctx context.Context) (*ConfigurationCollection, error) {
	var c ConfigurationCollection

	conf := s.d.Config().SelfServiceStrategy(ctx, string(s.ID())).Config
	if err := jsonx.
		NewStrictDecoder(bytes.NewBuffer(conf)).
		Decode(&c); err != nil {
		s.d.Logger().WithError(err).WithField("config", conf)
		return nil, errors.WithStack(herodot.ErrInternalServerError.
			WithReason("Unable to decode SAML Identity Provider configuration").
			WithDebug(err.Error()).WithWrap(err))

	}

	return &c, nil
}

func (s *Strategy) populateMethod(r *http.Request, c *container.Container, message func(provider string) *text.Message) error {
	conf, err := s.Config(r.Context())
	if err != nil {
		return ErrInvalidSAMLConfiguration.WithTrace(err)
	}

	// does not need sorting because there is only one field
	c.SetCSRF(s.d.GenerateCSRFToken(r))
	AddProviders(c, conf.SAMLProviders, message)

	return nil
}

func (s *Strategy) handleError(w http.ResponseWriter, r *http.Request, f flow.Flow, providerID string, traits []byte, err error) error {
	switch rf := f.(type) {
	case *login.Flow:
		return err
	case *registration.Flow:
		// Reset all nodes to not confuse users.
		// This is kinda hacky and will probably need to be updated at some point.

		if dup := new(identity.ErrDuplicateCredentials); errors.As(err, &dup) {
			err = schema.NewDuplicateCredentialsError(dup)

			if validationErr := new(schema.ValidationError); errors.As(err, &validationErr) {
				for _, m := range validationErr.Messages {
					m := m
					rf.UI.Messages.Add(&m)
				}
			} else {
				rf.UI.Messages.Add(text.NewErrorValidationDuplicateCredentialsOnOIDCLink())
			}

			lf, err := s.registrationToLogin(w, r, rf, providerID)
			if err != nil {
				return err
			}
			// return a new login flow with the error message embedded in the login flow.
			var redirectURL *url.URL
			if lf.Type == flow.TypeAPI {
				returnTo := s.d.Config().SelfServiceBrowserDefaultReturnTo(r.Context())
				if redirecter, ok := f.(flow.FlowWithRedirect); ok {
					secureReturnTo, err := x.SecureRedirectTo(r, returnTo, redirecter.SecureRedirectToOpts(r.Context(), s.d)...)
					if err == nil {
						returnTo = secureReturnTo
					}
				}
				redirectURL = lf.AppendTo(returnTo)
			} else {
				redirectURL = lf.AppendTo(s.d.Config().SelfServiceFlowLoginUI(r.Context()))
			}
			if dc, err := flow.DuplicateCredentials(lf); err == nil && dc != nil {
				redirectURL = urlx.CopyWithQuery(redirectURL, url.Values{"no_org_ui": {"true"}})

				for i, n := range lf.UI.Nodes {
					if n.Meta == nil || n.Meta.Label == nil {
						continue
					}
					switch n.Meta.Label.ID {
					case text.InfoSelfServiceLogin:
						lf.UI.Nodes[i].Meta.Label = text.NewInfoLoginAndLink()
					case text.InfoSelfServiceLoginWith:
						p := gjson.GetBytes(n.Meta.Label.Context, "provider").String()
						lf.UI.Nodes[i].Meta.Label = text.NewInfoLoginWithAndLink(p)
					}
				}

				newLoginURL := s.d.Config().SelfServiceFlowLoginUI(r.Context()).String()
				providerLabel := providerID
				provider, _ := s.Provider(r.Context(), providerID)
				if provider != nil && provider.Config() != nil {
					providerLabel = provider.Config().Label
				}
				lf.UI.Messages.Add(text.NewInfoLoginLinkMessage(dc.DuplicateIdentifier, providerLabel, newLoginURL))

				err := s.d.LoginFlowPersister().UpdateLoginFlow(r.Context(), lf)
				if err != nil {
					return err
				}
			}
			x.AcceptToRedirectOrJSON(w, r, s.d.Writer(), lf, redirectURL.String())
			// ensure the function does not continue to execute
			return flow.ErrCompletedByStrategy
		}

		rf.UI.Nodes = node.Nodes{}

		// Adds the "Continue" button
		rf.UI.SetCSRF(s.d.GenerateCSRFToken(r))
		AddProvider(rf.UI, providerID, text.NewInfoRegistrationContinue())

		if traits != nil {
			ds, err := s.d.Config().DefaultIdentityTraitsSchemaURL(r.Context())
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
		return ErrAPIFlowNotSupported.WithTrace(err)
	}

	return err
}

func (s *Strategy) CountActiveCredentials(cc map[identity.CredentialsType]identity.Credentials) (count int, err error) {
	for _, c := range cc {
		if c.Type == s.ID() && gjson.ValidBytes(c.Config) {
			var conf identity.CredentialsSAML
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
			var conf identity.CredentialsSAML
			if err = json.Unmarshal(c.Config, &conf); err != nil {
				return 0, errors.WithStack(err)
			}

			for _, ider := range c.Identifiers {
				parts := strings.Split(ider, ":")
				if len(parts) != 2 {
					continue
				}

				for _, prov := range conf.Providers {
					if parts[0] == prov.Provider && parts[1] == prov.Subject && len(prov.Subject) > 0 && len(prov.Provider) > 0 {
						count++
					}
				}
			}
		}
	}
	return
}

func (s *Strategy) CountActiveMultiFactorCredentials(_ map[identity.CredentialsType]identity.Credentials) (count int, err error) {
	return 0, nil
}

func (s *Strategy) CompletedAuthenticationMethod(_ context.Context, _ session.AuthenticationMethods) session.AuthenticationMethod {
	return session.AuthenticationMethod{
		Method: s.ID(),
		AAL:    identity.AuthenticatorAssuranceLevel1,
	}
}

func (s *Strategy) startSAMLFlow(w http.ResponseWriter, r *http.Request, f flow.Flow, pid string) error {
	middleware, err := s.d.SAMLMiddlewareManager().GetMiddleware(r.Context(), pid)
	if err != nil {
		return err
	}

	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(authCodeContainer{
		FlowID: f.GetID().String(),
	}); err != nil {
		return err
	}
	c := continuity.Container{
		ID:        uuid.Nil,
		Name:      "saml_request",
		ExpiresAt: time.Now().Add(time.Minute * 10).UTC().Truncate(time.Second),
		Payload:   sqlxx.NullJSONRawMessage(b.Bytes()),
	}

	if err := s.d.ContinuityPersister().SaveContinuitySession(r.Context(), &c); err != nil {
		return err
	}
	middleware.HandleStartAuthFlow(w, r.WithContext(context.WithValue(r.Context(), continuitySessionIDKey, c.ID)))

	return nil
}
