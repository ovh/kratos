package saml

import (
	"bytes"
	"encoding/json"
	"github.com/gofrs/uuid"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/herodot"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
	"github.com/ory/x/sqlcon"
	"github.com/ory/x/urlx"
	"github.com/pkg/errors"
	"net/http"
)

// Implement the interface
var _ login.Strategy = new(Strategy)

// RegisterLoginRoutes Call at the creation of Kratos, when Kratos implement all authentication routes
func (s *Strategy) RegisterLoginRoutes(r *x.RouterPublic) {
	s.setRoutes(r)
}

// Start of webview flow
//
// swagger:route GET /self-service/methods/saml/auth v0alpha2 initializeSelfServiceSamlFlowForBrowsers
func (s *Strategy) loginWithIdp(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	flowID := r.URL.Query().Get("flow")
	if flowID == "" {
		s.d.SelfServiceErrorManager().Forward(r.Context(), w, r, errors.New(`Missing "flow" parameter`))
	}

	f, err := s.validateFlow(r.Context(), r, uuid.FromStringOrNil(flowID))
	if err != nil {
		s.d.SelfServiceErrorManager().Forward(r.Context(), w, r, err)
	}

	if err := s.doLogin(w, r, f.(*login.Flow), ps.ByName("provider")); err != nil {
		s.d.SelfServiceErrorManager().Forward(r.Context(), w, r, err)
	}
}

// SubmitSelfServiceLoginFlowWithSAMLMethodBody is used to decode the login form payload
// when using the saml method.
//
// swagger:model SubmitSelfServiceLoginFlowWithSAMLMethodBody
type SubmitSelfServiceLoginFlowWithSAMLMethodBody struct {
	// The provider to register with
	//
	// required: true
	Provider string `json:"samlProvider"`

	// The CSRF Token
	CSRFToken string `json:"csrf_token"`

	// Method to use
	//
	// This field must be set to `saml` when using the saml method.
	//
	// required: true
	Method string `json:"method"`

	// The identity traits. This is a placeholder for the registration flow.
	Traits json.RawMessage `json:"traits"`
}

// Login and give a session to the user
func (s *Strategy) processLogin(w http.ResponseWriter, r *http.Request, a *login.Flow, provider Provider, claims *Claims) (*registration.Flow, error) {
	// If the user's ID is null, we have to handle error
	if claims.Subject == "" {
		return nil, s.handleError(w, r, a, provider.Config().ID, nil, errors.New("the user ID is empty: the problem probably comes from the mapping between the SAML attributes and the identity attributes"))
	}

	// This is a check to see if the user exists in the database
	i, c, err := s.d.PrivilegedIdentityPool().FindByCredentialsIdentifier(r.Context(), identity.CredentialsTypeSAML, identity.SAMLUniqueID(provider.Config().ID, claims.Subject))

	if err != nil {
		// ErrNoRows is returned when a SQL SELECT statement returns no rows.
		if errors.Is(err, sqlcon.ErrNoRows) {
			if config, err := s.Config(r.Context()); err != nil {
				return nil, s.handleError(w, r, a, provider.Config().ID, nil, err)
			} else if !config.AutoRegister {
				return nil, s.handleError(w, r, a, provider.Config().ID, nil, NewErrorValidationLoginIdentityNotFound())
			}

			// The user doesn't exist yet so we register him

			// If return_to was set before, we need to preserve it.
			var opts []registration.FlowOption
			if len(a.ReturnTo) > 0 {
				opts = append(opts, registration.WithFlowReturnTo(a.ReturnTo))
			}

			registerFlow, err := s.d.RegistrationHandler().NewRegistrationFlow(w, r, a.Type, opts...)
			if err != nil {
				return nil, s.handleError(w, r, a, provider.Config().ID, nil, err)
			}

			err = s.d.SessionTokenExchangePersister().MoveToNewFlow(r.Context(), a.ID, registerFlow.ID)
			if err != nil {
				return nil, s.handleError(w, r, a, provider.Config().ID, nil, err)
			}

			if err = s.processRegistration(w, r, registerFlow, provider, claims); err != nil {
				return registerFlow, err
			}

			return registerFlow, nil

		} else {
			return nil, err
		}
	}

	err = s.updateIdentityTraits(w, r, i, provider, claims)
	if err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, i.Traits, err)
	}

	var o identity.CredentialsSAML
	if err := json.NewDecoder(bytes.NewBuffer(c.Config)).Decode(&o); err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, nil, errors.WithStack(herodot.ErrInternalServerError.WithReason("The SAML credentials could not be decoded properly").WithDebug(err.Error())))
	}

	sess := session.NewInactiveSession() // Creation of an inactive session
	sess.CompletedLoginForWithProvider(s.ID(), identity.AuthenticatorAssuranceLevel1, provider.Config().ID,
		httprouter.ParamsFromContext(r.Context()).ByName("organization")) // Add saml to the Authentication Method References

	if err := s.d.LoginHookExecutor().PostLoginHook(w, r, node.SAMLGroup, a, i, sess, provider.Config().ID); err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, nil, err)
	}

	return nil, nil
}

func (s *Strategy) Login(w http.ResponseWriter, r *http.Request, f *login.Flow, _ *session.Session) (*identity.Identity, error) {
	if err := login.CheckAAL(f, identity.AuthenticatorAssuranceLevel1); err != nil {
		return nil, err
	}

	var p SubmitSelfServiceLoginFlowWithSAMLMethodBody
	if err := s.newLinkDecoder(&p, r); err != nil {
		return nil, s.handleError(w, r, f, "", nil, errors.WithStack(herodot.ErrBadRequest.WithDebug(err.Error()).WithReasonf("Unable to parse HTTP form request: %s", err.Error())))
	}

	var pid = p.Provider // This can come from both url query and post body
	if pid == "" {
		return nil, errors.WithStack(flow.ErrStrategyNotResponsible)
	}

	if x.IsJSONRequest(r) {
		url := urlx.AppendPaths(s.d.Config().SelfPublicURL(r.Context()), RouteBaseAuth+"/"+pid)
		v := url.Query()
		v.Set("flow", f.ID.String())
		url.RawQuery = v.Encode()
		s.d.Writer().WriteError(w, r, flow.NewBrowserLocationChangeRequiredError(url.String()))
		return nil, flow.ErrCompletedByStrategy
	}

	_, err := s.validateFlow(r.Context(), r, f.ID)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if err := s.doLogin(w, r, f, pid); err != nil {
		return nil, s.handleError(w, r, f, pid, nil, err)
	}

	return nil, flow.ErrCompletedByStrategy
}

func (s *Strategy) doLogin(w http.ResponseWriter, r *http.Request, f *login.Flow, pid string) error {
	if err := flow.MethodEnabledAndAllowed(r.Context(), f.GetFlowName(), s.ID().String(), s.ID().String(), s.d); err != nil {
		return err
	}

	providersConfigCollection, err := GetProvidersConfigCollection(r.Context(), s.d.Config())
	if err != nil {
		return err
	}
	_, err = providersConfigCollection.ProviderConfig(pid)
	if err != nil {
		return err
	}

	if s.alreadyAuthenticated(w, r, f) {
		return err
	}

	if err := s.startSAMLFlow(w, r, f, pid); err != nil {
		return err
	}

	f.Active = s.ID()
	if err = s.d.LoginFlowPersister().UpdateLoginFlow(r.Context(), f); err != nil {
		return errors.WithStack(herodot.ErrInternalServerError.WithReason("Could not update flow").WithDebug(err.Error()))
	}
	return nil
}

func (s *Strategy) RegisterAdminLoginRoutes(r *x.RouterAdmin) {
	s.setAdminRoutes(r)
}

func (s *Strategy) PopulateLoginMethod(r *http.Request, requestedAAL identity.AuthenticatorAssuranceLevel, l *login.Flow) error {
	// This strategy can only solve AAL1
	if requestedAAL > identity.AuthenticatorAssuranceLevel1 {
		return nil
	}

	return s.populateMethod(r, l.UI, text.NewInfoLoginWith)
}

// In order to do a JustInTimeProvisioning, it is important to update the identity traits at each new SAML connection
func (s *Strategy) updateIdentityTraits(w http.ResponseWriter, r *http.Request, i *identity.Identity, provider Provider, claims *Claims) error {

	var jsonClaims bytes.Buffer
	if err := json.NewEncoder(&jsonClaims).Encode(claims); err != nil {
		return err
	}

	if err := s.setTraits(w, r, claims, provider, jsonClaims, i); err != nil {
		return err
	}

	return nil
}
