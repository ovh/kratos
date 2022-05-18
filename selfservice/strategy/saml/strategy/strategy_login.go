package strategy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ory/herodot"
	"github.com/ory/kratos/continuity"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/flow/registration"
	handler "github.com/ory/kratos/selfservice/flow/saml"
	samlsp "github.com/ory/kratos/selfservice/strategy/saml"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/text"
	"github.com/ory/kratos/x"
	"github.com/pkg/errors"
)

//#################
// This file contains all the methods and functions allowing the login of a user.
//#################

// Implement the interface
var _ login.Strategy = new(Strategy)

//Call at the creation of Kratos, when Kratos implement all authentication routes
func (s *Strategy) RegisterLoginRoutes(r *x.RouterPublic) {
	s.setRoutes(r)
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
	// This field must be set to `oidc` when using the oidc method.
	//
	// required: true
	Method string `json:"method"`

	// The identity traits. This is a placeholder for the registration flow.
	Traits json.RawMessage `json:"traits"`
}

//Login and give a session to the user
func (s *Strategy) processLogin(w http.ResponseWriter, r *http.Request, a *login.Flow, provider samlsp.Provider, c *identity.Credentials, i *identity.Identity, claims *samlsp.Claims) (*registration.Flow, error) {

	var o CredentialsConfig
	if err := json.NewDecoder(bytes.NewBuffer(c.Config)).Decode(&o); err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, nil, errors.WithStack(herodot.ErrInternalServerError.WithReason("The password credentials could not be decoded properly").WithDebug(err.Error())))
	}

	sess := session.NewInactiveSession()                                  //creation of an inactive session
	sess.CompletedLoginFor(s.ID(), identity.AuthenticatorAssuranceLevel1) //Add saml to the Authentication Method References

	if err := s.d.LoginHookExecutor().PostLoginHook(w, r, a, i, sess); err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, nil, err)
	}

	return nil, nil
}

// Method not used but necessary to implement the interface
func (s *Strategy) Login(w http.ResponseWriter, r *http.Request, f *login.Flow, ss *session.Session) (i *identity.Identity, err error) {
	if err := login.CheckAAL(f, identity.AuthenticatorAssuranceLevel1); err != nil {
		return nil, err
	}

	var p SubmitSelfServiceLoginFlowWithSAMLMethodBody
	if err := s.newLinkDecoder(&p, r); err != nil {
		return nil, s.handleError(w, r, f, "", nil, errors.WithStack(herodot.ErrBadRequest.WithDebug(err.Error()).WithReasonf("Unable to parse HTTP form request: %s", err.Error())))
	}

	var pid = p.Provider // this can come from both url query and post body
	if pid == "" {
		return nil, errors.WithStack(flow.ErrStrategyNotResponsible)
	}

	if err := flow.MethodEnabledAndAllowed(r.Context(), s.ID().String(), s.ID().String(), s.d); err != nil {
		return nil, s.handleError(w, r, f, pid, nil, err)
	}

	req, err := s.validateFlow(r.Context(), r, f.ID)
	if err != nil {
		return nil, s.handleError(w, r, f, pid, nil, err)
	}

	if s.alreadyAuthenticated(w, r, req) {
		return
	}

	state := x.NewUUID().String()
	if err := s.d.ContinuityManager().Pause(r.Context(), w, r, sessionName,
		continuity.WithPayload(&authCodeContainer{
			State:  state,
			FlowID: f.ID.String(),
			Traits: p.Traits,
		}),
		continuity.WithLifespan(time.Minute*30)); err != nil {
		return nil, s.handleError(w, r, f, pid, nil, err)
	}

	f.Active = s.ID()
	if err = s.d.LoginFlowPersister().UpdateLoginFlow(r.Context(), f); err != nil {
		return nil, s.handleError(w, r, f, pid, nil, errors.WithStack(herodot.ErrInternalServerError.WithReason("Could not update flow").WithDebug(err.Error())))
	}

	if x.IsJSONRequest(r) {
		s.d.Writer().WriteError(w, r, flow.NewBrowserLocationChangeRequiredError(handler.RouteSamlLoginInit))
	} else {
		http.Redirect(w, r, handler.RouteSamlLoginInit, http.StatusSeeOther)
	}

	return nil, errors.WithStack(flow.ErrCompletedByStrategy)
}

// Method not used but necessary to implement the interface
func (s *Strategy) PopulateLoginMethod(r *http.Request, requestedAAL identity.AuthenticatorAssuranceLevel, l *login.Flow) error {
	if l.Type != flow.TypeBrowser {
		return nil
	}

	// This strategy can only solve AAL1
	if requestedAAL > identity.AuthenticatorAssuranceLevel1 {
		return nil
	}

	return s.populateMethod(r, l.UI, text.NewInfoLoginWith)
}
