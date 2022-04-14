package strategy

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/ory/herodot"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/kratos/selfservice/flow/registration"
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
	return nil, nil
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
