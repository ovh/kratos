package strategy

import (
	"errors"
	"net/http"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	samlsp "github.com/ory/kratos/selfservice/strategy/saml"
	"github.com/ory/x/sqlcon"
)

//#################
// This file is called when the /ACS receives an assertion, the method below allows you to define whether to register or login the user indicated in the assertion
//#################

// Handle SAML Assertion and process to either login or register
func (s *Strategy) processLoginOrRegister(w http.ResponseWriter, r *http.Request, provider samlsp.Provider, claims *samlsp.Claims) (*flow.Flow, error) {

	// This is a check to see if the user exists in the database
	i, c, err := s.d.PrivilegedIdentityPool().FindByCredentialsIdentifier(r.Context(), identity.CredentialsTypeSAML, uid(provider.Config().ID, claims.Subject))

	if err != nil {
		// ErrNoRows is returned when a SQL SELECT statement returns no rows.
		if errors.Is(err, sqlcon.ErrNoRows) {

			// The user doesn't net existe yet so we register him
			registerFlow, err := s.d.RegistrationHandler().NewRegistrationFlow(w, r, flow.TypeBrowser)
			if err != nil {
				return nil, s.handleError(w, r, registerFlow, provider.Config().ID, i.Traits, err)
			}

			if err = s.processRegistration(w, r, registerFlow, provider, claims); err != nil {
				return nil, s.handleError(w, r, registerFlow, provider.Config().ID, i.Traits, err)
			}

			return nil, nil

		} else {
			return nil, err
		}
	} else {
		// The user already exist in database so we log him
		loginFlow, err := s.d.LoginHandler().NewLoginFlow(w, r, flow.TypeBrowser)
		if err != nil {
			return nil, s.handleError(w, r, loginFlow, provider.Config().ID, i.Traits, err)
		}
		if _, err = s.processLogin(w, r, loginFlow, provider, c, i, claims); err != nil {
			return nil, s.handleError(w, r, loginFlow, provider.Config().ID, i.Traits, err)
		}
		return nil, nil
	}
}
