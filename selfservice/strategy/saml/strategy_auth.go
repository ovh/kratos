package saml

import (
	"errors"
	"github.com/ory/kratos/selfservice/flow/registration"
	"net/http"

	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/x/sqlcon"
)

// Handle SAML Assertion and process to either login or register
func (s *Strategy) processLoginOrRegister(w http.ResponseWriter, r *http.Request, loginFlow *login.Flow, provider Provider, claims *Claims) error {

	// If the user's ID is null, we have to handle error
	if claims.Subject == "" {
		return s.handleError(w, r, loginFlow, provider.Config().ID, nil, errors.New("the user ID is empty: the problem probably comes from the mapping between the SAML attributes and the identity attributes"))
	}

	// This is a check to see if the user exists in the database
	i, c, err := s.d.PrivilegedIdentityPool().FindByCredentialsIdentifier(r.Context(), identity.CredentialsTypeSAML, identity.SAMLUniqueID(provider.Config().ID, claims.Subject))

	if err != nil {
		// ErrNoRows is returned when a SQL SELECT statement returns no rows.
		if errors.Is(err, sqlcon.ErrNoRows) {

			// The user doesn't exist yet so we register him

			// If return_to was set before, we need to preserve it.
			var opts []registration.FlowOption
			if len(loginFlow.ReturnTo) > 0 {
				opts = append(opts, registration.WithFlowReturnTo(loginFlow.ReturnTo))
			}

			registerFlow, err := s.d.RegistrationHandler().NewRegistrationFlow(w, r, loginFlow.Type, opts...)
			if err != nil {
				return s.handleError(w, r, loginFlow, provider.Config().ID, nil, err)
			}

			err = s.d.SessionTokenExchangePersister().MoveToNewFlow(r.Context(), loginFlow.ID, registerFlow.ID)
			if err != nil {
				return s.handleError(w, r, loginFlow, provider.Config().ID, nil, err)
			}

			if err = s.processRegistration(w, r, registerFlow, provider, claims); err != nil {
				return err
			}

			return nil

		} else {
			return err
		}
	} else {
		// The user already exist in database, so we log him
		if _, err = s.processLogin(w, r, loginFlow, provider, c, i, claims); err != nil {
			return s.handleError(w, r, loginFlow, provider.Config().ID, i.Traits, err)
		}
		return nil
	}
}
