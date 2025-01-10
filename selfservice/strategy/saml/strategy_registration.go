package saml

import (
	"bytes"
	"encoding/json"
	"github.com/ory/herodot"
	"github.com/ory/kratos/selfservice/flow/login"
	"github.com/ory/x/otelx"
	"github.com/ory/x/urlx"
	"net/http"

	"github.com/pkg/errors"

	"github.com/ory/kratos/identity"
	"github.com/ory/x/decoderx"

	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/registration"
	"github.com/ory/kratos/text"

	"github.com/tidwall/sjson"

	"github.com/ory/kratos/x"
)

// Implement the interface
var _ registration.Strategy = new(Strategy)

// Call at the creation of Kratos, when Kratos implement all authentication routes
func (s *Strategy) RegisterRegistrationRoutes(r *x.RouterPublic) {
	s.setRoutes(r)
}

func (s *Strategy) createIdentity(w http.ResponseWriter, r *http.Request, a *registration.Flow, claims *Claims, provider Provider) (*identity.Identity, error) {
	var jsonClaims bytes.Buffer
	if err := json.NewEncoder(&jsonClaims).Encode(claims); err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, nil, err)
	}

	i := identity.NewIdentity(s.d.Config().DefaultIdentityTraitsSchemaID(r.Context()))
	if err := s.setTraits(w, r, claims, provider, jsonClaims, i); err != nil {
		return nil, s.handleError(w, r, a, provider.Config().ID, i.Traits, err)
	}

	s.d.Logger().
		WithRequest(r).
		WithField("saml_provider", provider.Config().ID).
		WithSensitiveField("saml_claims", claims).
		Debug("SAML Connect completed.")
	return i, nil
}

func (s *Strategy) setTraits(w http.ResponseWriter, r *http.Request, claims *Claims, provider Provider, jsonClaims bytes.Buffer, i *identity.Identity) error {

	traitsMap := make(map[string]interface{})
	json.Unmarshal(jsonClaims.Bytes(), &traitsMap)
	delete(traitsMap, "iss")
	delete(traitsMap, "email_verified")
	delete(traitsMap, "sub")
	traits, err := json.Marshal(traitsMap)
	if err != nil {
		return err
	}
	i.Traits = identity.Traits(traits)

	s.d.Logger().
		WithRequest(r).
		WithField("oidc_provider", provider.Config().ID).
		WithSensitiveField("identity_traits", i.Traits).
		WithField("mapper_jsonnet_url", provider.Config().Mapper).
		Debug("Merged form values and OpenID Connect Jsonnet output.")
	return nil
}

func (s *Strategy) registrationToLogin(w http.ResponseWriter, r *http.Request, rf *registration.Flow, providerID string) (*login.Flow, error) {
	// If return_to was set before, we need to preserve it.
	var opts []login.FlowOption
	if len(rf.ReturnTo) > 0 {
		opts = append(opts, login.WithFlowReturnTo(rf.ReturnTo))
	}

	if len(rf.UI.Messages) > 0 {
		opts = append(opts, login.WithFormErrorMessage(rf.UI.Messages))
	}

	opts = append(opts, login.WithInternalContext(rf.InternalContext))

	lf, _, err := s.d.LoginHandler().NewLoginFlow(w, r, rf.Type, opts...)
	if err != nil {
		return nil, err
	}

	csrfToken := s.d.CSRFHandler().RegenerateToken(w, r)
	lf.UI.SetCSRF(csrfToken)
	lf.CSRFToken = csrfToken
	if err := s.d.LoginFlowPersister().UpdateLoginFlow(r.Context(), lf); err != nil {
		return nil, err
	}

	err = s.d.SessionTokenExchangePersister().MoveToNewFlow(r.Context(), rf.ID, lf.ID)
	if err != nil {
		return nil, err
	}

	lf.RequestURL, err = x.TakeOverReturnToParameter(rf.RequestURL, lf.RequestURL)
	if err != nil {
		return nil, err
	}

	return lf, nil
}

func (s *Strategy) processRegistration(w http.ResponseWriter, r *http.Request, a *registration.Flow, provider Provider, claims *Claims) error {
	if _, _, err := s.d.PrivilegedIdentityPool().FindByCredentialsIdentifier(r.Context(), identity.CredentialsTypeSAML, identity.SAMLUniqueID(provider.Config().ID, claims.Subject)); err == nil {
		// If the identity already exists, we should perform the login flow instead.

		s.d.Logger().WithRequest(r).WithField("provider", provider.Config().ID).
			WithField("subject", claims.Subject).
			Debug("Received successful SAML callback but user is already registered. Re-initializing login flow now.")

		lf, err := s.registrationToLogin(w, r, a, provider.Config().ID)
		if err != nil {
			return s.handleError(w, r, a, provider.Config().ID, nil, err)
		}

		if _, err := s.processLogin(w, r, lf, provider, claims); err != nil {
			return s.handleError(w, r, a, provider.Config().ID, nil, err)
		}

		return nil
	}

	i, err := s.createIdentity(w, r, a, claims, provider)
	if err != nil {
		return s.handleError(w, r, a, provider.Config().ID, nil, err)
	}

	// Verify the identity
	if err := s.d.IdentityValidator().Validate(r.Context(), i); err != nil {
		return s.handleError(w, r, a, provider.Config().ID, nil, err)
	}

	// Create new uniq credentials identifier for user is database
	creds, err := identity.NewCredentialsSAML(claims.Subject, provider.Config().ID)
	if err != nil {
		return s.handleError(w, r, a, provider.Config().ID, nil, err)
	}

	// Set the identifiers to the identity
	i.SetCredentials(s.ID(), *creds)
	if err := s.d.RegistrationExecutor().PostRegistrationHook(w, r, identity.CredentialsTypeSAML, provider.Config().ID, a, i); err != nil {
		return s.handleError(w, r, a, provider.Config().ID, i.Traits, err)
	}

	return nil
}

// Method not used but necessary to implement the interface
func (s *Strategy) PopulateRegistrationMethod(r *http.Request, f *registration.Flow) error {
	return s.populateMethod(r, f.UI, text.NewInfoRegistrationWith)
}

func (s *Strategy) newLinkDecoder(p interface{}, r *http.Request) error {
	ds, err := s.d.Config().DefaultIdentityTraitsSchemaURL(r.Context())
	if err != nil {
		return err
	}

	raw, err := sjson.SetBytes(linkSchema, "properties.traits.$ref", ds.String()+"#/properties/traits")
	if err != nil {
		return errors.WithStack(err)
	}

	compiler, err := decoderx.HTTPRawJSONSchemaCompiler(raw)
	if err != nil {
		return errors.WithStack(err)
	}

	if err := s.dec.Decode(r, &p, compiler,
		decoderx.HTTPKeepRequestBody(true),
		decoderx.HTTPDecoderSetValidatePayloads(false),
		decoderx.HTTPDecoderUseQueryAndBody(),
		decoderx.HTTPDecoderAllowedMethods("POST", "GET"),
		decoderx.HTTPDecoderJSONFollowsFormFormat(),
	); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// SubmitSelfServiceRegistrationFlowWithSAMLMethodBody is used to decode the registration form payload
// when using the saml method.
//
// swagger:model SubmitSelfServiceRegistrationFlowWithSAMLMethodBody
type SubmitSelfServiceRegistrationFlowWithSAMLMethodBody struct {
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
}

func (s *Strategy) Register(w http.ResponseWriter, r *http.Request, f *registration.Flow, i *identity.Identity) (err error) {
	ctx, span := s.d.Tracer(r.Context()).Tracer().Start(r.Context(), "selfservice.strategy.saml.strategy.Register")
	defer otelx.End(span, &err)

	var p SubmitSelfServiceRegistrationFlowWithSAMLMethodBody
	if err := s.newLinkDecoder(&p, r); err != nil {
		return s.handleError(w, r, f, "", nil, errors.WithStack(herodot.ErrBadRequest.WithDebug(err.Error()).WithReasonf("Unable to parse HTTP form request: %s", err.Error())))
	}

	var pid = p.Provider // This can come from both url query and post body
	if pid == "" {
		return errors.WithStack(flow.ErrStrategyNotResponsible)
	}

	if x.IsJSONRequest(r) {
		url := urlx.AppendPaths(s.d.Config().SelfPublicURL(ctx), RouteBaseAuth+"/"+pid)
		v := url.Query()
		v.Set("flow", f.ID.String())
		url.RawQuery = v.Encode()
		s.d.Writer().WriteError(w, r, flow.NewBrowserLocationChangeRequiredError(url.String()))
		return flow.ErrCompletedByStrategy
	}

	if err := flow.MethodEnabledAndAllowed(ctx, f.GetFlowName(), s.ID().String(), s.ID().String(), s.d); err != nil {
		return err
	}

	providersConfigCollection, err := GetProvidersConfigCollection(ctx, s.d.Config())
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
	if err = s.d.RegistrationFlowPersister().UpdateRegistrationFlow(ctx, f); err != nil {
		return errors.WithStack(herodot.ErrInternalServerError.WithReason("Could not update flow").WithDebug(err.Error()))
	}
	return nil
}
