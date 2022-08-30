package saml

import (
	"context"
	_ "embed"
	"encoding/json"
	"github.com/gofrs/uuid"
	"github.com/ory/herodot"
	"github.com/ory/jsonschema/v3"
	"github.com/ory/kratos/continuity"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/kratos/selfservice/strategy"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
	"github.com/ory/x/decoderx"
	"github.com/ory/x/sqlxx"
	"github.com/ory/x/urlx"
	"github.com/pkg/errors"
	"github.com/tidwall/sjson"
	"net/http"
	"time"
)

//go:embed .schema/settings.schema.json
var settingsSchema []byte

var UnknownConnectionValidationError = &jsonschema.ValidationError{
	Message: "can not unlink non-existing SAML connection", InstancePtr: "#/"}
var ConnectionExistValidationError = &jsonschema.ValidationError{
	Message: "can not link unknown or already existing SAML connection", InstancePtr: "#/"}

func (s *Strategy) SettingsStrategyID() string {
	return s.ID().String()
}

//goland:noinspection GoUnusedParameter
func (s *Strategy) RegisterSettingsRoutes(router *x.RouterPublic) {}

func (s *Strategy) linkedProviders(ctx context.Context, r *http.Request, conf *ConfigurationCollection, confidential *identity.Identity) ([]Provider, error) {
	creds, ok := confidential.GetCredentials(s.ID())
	if !ok {
		return nil, nil
	}

	var available identity.CredentialsSAML
	if err := json.Unmarshal(creds.Config, &available); err != nil {
		return nil, errors.WithStack(err)
	}

	count, err := s.d.IdentityManager().CountActiveFirstFactorCredentials(ctx, confidential)
	if err != nil {
		return nil, err
	}

	if count < 2 {
		// This means that we're not able to remove a connection because it is the last configured credential. If it is
		// removed, the identity is no longer able to sign in.
		return nil, nil
	}

	var result []Provider
	for _, p := range available.Providers {
		prov, err := conf.Provider(p.Provider, s.d)
		if err != nil {
			return nil, err
		}
		result = append(result, prov)
	}

	return result, nil
}

func (s *Strategy) PopulateSettingsMethod(r *http.Request, id *identity.Identity, sr *settings.Flow) error {
	if sr.Type != flow.TypeBrowser {
		return nil
	}

	conf, err := s.Config(r.Context())
	if err != nil {
		return err
	}

	confidential, err := s.d.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), id.ID)
	if err != nil {
		return err
	}

	linked, err := s.linkedProviders(r.Context(), r, conf, confidential)
	if err != nil {
		return err
	}

	sr.UI.GetNodes().Remove("samlUnlink", "samlLink")
	sr.UI.SetCSRF(s.d.GenerateCSRFToken(r))
	if len(conf.SAMLProviders) > 0 {
		sr.UI.GetNodes().Append(NewLinkNode())
	}

	for _, l := range linked {
		sr.UI.GetNodes().Append(NewUnlinkNode(l.Config().ID))
	}

	return nil
}

// Update Settings Flow with SAML Method
//
// nolint:deadcode,unused
// swagger:model updateSettingsFlowWithSAMLMethod
type updateSettingsFlowWithSAMLMethod struct {
	// Method
	//
	// Should be set to profile when trying to update a profile.
	//
	// required: true
	Method string `json:"method"`

	// Link this provider
	//
	// Either this or `unlink` must be set.
	//
	// type: string
	// in: body
	Link string `json:"samlLink"`

	// Unlink this provider
	//
	// Either this or `link` must be set.
	//
	// type: string
	// in: body
	Unlink string `json:"samlUnlink"`

	// Flow ID is the flow's ID.
	//
	// in: query
	FlowID string `json:"flow"`

	// The identity's traits
	//
	// in: body
	Traits json.RawMessage `json:"traits"`
}

func (s *Strategy) decodeSettings(p *updateSettingsFlowWithSAMLMethod, r *http.Request) error {
	ds, err := s.d.Config().DefaultIdentityTraitsSchemaURL(r.Context())
	if err != nil {
		return err
	}
	raw, err := sjson.SetBytes(settingsSchema,
		"properties.traits.$ref", ds.String()+"#/properties/traits")
	if err != nil {
		return errors.WithStack(err)
	}

	compiler, err := decoderx.HTTPRawJSONSchemaCompiler(raw)
	if err != nil {
		return errors.WithStack(err)
	}

	if err := s.dec.Decode(r, &p, compiler,
		decoderx.HTTPKeepRequestBody(true),
		decoderx.HTTPDecoderUseQueryAndBody(),
		decoderx.HTTPDecoderSetValidatePayloads(false),
		decoderx.HTTPDecoderAllowedMethods("POST", "GET"),
		decoderx.HTTPDecoderJSONFollowsFormFormat()); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (p *updateSettingsFlowWithSAMLMethod) GetFlowID() uuid.UUID {
	return x.ParseUUID(p.FlowID)
}

func (p *updateSettingsFlowWithSAMLMethod) SetFlowID(rid uuid.UUID) {
	p.FlowID = rid.String()
}

func (s *Strategy) Settings(w http.ResponseWriter, r *http.Request, f *settings.Flow, ss *session.Session) (*settings.UpdateContext, error) {
	var p updateSettingsFlowWithSAMLMethod
	if err := s.decodeSettings(&p, r); err != nil {
		return nil, err
	}

	ctxUpdate, err := settings.PrepareUpdate(s.d, w, r, f, ss, settings.ContinuityKey(s.SettingsStrategyID()), &p)
	if errors.Is(err, settings.ErrContinuePreviousAction) {
		if !s.d.Config().SelfServiceStrategy(r.Context(), s.SettingsStrategyID()).Enabled {
			return nil, errors.WithStack(herodot.ErrNotFound.WithReason(strategy.EndpointDisabledMessage))
		}

		if l := len(p.Link); l > 0 {
			if err := s.initLinkProvider(w, r, ctxUpdate, &p); err != nil {
				return nil, err
			}

			return ctxUpdate, nil
		} else if u := len(p.Unlink); u > 0 {
			if err := s.unlinkProvider(w, r, ctxUpdate, &p); err != nil {
				return nil, err
			}

			return ctxUpdate, nil
		}

		return nil, s.handleSettingsError(w, r, ctxUpdate, &p, errors.WithStack(herodot.ErrInternalServerError.WithReason("Expected either link or unlink to be set when continuing flow but both are unset.")))
	} else if err != nil {
		return nil, s.handleSettingsError(w, r, ctxUpdate, &p, err)
	}

	if len(p.Link+p.Unlink) == 0 {
		return nil, errors.WithStack(flow.ErrStrategyNotResponsible)
	}

	if !s.d.Config().SelfServiceStrategy(r.Context(), s.SettingsStrategyID()).Enabled {
		return nil, errors.WithStack(herodot.ErrNotFound.WithReason(strategy.EndpointDisabledMessage))
	}

	if l, u := len(p.Link), len(p.Unlink); l > 0 && u > 0 {
		return nil, s.handleSettingsError(w, r, ctxUpdate, &p, errors.WithStack(&jsonschema.ValidationError{
			Message:     "it is not possible to link and unlink providers in the same request",
			InstancePtr: "#/",
		}))
	} else if l > 0 {
		if err := s.initLinkProvider(w, r, ctxUpdate, &p); err != nil {
			return nil, err
		}
		return ctxUpdate, nil
	} else if u > 0 {
		if err := s.unlinkProvider(w, r, ctxUpdate, &p); err != nil {
			return nil, err
		}

		return ctxUpdate, nil
	}

	return nil, s.handleSettingsError(w, r, ctxUpdate, &p, errors.WithStack(errors.WithStack(&jsonschema.ValidationError{
		Message: "missing properties: link, unlink", InstancePtr: "#/",
		Context: &jsonschema.ValidationErrorContextRequired{Missing: []string{"link", "unlink"}}})))
}

func (s *Strategy) isLinkable(r *http.Request, ctxUpdate *settings.UpdateContext, toLink string) (*identity.Identity, error) {
	providers, err := s.Config(r.Context())
	if err != nil {
		return nil, err
	}

	i, err := s.d.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), ctxUpdate.Session.Identity.ID)
	if err != nil {
		return nil, err
	}

	linkable, err := s.linkableProviders(r.Context(), r, providers, i)
	if err != nil {
		return nil, err
	}

	var found bool
	for _, available := range linkable {
		if toLink == available.Config().ID {
			found = true
		}
	}

	if !found {
		return nil, errors.WithStack(ConnectionExistValidationError)
	}

	return i, nil
}

func (s *Strategy) linkableProviders(ctx context.Context, r *http.Request, conf *ConfigurationCollection, confidential *identity.Identity) ([]Provider, error) {
	var available identity.CredentialsSAML
	creds, ok := confidential.GetCredentials(s.ID())
	if ok {
		if err := json.Unmarshal(creds.Config, &available); err != nil {
			return nil, errors.WithStack(err)
		}
	}

	var result []Provider
	for _, p := range conf.SAMLProviders {
		var found bool
		for _, pp := range available.Providers {
			if pp.Provider == p.ID {
				found = true
				break
			}
		}

		if !found {
			prov, err := conf.Provider(p.ID, s.d)
			if err != nil {
				return nil, err
			}
			result = append(result, prov)
		}
	}

	return result, nil
}

func (s *Strategy) initLinkProvider(w http.ResponseWriter, r *http.Request, ctxUpdate *settings.UpdateContext, p *updateSettingsFlowWithSAMLMethod) error {
	if _, err := s.isLinkable(r, ctxUpdate, p.Link); err != nil {
		return s.handleSettingsError(w, r, ctxUpdate, p, err)
	}

	if ctxUpdate.Session.AuthenticatedAt.Add(s.d.Config().SelfServiceFlowSettingsPrivilegedSessionMaxAge(r.Context())).Before(time.Now()) {
		return s.handleSettingsError(w, r, ctxUpdate, p, errors.WithStack(settings.NewFlowNeedsReAuth()))
	}

	_, err := s.validateFlow(r.Context(), r, ctxUpdate.Flow.ID)
	if err != nil {
		return s.handleSettingsError(w, r, ctxUpdate, p, err)
	}

	state := generateState(ctxUpdate.Flow.ID.String())
	if err := s.d.ContinuityManager().Pause(r.Context(), w, r, sessionName,
		continuity.WithPayload(&authCodeContainer{
			State:  state,
			FlowID: ctxUpdate.Flow.ID.String(),
			Traits: p.Traits,
		}),
		continuity.WithLifespan(time.Minute*30)); err != nil {
		return s.handleSettingsError(w, r, ctxUpdate, p, err)
	}

	if x.IsJSONRequest(r) {
		s.d.Writer().WriteError(w, r, flow.NewBrowserLocationChangeRequiredError(
			urlx.AppendPaths(s.d.Config().SelfPublicURL(r.Context()), RouteBaseAuth+"/"+p.Link).String()))
	} else {
		http.Redirect(w, r,
			urlx.AppendPaths(s.d.Config().SelfPublicURL(r.Context()), RouteBaseAuth+"/"+p.Link).String(), http.StatusSeeOther)
	}

	return errors.WithStack(flow.ErrCompletedByStrategy)
}

func (s *Strategy) linkProvider(w http.ResponseWriter, r *http.Request, ctxUpdate *settings.UpdateContext, claims *Claims, provider Provider) error {
	p := &updateSettingsFlowWithSAMLMethod{
		Link: provider.Config().ID, FlowID: ctxUpdate.Flow.ID.String()}
	if ctxUpdate.Session.AuthenticatedAt.Add(s.d.Config().SelfServiceFlowSettingsPrivilegedSessionMaxAge(r.Context())).Before(time.Now()) {
		return s.handleSettingsError(w, r, ctxUpdate, p, errors.WithStack(settings.NewFlowNeedsReAuth()))
	}

	i, err := s.isLinkable(r, ctxUpdate, p.Link)
	if err != nil {
		return s.handleSettingsError(w, r, ctxUpdate, p, err)
	}

	if err := s.linkCredentials(r.Context(), i, provider.Config().ID, claims.Subject); err != nil {
		return s.handleSettingsError(w, r, ctxUpdate, p, err)
	}

	if err := s.d.SettingsHookExecutor().PostSettingsHook(w, r, s.SettingsStrategyID(), ctxUpdate, i, settings.WithCallback(func(ctxUpdate *settings.UpdateContext) error {
		return s.PopulateSettingsMethod(r, ctxUpdate.Session.Identity, ctxUpdate.Flow)
	})); err != nil {
		return s.handleSettingsError(w, r, ctxUpdate, p, err)
	}

	return nil
}

func (s *Strategy) linkCredentials(ctx context.Context, i *identity.Identity, provider, subject string) error {
	if i.Credentials == nil {
		confidential, err := s.d.PrivilegedIdentityPool().GetIdentityConfidential(ctx, i.ID)
		if err != nil {
			return err
		}
		i.Credentials = confidential.Credentials
	}
	var conf identity.CredentialsSAML
	creds, err := i.ParseCredentials(s.ID(), &conf)
	if errors.Is(err, herodot.ErrNotFound) {
		var err error
		if creds, err = identity.NewCredentialsSAML(subject, provider); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		creds.Identifiers = append(creds.Identifiers, identity.SAMLUniqueID(provider, subject))
		conf.Providers = append(conf.Providers, identity.CredentialsSAMLProvider{
			Subject: subject, Provider: provider,
		})

		creds.Config, err = json.Marshal(conf)
		if err != nil {
			return err
		}
	}

	i.Credentials[s.ID()] = *creds
	return nil
}

func (s *Strategy) unlinkProvider(w http.ResponseWriter, r *http.Request, ctxUpdate *settings.UpdateContext, p *updateSettingsFlowWithSAMLMethod) error {
	if ctxUpdate.Session.AuthenticatedAt.Add(s.d.Config().SelfServiceFlowSettingsPrivilegedSessionMaxAge(r.Context())).Before(time.Now()) {
		return s.handleSettingsError(w, r, ctxUpdate, p, errors.WithStack(settings.NewFlowNeedsReAuth()))
	}

	providers, err := s.Config(r.Context())
	if err != nil {
		return s.handleSettingsError(w, r, ctxUpdate, p, err)
	}

	i, err := s.d.PrivilegedIdentityPool().GetIdentityConfidential(r.Context(), ctxUpdate.Session.Identity.ID)
	if err != nil {
		return s.handleSettingsError(w, r, ctxUpdate, p, err)
	}

	availableProviders, err := s.linkedProviders(r.Context(), r, providers, i)
	if err != nil {
		return s.handleSettingsError(w, r, ctxUpdate, p, err)
	}

	var cc identity.CredentialsSAML
	creds, err := i.ParseCredentials(s.ID(), &cc)
	if err != nil {
		return s.handleSettingsError(w, r, ctxUpdate, p, errors.WithStack(UnknownConnectionValidationError))
	}

	var found bool
	var updatedProviders []identity.CredentialsSAMLProvider
	var updatedIdentifiers []string
	for _, available := range availableProviders {
		if p.Unlink == available.Config().ID {
			for _, link := range cc.Providers {
				if link.Provider != p.Unlink {
					updatedIdentifiers = append(updatedIdentifiers, identity.SAMLUniqueID(link.Provider, link.Subject))
					updatedProviders = append(updatedProviders, link)
				} else {
					found = true
				}
			}
		}
	}

	if !found {
		return s.handleSettingsError(w, r, ctxUpdate, p, errors.WithStack(UnknownConnectionValidationError))
	}

	creds.Identifiers = updatedIdentifiers
	creds.Config, err = json.Marshal(&identity.CredentialsSAML{Providers: updatedProviders})
	if err != nil {
		return s.handleSettingsError(w, r, ctxUpdate, p, errors.WithStack(err))

	}

	i.Credentials[s.ID()] = *creds
	if err := s.d.SettingsHookExecutor().PostSettingsHook(w, r, s.SettingsStrategyID(), ctxUpdate, i, settings.WithCallback(func(ctxUpdate *settings.UpdateContext) error {
		return s.PopulateSettingsMethod(r, ctxUpdate.Session.Identity, ctxUpdate.Flow)
	})); err != nil {
		return s.handleSettingsError(w, r, ctxUpdate, p, err)
	}

	return errors.WithStack(flow.ErrCompletedByStrategy)
}

func (s *Strategy) handleSettingsError(w http.ResponseWriter, r *http.Request, ctxUpdate *settings.UpdateContext, p *updateSettingsFlowWithSAMLMethod, err error) error {
	if e := new(settings.FlowNeedsReAuth); errors.As(err, &e) {
		if err := s.d.ContinuityManager().Pause(r.Context(), w, r,
			settings.ContinuityKey(s.SettingsStrategyID()), settings.ContinuityOptions(p, ctxUpdate.Session.Identity)...); err != nil {
			return err
		}
	}

	if ctxUpdate.Flow != nil {
		ctxUpdate.Flow.UI.ResetMessages()
		ctxUpdate.Flow.UI.SetCSRF(s.d.GenerateCSRFToken(r))
	}

	return err
}

func (s *Strategy) Link(ctx context.Context, i *identity.Identity, credentialsConfig sqlxx.JSONRawMessage) error {
	var credentialsSAMLConfig identity.CredentialsSAML
	if err := json.Unmarshal(credentialsConfig, &credentialsSAMLConfig); err != nil {
		return err
	}
	if len(credentialsSAMLConfig.Providers) != 1 {
		return errors.New("No SAML provider was set")
	}
	var credentialsSAMLProvider = credentialsSAMLConfig.Providers[0]

	if err := s.linkCredentials(
		ctx,
		i,
		credentialsSAMLProvider.Provider,
		credentialsSAMLProvider.Subject,
	); err != nil {
		return err
	}

	options := []identity.ManagerOption{identity.ManagerAllowWriteProtectedTraits}
	if err := s.d.IdentityManager().Update(ctx, i, options...); err != nil {
		return err
	}

	return nil
}
