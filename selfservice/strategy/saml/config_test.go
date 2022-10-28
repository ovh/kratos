package saml_test

import (
	"context"
	"io/ioutil"
	"testing"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/selfservice/strategy/saml"
	"github.com/ory/kratos/x"
	"github.com/stretchr/testify/assert"
)

/* Liste des tests
SAML sans provider
SAML avec providers mais sans ID
SAML avec providers mais sans label
SAML avec providers mais sans private ou public key
SAML avec providers mais avec un champ en plus
SAML sans IDP informations
SAML avec IDP informations mais aucune donnes sur les metadatas
SAML avec IDP informations avec à la fois un URL et des données metadata
Tester tous les open file avec des trucs malveillants
Ajouter un champ dans l'attributes map
Retirer un champ
*/

func TestInitSAMLWithoutProvider(t *testing.T) {
	saml.DestroyMiddlewareIfExists()

	conf, reg := internal.NewFastRegistryWithMocks(t)
	//strategy := saml.NewStrategy(reg)
	errTS := testhelpers.NewErrorTestServer(t, reg)
	routerP := x.NewRouterPublic()
	routerA := x.NewRouterAdmin()
	ts, _ := testhelpers.NewKratosServerWithRouters(t, reg, routerP, routerA)

	attributesMap := make(map[string]string)
	attributesMap["id"] = "mail"
	attributesMap["firstname"] = "givenName"
	attributesMap["lastname"] = "sn"
	attributesMap["email"] = "mail"

	idpInformation := make(map[string]string)
	idpInformation["idp_sso_url"] = "https://samltest.id/idp/profile/SAML2/Redirect/SSO"
	idpInformation["idp_entity_id"] = "https://samltest.id/saml/idp"
	idpInformation["idp_certificate_path"] = "file://testdata/samlkratos.crt"
	idpInformation["idp_logout_url"] = "https://samltest.id/idp/profile/SAML2/Redirect/SSO"

	// Initiates without service provider
	ViperSetProviderConfig(
		t,
		conf,
	)

	conf.MustSet(context.Background(), config.ViperKeySelfServiceRegistrationEnabled, true)
	testhelpers.SetDefaultIdentitySchema(conf, "file://testdata/registration.schema.json")
	conf.MustSet(context.Background(), config.HookStrategyKey(config.ViperKeySelfServiceRegistrationAfter,
		identity.CredentialsTypeSAML.String()), []config.SelfServiceHook{{Name: "session"}})

	t.Logf("Kratos Public URL: %s", ts.URL)
	t.Logf("Kratos Error URL: %s", errTS.URL)

	resp, _ := NewTestClient(t, nil).Get(ts.URL + "/self-service/methods/saml/metadata")
	body, _ := ioutil.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Please indicate a SAML Identity Provider in your configuration file")
}

func TestInitSAMLWithoutPoviderID(t *testing.T) {
	saml.DestroyMiddlewareIfExists()

	conf, reg := internal.NewFastRegistryWithMocks(t)
	//strategy := saml.NewStrategy(reg)
	errTS := testhelpers.NewErrorTestServer(t, reg)
	routerP := x.NewRouterPublic()
	routerA := x.NewRouterAdmin()
	ts, _ := testhelpers.NewKratosServerWithRouters(t, reg, routerP, routerA)

	attributesMap := make(map[string]string)
	attributesMap["id"] = "mail"
	attributesMap["firstname"] = "givenName"
	attributesMap["lastname"] = "sn"
	attributesMap["email"] = "mail"

	idpInformation := make(map[string]string)
	idpInformation["idp_sso_url"] = "https://samltest.id/idp/profile/SAML2/Redirect/SSO"
	idpInformation["idp_entity_id"] = "https://samltest.id/saml/idp"
	idpInformation["idp_certificate_path"] = "file://testdata/samlkratos.crt"
	idpInformation["idp_logout_url"] = "https://samltest.id/idp/profile/SAML2/Redirect/SSO"

	// Initiates the service provider
	ViperSetProviderConfig(
		t,
		conf,
		saml.Configuration{
			ID:             "",
			Label:          "samlProviderTestLabel",
			PublicCertPath: "file://testdata/myservice.cert",
			PrivateKeyPath: "file://testdata/myservice.key",
			Mapper:         "file://testdata/saml.jsonnet",
			AttributesMap:  attributesMap,
			IDPInformation: idpInformation,
		},
	)

	conf.MustSet(context.Background(), config.ViperKeySelfServiceRegistrationEnabled, true)
	testhelpers.SetDefaultIdentitySchema(conf, "file://testdata/registration.schema.json")
	conf.MustSet(context.Background(), config.HookStrategyKey(config.ViperKeySelfServiceRegistrationAfter,
		identity.CredentialsTypeSAML.String()), []config.SelfServiceHook{{Name: "session"}})

	t.Logf("Kratos Public URL: %s", ts.URL)
	t.Logf("Kratos Error URL: %s", errTS.URL)

	resp, _ := NewTestClient(t, nil).Get(ts.URL + "/self-service/methods/saml/metadata")
	body, _ := ioutil.ReadAll(resp.Body)
	assert.Contains(t, string(body), "Provider must have an ID")
}

func TestAttributesMapWithoutID(t *testing.T) {
	saml.DestroyMiddlewareIfExists()

	conf, reg := internal.NewFastRegistryWithMocks(t)
	//strategy := saml.NewStrategy(reg)
	errTS := testhelpers.NewErrorTestServer(t, reg)
	routerP := x.NewRouterPublic()
	routerA := x.NewRouterAdmin()
	ts, _ := testhelpers.NewKratosServerWithRouters(t, reg, routerP, routerA)

	attributesMap := make(map[string]string)
	attributesMap["firstname"] = "givenName"
	attributesMap["lastname"] = "sn"
	attributesMap["email"] = "mail"

	idpInformation := make(map[string]string)
	idpInformation["idp_sso_url"] = "https://samltest.id/idp/profile/SAML2/Redirect/SSO"
	idpInformation["idp_entity_id"] = "https://samltest.id/saml/idp"
	idpInformation["idp_certificate_path"] = "file://testdata/samlkratos.crt"
	idpInformation["idp_logout_url"] = "https://samltest.id/idp/profile/SAML2/Redirect/SSO"

	// Initiates the service provider
	ViperSetProviderConfig(
		t,
		conf,
		saml.Configuration{
			ID:             "samlProviderTestID",
			Label:          "samlProviderTestLabel",
			PublicCertPath: "file://testdata/myservice.cert",
			PrivateKeyPath: "file://testdata/myservice.key",
			Mapper:         "file://testdata/saml.jsonnet",
			AttributesMap:  attributesMap,
			IDPInformation: idpInformation,
		},
	)

	conf.MustSet(context.Background(), config.ViperKeySelfServiceRegistrationEnabled, true)
	testhelpers.SetDefaultIdentitySchema(conf, "file://testdata/registration.schema.json")
	conf.MustSet(context.Background(), config.HookStrategyKey(config.ViperKeySelfServiceRegistrationAfter,
		identity.CredentialsTypeSAML.String()), []config.SelfServiceHook{{Name: "session"}})

	t.Logf("Kratos Public URL: %s", ts.URL)
	t.Logf("Kratos Error URL: %s", errTS.URL)

	resp, _ := NewTestClient(t, nil).Get(ts.URL + "/self-service/methods/saml/metadata")
	body, _ := ioutil.ReadAll(resp.Body)
	assert.Contains(t, string(body), "You must have an ID field in your attribute_map")

}
