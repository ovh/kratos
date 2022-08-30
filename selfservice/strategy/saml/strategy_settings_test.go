package saml_test

import (
	"context"
	"encoding/json"
	"github.com/gofrs/uuid"
	"github.com/ory/kratos/corpx"
	"github.com/ory/kratos/driver"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/internal"
	kratos "github.com/ory/kratos/internal/httpclient"
	"github.com/ory/kratos/internal/testhelpers"
	"github.com/ory/kratos/selfservice/flow"
	"github.com/ory/kratos/selfservice/flow/settings"
	"github.com/ory/kratos/selfservice/strategy/saml"
	"github.com/ory/kratos/ui/container"
	"github.com/ory/kratos/ui/node"
	"github.com/ory/kratos/x"
	"github.com/ory/x/snapshotx"
	"github.com/ory/x/sqlxx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"golang.org/x/net/html"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func init() {
	corpx.RegisterFakes()
}

func TestSettingsStrategy(t *testing.T) {
	ctx := context.Background()
	if testing.Short() {
		t.Skip()
	}

	var (
		conf, reg = internal.NewFastRegistryWithMocks(t)
	)

	uiTS := newUI(t, reg)
	publicTS, adminTS := testhelpers.NewKratosServers(t)

	testhelpers.InitKratosServers(t, reg, publicTS, adminTS)
	testhelpers.SetDefaultIdentitySchema(conf, "file://./stub/settings.schema.json")
	conf.MustSet(ctx, config.ViperKeySelfServiceBrowserDefaultReturnTo, "https://www.ory.sh/kratos")
	conf.MustSet(ctx, config.ViperKeySelfServiceStrategyConfig+"."+string(identity.CredentialsTypeSAML)+".enabled", true)

	providerId := "TestSettingsStrategyProvider"
	urlAcs := publicTS.URL + saml.RouteBaseAcs + "/" + providerId
	remoteIDP := newIDP(t, publicTS.URL+saml.RouteBaseMetadata+"/"+providerId, urlAcs)
	ViperSetProviderConfig(t, conf,
		saml.Configuration{
			ID:             providerId,
			Provider:       "generic",
			Label:          "SAML IdP 1",
			PublicCertPath: "file://./testdata/idp_cert.pem",
			PrivateKeyPath: "file://./testdata/idp_key.pem",
			AttributesMap:  map[string]string{"id": "uid", "email": "email"},
			IDPInformation: map[string]string{"idp_metadata_url": remoteIDP + "/simplesaml/saml2/idp/metadata.php"},
			Mapper:         "file://./testdata/saml.jsonnet",
		})

	var nprSDK = func(t *testing.T, client *http.Client, redirectTo string, exp time.Duration) *kratos.SettingsFlow {
		return testhelpers.InitializeSettingsFlowViaBrowser(t, client, false, publicTS)
	}

	var action = func(req *kratos.SettingsFlow) string {
		return req.Ui.Action
	}

	users := map[string]*identity.Identity{
		"user1": {ID: x.NewUUID(), Traits: identity.Traits(`{"email":"user1@example.com"}`),
			SchemaID: config.DefaultIdentityTraitsSchemaID,
			Credentials: map[identity.CredentialsType]identity.Credentials{
				"password": {Type: "password",
					Identifiers: []string{"user1@example.com"},
					Config:      sqlxx.JSONRawMessage(`{"hashed_password":"$argon2id$iammocked...."}`)}},
		},
	}
	agents := testhelpers.AddAndLoginIdentities(t, reg, publicTS, users)

	var makeRequestWithClient = func(t *testing.T, action string, fv url.Values, client *http.Client, statusCode int) (*http.Response, []byte) {
		if client == nil {
			client = NewTestClient(t, nil)
		}

		res, err := client.PostForm(action, fv)
		require.NoError(t, err, action)

		body, err := io.ReadAll(res.Body)
		require.NoError(t, res.Body.Close())
		require.NoError(t, err)

		require.Equal(t, statusCode, res.StatusCode, "%s: %s\n\t%s", action, res.Request.URL.String(), body)

		return res, body
	}

	var getValueByName = func(body []byte, name string) string {
		doc, err := html.Parse(strings.NewReader(string(body)))
		require.NoError(t, err, body)

		n := traverse(doc, name)
		require.NotNil(t, n)
		result, ok := getAttribute(n, "value")
		require.True(t, ok)

		return result
	}

	var checkCredentials = func(t *testing.T, shouldExist bool, iid uuid.UUID, provider, subject string) {
		actual, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(context.Background(), iid)
		require.NoError(t, err)

		var cc identity.CredentialsSAML
		creds, err := actual.ParseCredentials(identity.CredentialsTypeSAML, &cc)
		require.NoError(t, err)

		if shouldExist {
			assert.Contains(t, creds.Identifiers, provider+":"+subject)
		} else {
			assert.NotContains(t, creds.Identifiers, provider+":"+subject)
		}

		var found bool
		for _, p := range cc.Providers {
			if p.Provider == provider && p.Subject == subject {
				found = true
				break
			}
		}

		require.EqualValues(t, shouldExist, found)
	}

	t.Run("suite=link", func(t *testing.T) {
		var link = func(t *testing.T, agent, provider string) (body []byte, res *http.Response, req *kratos.SettingsFlow) {
			req = nprSDK(t, agents[agent], "", time.Hour)

			client := agents[agent]
			//Post to kratos to initiate SAML flow
			body, res = testhelpers.HTTPPostForm(t, client, action(req),
				&url.Values{"csrf_token": {x.FakeCSRFToken}, "samlLink": {provider}})

			//Post to identity provider UI
			res, body = makeRequestWithClient(t, res.Request.URL.String(), url.Values{
				"username": []string{"user1"},
				"password": []string{"user1pass"},
			}, client, 200)

			//Extract SAML response from body returned by identity provider
			SAMLResponse := getValueByName(body, "SAMLResponse")
			relayState := getValueByName(body, "RelayState")

			//Post SAML response to kratos
			res, body = makeRequestWithClient(t, urlAcs, url.Values{
				"SAMLResponse": []string{SAMLResponse},
				"RelayState":   []string{relayState},
			}, client, 200)

			return
		}

		t.Run("case=should link a connection", func(t *testing.T) {
			agent, provider := "user1", providerId
			updatedFlow, res, originalFlow := link(t, agent, provider)
			assert.Contains(t, res.Request.URL.String(), uiTS.URL)

			updatedFlowSDK, _, err := testhelpers.NewSDKCustomClient(publicTS, agents[agent]).FrontendApi.GetSettingsFlow(context.Background()).Id(originalFlow.Id).Execute()
			require.NoError(t, err)
			require.EqualValues(t, flow.StateSuccess, updatedFlowSDK.State)

			t.Run("flow=original", func(t *testing.T) {
				snapshotx.SnapshotT(t, originalFlow.Ui.Nodes, snapshotx.ExceptPaths("0.attributes.value", "1.attributes.value"))
			})
			t.Run("flow=response", func(t *testing.T) {
				snapshotx.SnapshotT(t, json.RawMessage(gjson.GetBytes(updatedFlow, "ui.nodes").Raw),
					snapshotx.ExceptPaths("0.attributes.value", "1.attributes.value", "2.attributes.value"))
			})
			t.Run("flow=fetch", func(t *testing.T) {
				snapshotx.SnapshotT(t, updatedFlowSDK.Ui.Nodes, snapshotx.ExceptPaths("0.attributes.value", "1.attributes.value", "2.attributes.value"))
			})

			checkCredentials(t, true, users[agent].ID, provider, "1")
		})
	})
}

func TestPopulateSettingsMethod(t *testing.T) {
	ctx := context.Background()
	nRegistry := func(t *testing.T, conf *saml.ConfigurationCollection) *driver.RegistryDefault {
		c, reg := internal.NewFastRegistryWithMocks(t)

		testhelpers.SetDefaultIdentitySchema(c, "file://stub/registration.schema.json")
		c.MustSet(ctx, config.ViperKeyPublicBaseURL, "https://www.ory.sh/")

		viperSetProviderConfig(t, c, conf.SAMLProviders...)
		return reg
	}

	ns := func(t *testing.T, reg *driver.RegistryDefault) *saml.Strategy {
		ss, err := reg.SettingsStrategies(context.Background()).Strategy(identity.CredentialsTypeSAML.String())
		require.NoError(t, err)
		return ss.(*saml.Strategy)
	}

	nr := func() *settings.Flow {
		return &settings.Flow{Type: flow.TypeBrowser, ID: x.NewUUID(), UI: container.New("")}
	}

	populate := func(t *testing.T, reg *driver.RegistryDefault, i *identity.Identity, req *settings.Flow) *container.Container {
		require.NoError(t, reg.PrivilegedIdentityPool().CreateIdentity(context.Background(), i))
		require.NoError(t, ns(t, reg).PopulateSettingsMethod(new(http.Request), i, req))
		require.NotNil(t, req.UI)
		require.NotNil(t, req.UI.Nodes)
		assert.Equal(t, "POST", req.UI.Method)
		return req.UI
	}

	defaultConfig := []saml.Configuration{
		{Provider: "generic", ID: "corp1"},
		{Provider: "generic", ID: "corp2"},
		{Provider: "generic", ID: "corp3"},
	}

	for k, tc := range []struct {
		c            []saml.Configuration
		i            *identity.Credentials
		e            node.Nodes
		withPassword bool
	}{
		{
			c: []saml.Configuration{},
			e: node.Nodes{
				node.NewCSRFNode(x.FakeCSRFToken),
			},
		},
		{
			c: []saml.Configuration{
				{Provider: "generic", ID: "corp1"},
			},
			e: node.Nodes{
				node.NewCSRFNode(x.FakeCSRFToken),
				saml.NewLinkNode(),
			},
		},
		{
			c: defaultConfig,
			e: node.Nodes{
				node.NewCSRFNode(x.FakeCSRFToken),
				saml.NewLinkNode(),
			},
		},
		{
			c: defaultConfig,
			e: node.Nodes{
				node.NewCSRFNode(x.FakeCSRFToken),
				saml.NewLinkNode(),
			},
			i: &identity.Credentials{Type: identity.CredentialsTypeSAML, Identifiers: []string{}, Config: []byte(`{}`)},
		},
		{
			c: defaultConfig,
			e: node.Nodes{
				node.NewCSRFNode(x.FakeCSRFToken),
				saml.NewLinkNode(),
			},
			i: &identity.Credentials{Type: identity.CredentialsTypeSAML, Identifiers: []string{
				"corp1:1234",
			}, Config: []byte(`{"providers":[{"provider":"corp1","subject":"1234"}]}`)},
		},
		{
			c: defaultConfig,
			e: node.Nodes{
				node.NewCSRFNode(x.FakeCSRFToken),
				saml.NewLinkNode(),
				saml.NewUnlinkNode("corp1"),
			},
			withPassword: true,
			i: &identity.Credentials{Type: identity.CredentialsTypeSAML, Identifiers: []string{
				"corp1:1234",
			}, Config: []byte(`{"providers":[{"samlProvider":"corp1","subject":"1234"}]}`)},
		},
		{
			c: defaultConfig,
			e: node.Nodes{
				node.NewCSRFNode(x.FakeCSRFToken),
				saml.NewLinkNode(),
				saml.NewUnlinkNode("corp1"),
				saml.NewUnlinkNode("corp2"),
			},
			i: &identity.Credentials{Type: identity.CredentialsTypeSAML, Identifiers: []string{
				"corp1:1234",
				"corp2:1234",
			},
				Config: []byte(`{"providers":[{"samlProvider":"corp1","subject":"1234"},{"samlProvider":"corp2","subject":"1234"}]}`)},
		},
	} {
		t.Run("iteration="+strconv.Itoa(k), func(t *testing.T) {
			reg := nRegistry(t, &saml.ConfigurationCollection{SAMLProviders: tc.c})
			i := &identity.Identity{
				Traits:      []byte(`{"email":"foo@bar.com"}`),
				Credentials: make(map[identity.CredentialsType]identity.Credentials, 2),
			}
			if tc.i != nil {
				i.Credentials[identity.CredentialsTypeSAML] = *tc.i
			}
			if tc.withPassword {
				i.Credentials[identity.CredentialsTypePassword] = identity.Credentials{
					Type:        identity.CredentialsTypePassword,
					Identifiers: []string{"foo@bar.com"},
					Config:      []byte(`{"hashed_password":"$argon2id$..."}`),
				}
			}
			actual := populate(t, reg, i, nr())
			assert.EqualValues(t, tc.e, actual.Nodes)
		})
	}
}
