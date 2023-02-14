package saml_test

import (
	"io/ioutil"
	"testing"

	"github.com/ory/kratos/selfservice/strategy/saml"
	"github.com/ory/x/fetcher"
	"github.com/stretchr/testify/require"

	"gotest.tools/assert"
)

func TestInitMiddleWareWithMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	saml.DestroyMiddlewareIfExists("samlProvider")

	middleWare, _, _, err := InitTestMiddlewareWithMetadata(t,
		"file://testdata/SP_IDPMetadata.xml")

	require.NoError(t, err)
	assert.Check(t, middleWare != nil)
	assert.Check(t, middleWare.ServiceProvider.IDPMetadata != nil)
	assert.Check(t, middleWare.ServiceProvider.MetadataURL.Path == "/self-service/methods/saml/metadata/:provider")
	assert.Check(t, middleWare.ServiceProvider.IDPMetadata.EntityID == "https://idp.testshib.org/idp/shibboleth")
}

func TestInitMiddleWareWithoutMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	saml.DestroyMiddlewareIfExists("samlProvider")

	middleWare, _, _, err := InitTestMiddlewareWithoutMetadata(t,
		"https://samltest.id/idp/profile/SAML2/Redirect/SSO",
		"https://samltest.id/saml/idp",
		"file://testdata/idp_cert.pem",
		"https://samltest.id/idp/profile/SAML2/Redirect/SSO")

	require.NoError(t, err)
	assert.Check(t, middleWare != nil)
	assert.Check(t, middleWare.ServiceProvider.IDPMetadata != nil)
	assert.Check(t, middleWare.ServiceProvider.MetadataURL.Path == "/self-service/methods/saml/metadata/:provider")
	assert.Check(t, middleWare.ServiceProvider.IDPMetadata.EntityID == "https://samltest.id/saml/idp")
}

func TestGetMiddleware(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	saml.DestroyMiddlewareIfExists("samlProvider")

	InitTestMiddlewareWithMetadata(t,
		"file://testdata/SP_IDPMetadata.xml")

	middleWare, err := saml.GetMiddleware("samlProvider")

	require.NoError(t, err)
	assert.Check(t, middleWare != nil)
	assert.Check(t, middleWare.ServiceProvider.IDPMetadata != nil)
	assert.Check(t, middleWare.ServiceProvider.MetadataURL.Path == "/self-service/methods/saml/metadata/:provider")
	assert.Check(t, middleWare.ServiceProvider.IDPMetadata.EntityID == "https://idp.testshib.org/idp/shibboleth")
}

func TestMustParseCertificate(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	saml.DestroyMiddlewareIfExists("samlProvider")

	certificateBuffer, err := fetcher.NewFetcher().Fetch("file://testdata/sp_cert.pem")
	require.NoError(t, err)

	certificate, err := ioutil.ReadAll(certificateBuffer)
	require.NoError(t, err)

	cert, err := saml.MustParseCertificate(certificate)

	require.NoError(t, err)
	assert.Check(t, cert.Issuer.Country[0] == "US")
	assert.Check(t, cert.Issuer.Organization[0] == "foo")
	assert.Check(t, cert.Issuer.Province[0] == "GA")
	assert.Check(t, cert.Subject.Country[0] == "US")
	assert.Check(t, cert.Subject.Organization[0] == "foo")
	assert.Check(t, cert.Subject.Province[0] == "GA")
	assert.Check(t, cert.NotBefore.String() == "2013-10-02 00:08:51 +0000 UTC")
	assert.Check(t, cert.NotAfter.String() == "2014-10-02 00:08:51 +0000 UTC")
	assert.Check(t, cert.SerialNumber.String() == "14253244695696570161")
}
