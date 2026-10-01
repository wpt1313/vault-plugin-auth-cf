// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

// Package cf provides a mock implementation of the pieces of the Cloud
// Foundry v3 API (https://v3-apidocs.cloudfoundry.org) that go-cfclient/v3
// exercises when creating a client and verifying apps/orgs/spaces: service
// discovery, UAA token issuance, and the apps/processes/organizations/spaces
// "get" endpoints.
package cf

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
)

const (
	AuthUsername = "username"
	AuthPassword = "password"

	AuthClientID     = "ClientID"
	AuthClientSecret = "ClientSecret"

	FoundServiceGUID = "1bf2e7f6-2d1d-41ec-501c-c70"
	FoundAppGUID     = "2d3e834a-3a25-4591-974c-fa5626d5d0a1"
	FoundOrgGUID     = "34a878d0-c2f9-4521-ba73-a9f664e82c7bf"
	FoundSpaceGUID   = "3d2eba6b-ef19-44d5-91dd-1975b0db5cc9"
	FoundProcessGUID = "6d0a0da4-5dcb-4305-a6c1-7b3f9f5e9d6f"
	FoundAppName     = "name-2401"
	FoundSpaceName   = "cfdev-space"
	FoundOrgName     = "system"

	UnfoundServiceGUID = "service-id-unfound"
	UnfoundAppGUID     = "app-id-unfound"
	UnfoundOrgID       = "org-id-unfound"
	UnfoundSpaceGUID   = "space-id-unfound"
)

var logger = hclog.Default()

// MockServer starts an httptest.Server that emulates just enough of the CF
// v3 API (plus UAA) for go-cfclient/v3 to successfully build a client and
// look up the "found" app/org/space fixtures above. loud, when true, logs
// every incoming request; casToTrust, when non-empty, configures the server
// to require and trust client certificates signed by those CAs (mTLS).
func MockServer(loud bool, casToTrust []string) *httptest.Server {
	var testServerURL string

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if loud {
			logger.Info(fmt.Sprintf("%+v", r))
		}

		path := r.URL.EscapedPath()

		switch {
		case path == "/":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, strings.Replace(rootResponse, "{{TEST_URL}}", testServerURL, -1))

		case path == "/oauth/token":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, tokenResponse)

		case path == "/v3/apps/"+FoundAppGUID:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, appResponse)

		case path == "/v3/apps/"+FoundAppGUID+"/processes":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, processesResponse)

		case path == "/v3/apps/"+UnfoundAppGUID:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, unfoundAppResponse)

		case path == "/v3/organizations/"+FoundOrgGUID:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, orgResponse)

		case path == "/v3/organizations/"+UnfoundOrgID:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, unfoundOrgResponse)

		case path == "/v3/spaces/"+FoundSpaceGUID:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, spaceResponse)

		case path == "/v3/spaces/"+UnfoundSpaceGUID:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, unfoundSpaceResponse)

		default:
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "unexpected request: %s %s", r.Method, path)
		}
	}))
	testServerURL = testServer.URL

	if len(casToTrust) > 0 {
		clientCACertPool := x509.NewCertPool()
		for _, ca := range casToTrust {
			clientCACertPool.AppendCertsFromPEM([]byte(ca))
		}
		testServer.TLS = &tls.Config{}
		testServer.TLS.ClientCAs = clientCACertPool
	}

	// give the server time to listen
	time.Sleep(time.Millisecond * 250)

	return testServer
}

const (
	// rootResponse emulates the CF API's service-discovery root document,
	// pointing both the login and UAA links back at this same mock server so
	// that go-cfclient/v3's config.New can discover them and then obtain an
	// OAuth2 token from the "/oauth/token" case above.
	rootResponse = `{
	"links": {
		"self": {"href": "{{TEST_URL}}"},
		"login": {"href": "{{TEST_URL}}"},
		"uaa": {"href": "{{TEST_URL}}"},
		"app_ssh": {
			"href": "ssh.dev.cfdev.sh:2222",
			"meta": {
				"host_key_fingerprint": "96:4d:89:2d:39:18:bc:16:e1:d3:d8:44:f8:16:af:85",
				"oauth_client": "ssh-proxy"
			}
		}
	}
}`

	tokenResponse = `{
	"access_token": "******",
	"token_type": "bearer",
	"id_token": "******",
	"refresh_token": "******",
	"expires_in": 599,
	"scope": "clients.read openid routing.router_groups.write scim.read cloud_controller.admin uaa.user routing.router_groups.read cloud_controller.read password.write cloud_controller.write network.admin doppler.firehose scim.write",
	"jti": "13cb302b1c66407d9f7036c2c2e1d120"
}`

	appResponse = `{
	"guid": "2d3e834a-3a25-4591-974c-fa5626d5d0a1",
	"created_at": "2016-06-08T16:41:44Z",
	"updated_at": "2016-06-08T16:41:44Z",
	"name": "name-2401",
	"state": "STARTED",
	"lifecycle": {
		"type": "buildpack",
		"data": {
			"buildpacks": [],
			"stack": "cflinuxfs3"
		}
	},
	"relationships": {
		"space": {
			"data": {"guid": "3d2eba6b-ef19-44d5-91dd-1975b0db5cc9"}
		},
		"current_droplet": {
			"data": null
		}
	},
	"metadata": {"labels": {}, "annotations": {}}
}`

	unfoundAppResponse = `{
	"errors": [
		{
			"code": 100004,
			"title": "CF-AppNotFound",
			"detail": "The app could not be found: app-id-unfound"
		}
	]
}`

	// processesResponse lists a single "web" process with one live instance
	// for FoundAppGUID, which is what backend.validate uses to confirm the
	// app has live instances (the v3 API, unlike v2, doesn't expose an
	// instance count directly on the app resource).
	processesResponse = `{
	"pagination": {
		"total_results": 1,
		"total_pages": 1,
		"first": {"href": ""},
		"last": {"href": ""},
		"next": null,
		"previous": null
	},
	"resources": [
		{
			"guid": "6d0a0da4-5dcb-4305-a6c1-7b3f9f5e9d6f",
			"created_at": "2016-06-08T16:41:44Z",
			"updated_at": "2016-06-08T16:41:44Z",
			"type": "web",
			"instances": 1,
			"memory_in_mb": 1024,
			"disk_in_mb": 1024,
			"relationships": {
				"app": {
					"data": {"guid": "2d3e834a-3a25-4591-974c-fa5626d5d0a1"}
				}
			},
			"metadata": {"labels": {}, "annotations": {}}
		}
	]
}`

	orgResponse = `{
	"guid": "34a878d0-c2f9-4521-ba73-a9f664e82c7bf",
	"created_at": "2019-05-17T22:49:40Z",
	"updated_at": "2019-05-17T22:49:40Z",
	"name": "system",
	"suspended": false,
	"metadata": {"labels": {}, "annotations": {}}
}`

	unfoundOrgResponse = `{
	"errors": [
		{
			"code": 30003,
			"title": "CF-OrganizationNotFound",
			"detail": "The organization could not be found: org-id-unfound"
		}
	]
}`

	spaceResponse = `{
	"guid": "3d2eba6b-ef19-44d5-91dd-1975b0db5cc9",
	"created_at": "2019-05-17T22:53:30Z",
	"updated_at": "2019-05-17T22:53:30Z",
	"name": "cfdev-space",
	"relationships": {
		"organization": {
			"data": {"guid": "34a878d0-c2f9-4521-ba73-a9f664e82c7bf"}
		}
	},
	"metadata": {"labels": {}, "annotations": {}}
}`

	unfoundSpaceResponse = `{
	"errors": [
		{
			"code": 40004,
			"title": "CF-SpaceNotFound",
			"detail": "The app space could not be found: space-id-unfound"
		}
	]
}`
)
