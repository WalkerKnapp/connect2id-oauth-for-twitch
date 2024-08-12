/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2023, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.oauth2.sdk;


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionDetails;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionFactory;
import com.nimbusds.oauth2.sdk.assertions.saml2.SAML2AssertionDetails;
import com.nimbusds.oauth2.sdk.assertions.saml2.SAML2AssertionFactory;
import com.nimbusds.oauth2.sdk.auth.*;
import com.nimbusds.oauth2.sdk.ciba.AuthRequestID;
import com.nimbusds.oauth2.sdk.ciba.CIBAGrant;
import com.nimbusds.oauth2.sdk.device.DeviceCode;
import com.nimbusds.oauth2.sdk.device.DeviceCodeGrant;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail;
import com.nimbusds.oauth2.sdk.rar.AuthorizationType;
import com.nimbusds.oauth2.sdk.token.*;
import com.nimbusds.oauth2.sdk.tokenexchange.TokenExchangeGrant;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.nativesso.DeviceSecret;
import junit.framework.TestCase;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSocketFactory;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;


public class TokenRequestTest extends TestCase {


	private static final URI ENDPOINT = URI.create("https://c2id.com/token");

	private static final ClientID CLIENT_ID = new ClientID("123");

	private static final Secret CLIENT_SECRET = new Secret();
	
	private static final AuthorizationCode CODE = new AuthorizationCode();

	private static final RefreshToken REFRESH_TOKEN = new RefreshToken();

	private static final DeviceCode DEVICE_CODE = new DeviceCode();

	private static final AuthRequestID AUTH_REQUEST_ID = new AuthRequestID();

	private static final DeviceSecret DEVICE_SECRET = new DeviceSecret("iecohw6aek2cohchoh5Uicheexe9eemu");

	private static final Scope SCOPE = new Scope("openid", "email");
	


	public void testBuilderWithClientAuthentication_minimal() {

		ClientAuthentication clientAuth = new ClientSecretBasic(CLIENT_ID, CLIENT_SECRET);
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(CODE, null);

		TokenRequest request = new TokenRequest.Builder(ENDPOINT, clientAuth, grant)
			.build();

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(grant, request.getAuthorizationGrant());

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
		assertNull(request.getAuthorizationDetails());
		assertNull(request.getResources());
		assertNull(request.getExistingGrant());
		assertNull(request.getDeviceSecret());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testBuilderWithClientAuthentication_allSet() throws ParseException {

		ClientSecretBasic basicAuth = new ClientSecretBasic(CLIENT_ID, CLIENT_SECRET);
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(CODE, null);

		List<AuthorizationDetail> authorizationDetails = Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("example_api")).build());
		List<URI> resources = Arrays.asList(URI.create("https://rs1.com"), URI.create("https://rs2.com"));
		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("x", Collections.singletonList("100"));
		customParams.put("y", Collections.singletonList("200"));

		TokenRequest request = new TokenRequest.Builder(ENDPOINT, basicAuth, grant)
			.scope(SCOPE)
			.authorizationDetails(authorizationDetails)
			.resources(resources.get(0), resources.get(1))
			.existingGrant(REFRESH_TOKEN) // must be ignored
			.deviceSecret(DEVICE_SECRET)
			.customParameter("x", "100")
			.customParameter("y", "200")
			.build();

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(basicAuth, request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertEquals(SCOPE, request.getScope());
		assertEquals(resources, request.getResources());
		assertNull(request.getExistingGrant());
		assertEquals(DEVICE_SECRET, request.getDeviceSecret());
		assertEquals(customParams, request.getCustomParameters());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(ENDPOINT, httpRequest.getURI());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		ClientSecretBasic basic = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertEquals(basicAuth.getClientID(), basic.getClientID());
		assertEquals(basicAuth.getClientSecret(), basic.getClientSecret());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList(CODE.getValue()), params.get("code"));
		assertEquals(AuthorizationDetail.toJSONString(authorizationDetails), MultivaluedMapUtils.getFirstValue(params, "authorization_details"));
		assertEquals(Arrays.asList("https://rs1.com", "https://rs2.com"), params.get("resource"));
		assertEquals(DEVICE_SECRET.getValue(), MultivaluedMapUtils.getFirstValue(params, "device_secret"));
		assertEquals("100", MultivaluedMapUtils.getFirstValue(params, "x"));
		assertEquals("200", MultivaluedMapUtils.getFirstValue(params, "y"));
		assertEquals(7, params.size());

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(basicAuth.getClientID(), request.getClientAuthentication().getClientID());
		assertEquals(basicAuth.getClientSecret(), ((ClientSecretBasic) request.getClientAuthentication()).getClientSecret());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull("Must be skipped", request.getScope());
		assertEquals(resources, request.getResources());
		assertNull(request.getExistingGrant());
		assertEquals(DEVICE_SECRET, request.getDeviceSecret());
		assertEquals(customParams, request.getCustomParameters());
	}


	public void testBuilderWithClientAuthentication_allSet_thenCleared() {

		ClientAuthentication clientAuth = new ClientSecretBasic(CLIENT_ID, CLIENT_SECRET);
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(CODE, null);

		TokenRequest.Builder builder = new TokenRequest.Builder(ENDPOINT, clientAuth, grant)
			.scope(SCOPE)
			.authorizationDetails(Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("example_api")).build()))
			.resource(URI.create("https://rs1.com"))
			.existingGrant(REFRESH_TOKEN) // must be ignored
			.deviceSecret(DEVICE_SECRET)
			.customParameter("x", "100")
			.customParameter("y", "200");

		builder = builder
			.scope(null)
			.authorizationDetails(null)
			.resources(null)
			.existingGrant(null)
			.deviceSecret(null)
			.customParameter("x", null)
			.customParameter("y", null);

		TokenRequest request = builder.build();

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
		assertNull(request.getAuthorizationDetails());
		assertNull(request.getResources());
		assertNull(request.getExistingGrant());
		assertNull(request.getDeviceSecret());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testBuilderWithClientAuthentication_rejectNullAuthentication() {
		try {
			new TokenRequest.Builder(ENDPOINT,
				(ClientAuthentication) null,
				new CIBAGrant(AUTH_REQUEST_ID));
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}


	public void testPublicClientBuilder_minimal()
		throws ParseException {

		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(CODE, URI.create("http://example.com/in"));

		TokenRequest request = new TokenRequest.Builder(ENDPOINT, CLIENT_ID, grant)
			.build();

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(CLIENT_ID, request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
		assertNull(request.getAuthorizationDetails());
		assertNull(request.getResources());
		assertNull(request.getExistingGrant());
		assertNull(request.getDeviceSecret());
		assertTrue(request.getCustomParameters().isEmpty());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(CLIENT_ID, request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
		assertNull(request.getAuthorizationDetails());
		assertNull(request.getResources());
		assertNull(request.getExistingGrant());
		assertNull(request.getDeviceSecret());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testPublicClientBuilder_allSet()
		throws ParseException {

		AuthorizationGrant grant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("apples pears oranges 1001"));
		List<AuthorizationDetail> authorizationDetails = Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("example_api")).build());
		List<URI> resources = Collections.singletonList(URI.create("https://rs1.com"));
		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("x", Collections.singletonList("100"));
		customParams.put("y", Collections.singletonList("200"));

		TokenRequest request = new TokenRequest.Builder(ENDPOINT, CLIENT_ID, grant)
			.scope(SCOPE)
			.authorizationDetails(authorizationDetails)
			.resource(resources.get(0))
			.existingGrant(REFRESH_TOKEN)
			.deviceSecret(DEVICE_SECRET)
			.customParameter("x", "100")
			.customParameter("y", "200")
			.build();

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(CLIENT_ID, request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertEquals(SCOPE, request.getScope());
		assertEquals(authorizationDetails, request.getAuthorizationDetails());
		assertEquals(resources, request.getResources());
		assertEquals(REFRESH_TOKEN, request.getExistingGrant());
		assertEquals(DEVICE_SECRET, request.getDeviceSecret());
		assertEquals(customParams, request.getCustomParameters());
		assertEquals(Collections.singletonList("100"), request.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameter("y"));

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(CLIENT_ID, request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertEquals(SCOPE, request.getScope());
		assertEquals(authorizationDetails, request.getAuthorizationDetails());
		assertEquals(resources, request.getResources());
		assertEquals(REFRESH_TOKEN, request.getExistingGrant());
		assertEquals(DEVICE_SECRET, request.getDeviceSecret());
		assertEquals(customParams, request.getCustomParameters());
		assertEquals(Collections.singletonList("100"), request.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameter("y"));
	}


	public void testClientBuilderWithoutExplicitClient() {

		AuthorizationGrant grant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("apples pears oranges 1001"));

		TokenRequest request = new TokenRequest.Builder(ENDPOINT, grant)
			.build();

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
		assertNull(request.getAuthorizationDetails());
		assertNull(request.getResources());
		assertNull(request.getExistingGrant());
		assertNull(request.getDeviceSecret());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testBuilderWithClientAuthentication_nullEndpoint() {

		ClientSecretBasic basicAuth = new ClientSecretBasic(CLIENT_ID, CLIENT_SECRET);
		AuthorizationGrant grant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("apples pears oranges 1001"));

		TokenRequest request = new TokenRequest.Builder(null, basicAuth, grant)
			.scope(SCOPE)
			.build();

		assertNull(request.getEndpointURI());
		assertEquals(basicAuth, request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertEquals(SCOPE, request.getScope());
	}


	public void testPublicClientBuilder_nullEndpoint() {

		AuthorizationGrant grant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("apples pears oranges 1001"));

		TokenRequest request = new TokenRequest.Builder(null, CLIENT_ID, grant)
			.scope(SCOPE)
			.build();

		assertNull(request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(CLIENT_ID, request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertEquals(SCOPE, request.getScope());
	}


	public void testClientBuilderWithoutExplicitClient_nullEndpoint() {

		AuthorizationGrant grant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("apples pears oranges 1001"));

		TokenRequest request = new TokenRequest.Builder(null, grant)
			.build();

		assertNull(request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
	}


	public void testBuilder_rejectNullGrant() {

		try {
			new TokenRequest.Builder(
				ENDPOINT,
				new ClientSecretBasic(CLIENT_ID, CLIENT_SECRET),
				null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}

		try {
			new TokenRequest.Builder(
				ENDPOINT,
				CLIENT_ID,
				null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}

		try {
			new TokenRequest.Builder(
				ENDPOINT,
				null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}


	public void testBuilder_rejectNullClientAuthentication() {

		try {
			new TokenRequest.Builder(
				ENDPOINT,
                                (ClientAuthentication) null,
				new CIBAGrant(AUTH_REQUEST_ID));
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}


	public void testBuilder_rejectNullClientID() {

		try {
			new TokenRequest.Builder(
				ENDPOINT,
                                (ClientID) null,
				null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}


	public void testConstructorWithClientAuthentication_minimal()
		throws Exception {
		
		ClientAuthentication clientAuth = new ClientSecretBasic(CLIENT_ID, CLIENT_SECRET);
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(CODE, null);

		TokenRequest request = new TokenRequest(ENDPOINT, clientAuth, grant, SCOPE);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertEquals(SCOPE, request.getScope());
		assertNull(request.getAuthorizationDetails());
		assertNull(request.getResources());
		assertNull(request.getExistingGrant());
		assertNull(request.getDeviceSecret());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(ENDPOINT.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		ClientSecretBasic basic = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertEquals(CLIENT_ID, basic.getClientID());
		assertEquals(CLIENT_SECRET, basic.getClientSecret());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList(CODE.getValue()), params.get("code"));
		assertEquals(2, params.size());

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(CLIENT_ID, request.getClientAuthentication().getClientID());
		assertEquals(CLIENT_SECRET, ((ClientSecretBasic)request.getClientAuthentication()).getClientSecret());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull("Scope must be skipped", request.getScope());
		assertNull(request.getAuthorizationDetails());
		assertNull(request.getResources());
		assertNull(request.getExistingGrant());
		assertNull(request.getDeviceSecret());
	}


	public void testConstructorWithClientAuthentication_allSet()
		throws Exception {

		ClientSecretBasic clientAuth = new ClientSecretBasic(CLIENT_ID, CLIENT_SECRET);
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(CODE, null);
		List<AuthorizationDetail> authorizationDetails = Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("example_api")).build());
		List<URI> resources = Arrays.asList(URI.create("https://rs1.com"), URI.create("https://rs2.com"));
		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("x", Collections.singletonList("100"));
		customParams.put("y", Collections.singletonList("200"));

		TokenRequest request = new TokenRequest(ENDPOINT, clientAuth, grant, SCOPE, authorizationDetails, resources, DEVICE_SECRET, customParams);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertEquals(SCOPE, request.getScope());
		assertEquals(resources, request.getResources());
		assertNull(request.getExistingGrant());
		assertEquals(DEVICE_SECRET, request.getDeviceSecret());
		assertEquals(customParams, request.getCustomParameters());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(ENDPOINT.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		ClientSecretBasic basic = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertEquals(clientAuth.getClientID(), basic.getClientID());
		assertEquals(clientAuth.getClientSecret(), basic.getClientSecret());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList(CODE.getValue()), params.get("code"));
		assertEquals(AuthorizationDetail.toJSONString(authorizationDetails), MultivaluedMapUtils.getFirstValue(params, "authorization_details"));
		assertEquals(Arrays.asList("https://rs1.com", "https://rs2.com"), params.get("resource"));
		assertEquals(DEVICE_SECRET.getValue(), MultivaluedMapUtils.getFirstValue(params, "device_secret"));
		assertEquals("100", MultivaluedMapUtils.getFirstValue(params, "x"));
		assertEquals("200", MultivaluedMapUtils.getFirstValue(params, "y"));
		assertEquals(7, params.size());
	}


	public void testConstructorWithClientAuthenticationAndNoScope_deprecated()
		throws Exception {

		ClientAuthentication clientAuth = new ClientSecretBasic(CLIENT_ID, CLIENT_SECRET);
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(CODE, null);

		TokenRequest request = new TokenRequest(ENDPOINT, clientAuth, grant);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
		assertNull(request.getResources());
		assertNull(request.getExistingGrant());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(ENDPOINT.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		ClientSecretBasic basic = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertEquals("123", basic.getClientID().getValue());
		assertEquals(CLIENT_SECRET, basic.getClientSecret());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList(CODE.getValue()), params.get("code"));
		assertEquals(2, params.size());
	}


	public void testConstructorWithPubKeyTLSClientAuth()
		throws Exception {

		ClientAuthentication clientAuth = new SelfSignedTLSClientAuthentication(CLIENT_ID, (SSLSocketFactory)null);
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(CODE, null);

		TokenRequest request = new TokenRequest(ENDPOINT, clientAuth, grant, null);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
		assertNull(request.getResources());
		assertNull(request.getExistingGrant());
		assertNull(request.getDeviceSecret());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(ENDPOINT.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList(CODE.getValue()), params.get("code"));
		assertEquals(Collections.singletonList(CLIENT_ID.getValue()), params.get("client_id"));
		assertEquals(3, params.size());
	}


	public void testConstructorWithTLSClientAuth()
		throws Exception {

		ClientAuthentication clientAuth = new PKITLSClientAuthentication(CLIENT_ID, (SSLSocketFactory) null);
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(CODE, null);

		TokenRequest request = new TokenRequest(ENDPOINT, clientAuth, grant, null);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
		assertNull(request.getResources());
		assertNull(request.getExistingGrant());
		assertNull(request.getDeviceSecret());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(ENDPOINT.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList(CODE.getValue()), params.get("code"));
		assertEquals(Collections.singletonList(CLIENT_ID.getValue()), params.get("client_id"));
		assertEquals(3, params.size());
	}


	public void testRejectNullClientAuthentication() {

		try {
			new TokenRequest(ENDPOINT, (ClientAuthentication)null, new ClientCredentialsGrant(), null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}


	public void testPublicClientConstructor_minimal()
		throws Exception {

		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(CODE, new URI("http://example.com/in"));

		TokenRequest request = new TokenRequest(ENDPOINT, CLIENT_ID, grant, null);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(CLIENT_ID, request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
		assertNull(request.getAuthorizationDetails());
		assertNull(request.getResources());
		assertNull(request.getExistingGrant());
		assertNull(request.getDeviceSecret());
		assertTrue(request.getCustomParameters().isEmpty());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(ENDPOINT.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertNull(httpRequest.getAuthorization());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList(CODE.getValue()), params.get("code"));
		assertEquals(Collections.singletonList(CLIENT_ID.getValue()), params.get("client_id"));
		assertEquals(Collections.singletonList("http://example.com/in"), params.get("redirect_uri"));
		assertEquals(4, params.size());
		
		request = TokenRequest.parse(httpRequest);
		
		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(CLIENT_ID, request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
		assertNull(request.getAuthorizationDetails());
		assertNull(request.getResources());
		assertNull(request.getExistingGrant());
		assertNull(request.getDeviceSecret());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testPublicClientConstructor_allSet()
		throws Exception {

		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(CODE, new URI("http://example.com/in"));
		List<AuthorizationDetail> authorizationDetails = Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("example_api")).build());
		List<URI> resources = Collections.singletonList(URI.create("https://rs1.com"));
		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("x", Collections.singletonList("100"));
		customParams.put("y", Collections.singletonList("200"));

		TokenRequest request = new TokenRequest(ENDPOINT, CLIENT_ID, grant, SCOPE, authorizationDetails, resources, REFRESH_TOKEN, DEVICE_SECRET, customParams);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(CLIENT_ID, request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertEquals(SCOPE, request.getScope());
		assertEquals(authorizationDetails, request.getAuthorizationDetails());
		assertEquals(resources, request.getResources());
		assertEquals(REFRESH_TOKEN, request.getExistingGrant());
		assertEquals(DEVICE_SECRET, request.getDeviceSecret());
		assertEquals(customParams, request.getCustomParameters());
		assertEquals(Collections.singletonList("100"), request.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameter("y"));

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(ENDPOINT.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertNull(httpRequest.getAuthorization());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList(CODE.getValue()), params.get("code"));
		assertEquals(Collections.singletonList(CLIENT_ID.getValue()), params.get("client_id"));
		assertEquals(Collections.singletonList("http://example.com/in"), params.get("redirect_uri"));
		assertEquals(Collections.singletonList(AuthorizationDetail.toJSONString(authorizationDetails)), params.get("authorization_details"));
		assertEquals(Collections.singletonList("https://rs1.com"), params.get("resource"));
		assertEquals(Collections.singletonList(REFRESH_TOKEN.getValue()), params.get("existing_grant"));
		assertEquals(Collections.singletonList(DEVICE_SECRET.getValue()), params.get("device_secret"));
		assertEquals(Collections.singletonList("100"), params.get("x"));
		assertEquals(Collections.singletonList("200"), params.get("y"));
		assertEquals(10, params.size());
		
		request = TokenRequest.parse(httpRequest);
		
		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(CLIENT_ID, request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull("Must be skipped", request.getScope());
		assertEquals(authorizationDetails, request.getAuthorizationDetails());
		assertEquals(resources, request.getResources());
		assertEquals(REFRESH_TOKEN, request.getExistingGrant());
		assertEquals(DEVICE_SECRET, request.getDeviceSecret());
		assertEquals(customParams, request.getCustomParameters());
		assertEquals(Collections.singletonList("100"), request.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameter("y"));
	}


	public void testPublicClientConstructorWithoutScope_deprecated()
		throws Exception {

		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(CODE, new URI("http://example.com/in"));

		TokenRequest request = new TokenRequest(ENDPOINT, CLIENT_ID, grant);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(CLIENT_ID, request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
		assertNull(request.getResources());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(ENDPOINT.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertNull(httpRequest.getAuthorization());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList(CODE.getValue()), params.get("code"));
		assertEquals(Collections.singletonList(CLIENT_ID.getValue()), params.get("client_id"));
		assertEquals(Collections.singletonList("http://example.com/in"), params.get("redirect_uri"));
		assertEquals(4, params.size());
	}


	public void testPublicClientConstructorMissingClientID()
		throws Exception {

		ClientID clientID = null;
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(CODE, new URI("http://example.com/in"));

		try {
			new TokenRequest(ENDPOINT, clientID, grant, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The \"authorization_code\" grant type requires a \"client_id\" parameter", e.getMessage());
		}
	}


	public void testConstructorWithoutClientID()
		throws Exception {

		AuthorizationGrant grant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"));

		TokenRequest request = new TokenRequest(ENDPOINT, grant, SCOPE);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertEquals(SCOPE, request.getScope());
		assertNull(request.getAuthorizationDetails());
		assertNull(request.getResources());
		assertNull(request.getDeviceSecret());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(ENDPOINT.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertNull(httpRequest.getAuthorization());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.PASSWORD.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList("alice"), params.get("username"));
		assertEquals(Collections.singletonList("secret"), params.get("password"));
		assertEquals(Scope.parse("openid email"), Scope.parse(MultivaluedMapUtils.getFirstValue(params, "scope")));
		assertEquals(4, params.size());

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertEquals(SCOPE, request.getScope());
		assertNull(request.getAuthorizationDetails());
		assertNull(request.getResources());
		assertNull(request.getDeviceSecret());
	}


	public void testMinimalConstructorWithoutScope_deprecated()
		throws Exception {

		AuthorizationGrant grant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"));

		TokenRequest request = new TokenRequest(ENDPOINT, grant);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
		assertNull(request.getResources());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(ENDPOINT.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertNull(httpRequest.getAuthorization());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.PASSWORD.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList("alice"), params.get("username"));
		assertEquals(Collections.singletonList("secret"), params.get("password"));
		assertEquals(3, params.size());
	}


	public void testMissingClientCredentialsAuthentication() {

		try {
			new TokenRequest(ENDPOINT, new ClientCredentialsGrant(), null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The \"client_credentials\" grant type requires client authentication", e.getMessage());
		}
	}


	public void testConstructorIllegalResourceURI()
		throws Exception {

		try {
			new TokenRequest(
				ENDPOINT,
				new ClientSecretBasic(CLIENT_ID, CLIENT_SECRET),
				new ClientCredentialsGrant(),
				null,
				Collections.singletonList(new URI("https://api.example.com/data#fragment")),
				null
				);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("Resource URI must be absolute and with no query or fragment: https://api.example.com/data#fragment", e.getMessage());
		}
	}
	
	
	public void testCodeGrantWithBasicSecret()
		throws Exception {
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		
		String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);
		
		String postBody = 
			"grant_type=authorization_code" +
			"&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb";
		
		httpRequest.setBody(postBody);
		
		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertEquals(ENDPOINT, tr.getEndpointURI());

		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, authBasic.getMethod());
		assertEquals("Basic " + authBasicString, authBasic.toHTTPAuthorizationHeader());
		assertEquals("s6BhdRkqt3", authBasic.getClientID().getValue());

		AuthorizationCodeGrant codeGrant = (AuthorizationCodeGrant)tr.getAuthorizationGrant();
		assertEquals(GrantType.AUTHORIZATION_CODE, codeGrant.getType());
		assertEquals("SplxlOBeZQQYbYS6WxSbIA", codeGrant.getAuthorizationCode().getValue());
		assertEquals("https://client.example.com/cb", codeGrant.getRedirectionURI().toString());

		assertNull(tr.getClientID());
		assertNull(tr.getScope());
		assertNull(tr.getResources());
		
		httpRequest = tr.toHTTPRequest();
		
		assertEquals(ENDPOINT, httpRequest.getURI());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(Collections.singletonList("authorization_code"), httpRequest.getBodyAsFormParameters().get("grant_type"));
		assertEquals(Collections.singletonList("SplxlOBeZQQYbYS6WxSbIA"), httpRequest.getBodyAsFormParameters().get("code"));
		assertEquals(Collections.singletonList("https://client.example.com/cb"), httpRequest.getBodyAsFormParameters().get("redirect_uri"));
		assertEquals(3, httpRequest.getBodyAsFormParameters().size());
	}
	
	
	public void testCodeGrantWithPKCE() throws ParseException {
		
		AuthorizationCode code = new AuthorizationCode();
		URI redirectURI = URI.create("app://oauth-callback");
		CodeVerifier pkceVerifier = new CodeVerifier();
		
		TokenRequest request = new TokenRequest(
			ENDPOINT,
			CLIENT_ID,
			new AuthorizationCodeGrant(code, redirectURI, pkceVerifier),
			null);
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		
		assertNull(httpRequest.getAuthorization()); // no client auth here
		
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList(code.getValue()), params.get("code"));
		assertEquals(Collections.singletonList(redirectURI.toString()), params.get("redirect_uri"));
		assertEquals(Collections.singletonList(CLIENT_ID.getValue()), params.get("client_id"));
		assertEquals(Collections.singletonList(pkceVerifier.getValue()), params.get("code_verifier"));
		assertEquals(5, params.size());
	}


	public void testParseCodeGrantWithPKCE()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		String postBody =
			"grant_type=authorization_code" +
			"&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb" +
			"&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" +
			"&client_id=123";

		httpRequest.setBody(postBody);

		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertEquals(ENDPOINT, tr.getEndpointURI());

		assertNull(tr.getClientAuthentication());
		assertEquals(CLIENT_ID, tr.getClientID());

		AuthorizationCodeGrant codeGrant = (AuthorizationCodeGrant)tr.getAuthorizationGrant();
		assertEquals(GrantType.AUTHORIZATION_CODE, codeGrant.getType());
		assertEquals("SplxlOBeZQQYbYS6WxSbIA", codeGrant.getAuthorizationCode().getValue());
		assertEquals("https://client.example.com/cb", codeGrant.getRedirectionURI().toString());
		assertEquals("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", codeGrant.getCodeVerifier().getValue());

		httpRequest = tr.toHTTPRequest();
		
		assertEquals(ENDPOINT, httpRequest.getURI());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		assertNull(httpRequest.getAuthorization());
		assertEquals(Collections.singletonList("authorization_code"), httpRequest.getBodyAsFormParameters().get("grant_type"));
		assertEquals(Collections.singletonList("SplxlOBeZQQYbYS6WxSbIA"), httpRequest.getBodyAsFormParameters().get("code"));
		assertEquals(Collections.singletonList("https://client.example.com/cb"), httpRequest.getBodyAsFormParameters().get("redirect_uri"));
		assertEquals(Collections.singletonList("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), httpRequest.getBodyAsFormParameters().get("code_verifier"));
		assertEquals(Collections.singletonList(CLIENT_ID.getValue()), httpRequest.getBodyAsFormParameters().get("client_id"));
		assertEquals(5, httpRequest.getBodyAsFormParameters().size());
	}

	public void testParseCodeGrantWithPKCE_illegalCodeVerifier() {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		String postBody =
			"grant_type=authorization_code" +
			"&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb" +
			"&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX%40" +
			"&client_id=123";

		httpRequest.setBody(postBody);

		try {
			TokenRequest.parse(httpRequest);
		} catch (ParseException e) {
			assertEquals("Illegal char(s) in code verifier, see RFC 7636, section 4.1", e.getMessage());
		}

	}


	public void testParseRefreshTokenGrantWithBasicSecret()
		throws Exception {
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		
		final String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);
		
		final String postBody = 
			"grant_type=refresh_token" +
			"&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA";
		
		httpRequest.setBody(postBody);
		
		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertEquals(ENDPOINT, tr.getEndpointURI());

		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, authBasic.getMethod());
		assertEquals("Basic " + authBasicString, authBasic.toHTTPAuthorizationHeader());
		assertEquals("s6BhdRkqt3", authBasic.getClientID().getValue());

		RefreshTokenGrant rtGrant = (RefreshTokenGrant)tr.getAuthorizationGrant();
		assertEquals(GrantType.REFRESH_TOKEN, rtGrant.getType());
		assertEquals("tGzv3JOkF0XG5Qx2TlKWIA", rtGrant.getRefreshToken().getValue());
		
		httpRequest = tr.toHTTPRequest();
		
		assertEquals(ENDPOINT, httpRequest.getURI());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(postBody, httpRequest.getBody());
	}


	public void testParsePasswordCredentialsGrant()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		final String postBody = "grant_type=password&username=johndoe&password=A3ddj3w";

		httpRequest.setBody(postBody);

		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertEquals(ENDPOINT, tr.getEndpointURI());

		assertNull(tr.getClientAuthentication());
		assertNull(tr.getClientID());

		ResourceOwnerPasswordCredentialsGrant pwdGrant = (ResourceOwnerPasswordCredentialsGrant)tr.getAuthorizationGrant();
		assertEquals(GrantType.PASSWORD, pwdGrant.getType());
		assertEquals("johndoe", pwdGrant.getUsername());
		assertEquals("A3ddj3w", pwdGrant.getPassword().getValue());

		assertNull(tr.getScope());

		httpRequest = tr.toHTTPRequest();
		
		assertEquals(ENDPOINT, httpRequest.getURI());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		assertNull(httpRequest.getAuthorization());
		assertEquals(Collections.singletonList("password"), httpRequest.getBodyAsFormParameters().get("grant_type"));
		assertEquals(Collections.singletonList("johndoe"), httpRequest.getBodyAsFormParameters().get("username"));
		assertEquals(Collections.singletonList("A3ddj3w"), httpRequest.getBodyAsFormParameters().get("password"));
		assertEquals(3, httpRequest.getBodyAsFormParameters().size());
	}


	public void testParsePasswordCredentialsGrantWithClientAuthentication()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		final String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);

		final String postBody = "grant_type=password&username=johndoe&password=A3ddj3w";

		httpRequest.setBody(postBody);

		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertEquals(ENDPOINT, tr.getEndpointURI());

		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, authBasic.getMethod());
		assertEquals("Basic " + authBasicString, authBasic.toHTTPAuthorizationHeader());
		assertEquals("s6BhdRkqt3", authBasic.getClientID().getValue());

		ResourceOwnerPasswordCredentialsGrant pwdGrant = (ResourceOwnerPasswordCredentialsGrant)tr.getAuthorizationGrant();
		assertEquals(GrantType.PASSWORD, pwdGrant.getType());
		assertEquals("johndoe", pwdGrant.getUsername());
		assertEquals("A3ddj3w", pwdGrant.getPassword().getValue());

		assertNull(tr.getScope());

		httpRequest = tr.toHTTPRequest();
		
		assertEquals(ENDPOINT, httpRequest.getURI());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(Collections.singletonList("password"), httpRequest.getBodyAsFormParameters().get("grant_type"));
		assertEquals(Collections.singletonList("johndoe"), httpRequest.getBodyAsFormParameters().get("username"));
		assertEquals(Collections.singletonList("A3ddj3w"), httpRequest.getBodyAsFormParameters().get("password"));
		assertEquals(3, httpRequest.getBodyAsFormParameters().size());
	}


	public void testParseClientCredentialsGrant()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		final String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);

		final String postBody = "grant_type=client_credentials";

		httpRequest.setBody(postBody);

		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertEquals(ENDPOINT, tr.getEndpointURI());

		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, authBasic.getMethod());
		assertEquals("Basic " + authBasicString, authBasic.toHTTPAuthorizationHeader());
		assertEquals("s6BhdRkqt3", authBasic.getClientID().getValue());

		ClientCredentialsGrant clientCredentialsGrant = (ClientCredentialsGrant)tr.getAuthorizationGrant();
		assertEquals(GrantType.CLIENT_CREDENTIALS, clientCredentialsGrant.getType());

		assertNull(tr.getScope());

		httpRequest = tr.toHTTPRequest();
		
		assertEquals(ENDPOINT, httpRequest.getURI());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(postBody, httpRequest.getBody());
	}


	public void testParseClientCredentialsGrantMissingAuthentication() {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		final String postBody = "grant_type=client_credentials";

		httpRequest.setBody(postBody);

		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_CLIENT, e.getErrorObject());
		}
	}


	public void testSupportTokenRequestClientSecretPostSerialization()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode();
		URI redirectURI = new URI("https://arbitrary.redirect.uri/");
		ClientSecretPost clientAuthentication = new ClientSecretPost(CLIENT_ID, CLIENT_SECRET);
		AuthorizationGrant grant = new AuthorizationCodeGrant(code, redirectURI);
		TokenRequest request = new TokenRequest(ENDPOINT, clientAuthentication, grant);

		HTTPRequest httpRequest = request.toHTTPRequest();
		TokenRequest reconstructedRequest = TokenRequest.parse(httpRequest);
		
		assertEquals(CLIENT_ID, reconstructedRequest.getClientAuthentication().getClientID());
		assertEquals(CLIENT_SECRET, ((ClientSecretPost) reconstructedRequest.getClientAuthentication()).getClientSecret());
		assertEquals(code, ((AuthorizationCodeGrant) reconstructedRequest.getAuthorizationGrant()).getAuthorizationCode());
	}


	// See issue 141
	public void testEmptyClientSecret()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, URI.create("https://googleapis.com/oauth2/v3/token"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("code=0a2b49a9-985d-47cb-b36f-be9ed4927b4c&redirect_uri=https%3A%2F%2Fdevelopers.google.com%2Foauthplayground&client_id=google&client_secret=&scope=&grant_type=authorization_code");

		TokenRequest request = TokenRequest.parse(httpRequest);

		assertEquals("https://googleapis.com/oauth2/v3/token", request.getEndpointURI().toString());
		assertNull(request.getClientAuthentication());
		AuthorizationGrant grant = request.getAuthorizationGrant();
		assertTrue(grant instanceof AuthorizationCodeGrant);

		AuthorizationCodeGrant codeGrant = (AuthorizationCodeGrant)grant;
		assertEquals("0a2b49a9-985d-47cb-b36f-be9ed4927b4c", codeGrant.getAuthorizationCode().getValue());
		assertEquals("https://developers.google.com/oauthplayground", codeGrant.getRedirectionURI().toString());

		assertEquals("google", request.getClientID().getValue());

		assertNull(request.getScope());
	}


	public void testCodeGrant_confidentialClient()
		throws Exception {

		Secret clientSecret = CLIENT_SECRET;
		ClientAuthentication clientAuth = new ClientSecretBasic(CLIENT_ID, clientSecret);
		AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant(new AuthorizationCode("xyz"), new URI("https://example.com/cb"));

		TokenRequest request = new TokenRequest.Builder(ENDPOINT, clientAuth, codeGrant)
			.build();

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertEquals(codeGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(CLIENT_ID, request.getClientAuthentication().getClientID());
		assertEquals(clientSecret, ((ClientSecretBasic)request.getClientAuthentication()).getClientSecret());
		assertEquals(codeGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testCodeGrant_publicClient()
		throws Exception {

		AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant(new AuthorizationCode("xyz"), new URI("https://example.com/cb"));

		TokenRequest request = new TokenRequest.Builder(ENDPOINT, CLIENT_ID, codeGrant)
			.build();

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(CLIENT_ID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(codeGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(CLIENT_ID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(codeGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testCodeGrant_publicClient_pkce()
		throws Exception {

		AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant(new AuthorizationCode("xyz"), new URI("https://example.com/cb"), new CodeVerifier());

		TokenRequest request = new TokenRequest.Builder(ENDPOINT, CLIENT_ID, codeGrant)
			.build();

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(CLIENT_ID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(codeGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(CLIENT_ID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(codeGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testCodeGrant_rejectUnidentifiedClient()
		throws Exception {

		AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant(CODE, new URI("https://example.com/cb"));

		try {
			new TokenRequest.Builder(ENDPOINT, codeGrant)
				.build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("The \"authorization_code\" grant type requires a \"client_id\" parameter", e.getMessage());
		}

		try {
			new TokenRequest(ENDPOINT, codeGrant, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The \"authorization_code\" grant type requires a \"client_id\" parameter", e.getMessage());
		}


		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody(URLUtils.serializeParameters(codeGrant.toParameters()));

		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing required client_id parameter", e.getMessage());
		}
	}


	public void testCodeGrant_parseWithScopeParameter()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		Map<String, List<String>> formParams = new HashMap<>();
		formParams.put("client_id", Collections.singletonList(CLIENT_ID.getValue()));
		formParams.put("grant_type", Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
		formParams.put("code", Collections.singletonList(new AuthorizationCode("ohn3Ohrohwue").getValue()));
		formParams.put("redirect_uri", Collections.singletonList(URI.create("https://example.com/cb").toString()));
		formParams.put("scope", Collections.singletonList(new Scope("read", "write").toString()));
		httpRequest.setBody(URLUtils.serializeParameters(formParams));

		TokenRequest request = TokenRequest.parse(httpRequest);
		assertEquals(CLIENT_ID, request.getClientID());
		AuthorizationGrant grant = request.getAuthorizationGrant();
		AuthorizationCodeGrant codeGrant = (AuthorizationCodeGrant) grant;
		assertEquals(new AuthorizationCode("ohn3Ohrohwue"), codeGrant.getAuthorizationCode());
		assertEquals(URI.create("https://example.com/cb"), codeGrant.getRedirectionURI());
		assertNull(request.getScope());
	}


	public void testPasswordGrant_confidentialClient()
		throws Exception {

		Secret clientSecret = CLIENT_SECRET;
		ClientAuthentication clientAuth = new ClientSecretBasic(CLIENT_ID, clientSecret);
		ResourceOwnerPasswordCredentialsGrant passwordGrant = new ResourceOwnerPasswordCredentialsGrant("alice", CLIENT_SECRET);

		TokenRequest request = new TokenRequest(ENDPOINT, clientAuth, passwordGrant);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertEquals(passwordGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth.getClientID(), request.getClientAuthentication().getClientID());
		assertEquals(passwordGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testPasswordGrant_publicClient()
		throws Exception {

		ResourceOwnerPasswordCredentialsGrant passwordGrant = new ResourceOwnerPasswordCredentialsGrant("alice", CLIENT_SECRET);

		TokenRequest request = new TokenRequest(ENDPOINT, CLIENT_ID, passwordGrant);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(CLIENT_ID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(passwordGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(CLIENT_ID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(passwordGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testPasswordGrant_unspecifiedClient()
		throws Exception {

		ResourceOwnerPasswordCredentialsGrant passwordGrant = new ResourceOwnerPasswordCredentialsGrant("alice", CLIENT_SECRET);

		TokenRequest request = new TokenRequest(ENDPOINT, passwordGrant);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(passwordGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(passwordGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testRefreshTokenGrant_confidentialClient()
		throws Exception {

		Secret clientSecret = CLIENT_SECRET;
		ClientAuthentication clientAuth = new ClientSecretBasic(CLIENT_ID, clientSecret);
		RefreshTokenGrant grant = new RefreshTokenGrant(new RefreshToken("xyz"));

		TokenRequest request = new TokenRequest(ENDPOINT, clientAuth, grant);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth.getClientID(), request.getClientAuthentication().getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testRefreshTokenGrant_publicClient()
		throws Exception {

		RefreshTokenGrant grant = new RefreshTokenGrant(new RefreshToken("xyz"));

		TokenRequest request = new TokenRequest(ENDPOINT, CLIENT_ID, grant);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(CLIENT_ID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(CLIENT_ID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testRefreshTokenGrant_unspecifiedClient()
		throws Exception {

		RefreshTokenGrant grant = new RefreshTokenGrant(new RefreshToken("xyz"));

		TokenRequest request = new TokenRequest(ENDPOINT, grant);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testClientCredentialsGrant_confidentialClient()
		throws Exception {

		Secret clientSecret = CLIENT_SECRET;
		ClientAuthentication clientAuth = new ClientSecretBasic(CLIENT_ID, clientSecret);
		ClientCredentialsGrant grant = new ClientCredentialsGrant();

		TokenRequest request = new TokenRequest(ENDPOINT, clientAuth, grant);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertEquals(GrantType.CLIENT_CREDENTIALS, request.getAuthorizationGrant().getType());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth.getClientID(), request.getClientAuthentication().getClientID());
		assertEquals(GrantType.CLIENT_CREDENTIALS, request.getAuthorizationGrant().getType());
		assertNull(request.getScope());
	}


	public void testClientCredentialsGrant_rejectPublicClient()
		throws Exception {

		ClientCredentialsGrant grant = new ClientCredentialsGrant();

		try {
			new TokenRequest(ENDPOINT, CLIENT_ID, grant);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The \"client_credentials\" grant type requires client authentication", e.getMessage());
		}

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody(URLUtils.serializeParameters(grant.toParameters()));

		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing client authentication", e.getMessage());
		}
	}


	public void testClientCredentialsGrant_rejectUnregisteredClient()
		throws Exception {

		ClientCredentialsGrant grant = new ClientCredentialsGrant();

		try {
			new TokenRequest(ENDPOINT, grant);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The \"client_credentials\" grant type requires client authentication", e.getMessage());
		}

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody(URLUtils.serializeParameters(grant.toParameters()));

		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing client authentication", e.getMessage());
		}
	}


	public void testJWTBearerGrant_confidentialClient()
		throws Exception {

		Secret clientSecret = CLIENT_SECRET;
		ClientAuthentication clientAuth = new ClientSecretBasic(CLIENT_ID, clientSecret);

		SignedJWT jwt = JWTAssertionFactory.create(new JWTAssertionDetails(
			new Issuer("123"),
			new Subject("123"),
			new Audience(ENDPOINT)),
			JWSAlgorithm.HS256,
			new Secret());
		JWTBearerGrant grant = new JWTBearerGrant(jwt);

		TokenRequest request = new TokenRequest(ENDPOINT, clientAuth, grant);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertEquals(GrantType.JWT_BEARER, request.getAuthorizationGrant().getType());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth.getClientID(), request.getClientAuthentication().getClientID());
		assertEquals(GrantType.JWT_BEARER, request.getAuthorizationGrant().getType());
		assertNull(request.getScope());
	}


	public void testJWTBearerGrant_publicClient()
		throws Exception {

		SignedJWT jwt = JWTAssertionFactory.create(new JWTAssertionDetails(
				new Issuer("123"),
				new Subject("123"),
				new Audience(ENDPOINT)),
			JWSAlgorithm.HS256,
			new Secret());
		JWTBearerGrant grant = new JWTBearerGrant(jwt);

		TokenRequest request = new TokenRequest(ENDPOINT, CLIENT_ID, grant);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(CLIENT_ID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(GrantType.JWT_BEARER, request.getAuthorizationGrant().getType());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(CLIENT_ID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(GrantType.JWT_BEARER, request.getAuthorizationGrant().getType());
		assertNull(request.getScope());
	}


	public void testJWTBearerGrant_unregisteredClient()
		throws Exception {

		SignedJWT jwt = JWTAssertionFactory.create(new JWTAssertionDetails(
				new Issuer("123"),
				new Subject("123"),
				new Audience(ENDPOINT)),
			JWSAlgorithm.HS256,
			new Secret());
		JWTBearerGrant grant = new JWTBearerGrant(jwt);

		TokenRequest request = new TokenRequest(ENDPOINT, grant);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(GrantType.JWT_BEARER, request.getAuthorizationGrant().getType());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(GrantType.JWT_BEARER, request.getAuthorizationGrant().getType());
		assertNull(request.getScope());
	}


	public void testSAML2BearerGrant_confidentialClient()
		throws Exception {

		Secret clientSecret = CLIENT_SECRET;
		ClientAuthentication clientAuth = new ClientSecretBasic(CLIENT_ID, clientSecret);

		BasicCredential credential = new BasicCredential(new SecretKeySpec(new Secret().getValueBytes(), "HmacSha256"));
		String samlAssertion = SAML2AssertionFactory.createAsString(new SAML2AssertionDetails(
			new Issuer("123"),
			new Subject("123"),
			new Audience(ENDPOINT)),
			SignatureConstants.ALGO_ID_MAC_HMAC_SHA256,
			credential);
		SAML2BearerGrant grant = new SAML2BearerGrant(Base64URL.encode(samlAssertion));

		TokenRequest request = new TokenRequest(ENDPOINT, clientAuth, grant);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth.getClientID(), request.getClientAuthentication().getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testSAML2BearerGrant_publicClient()
		throws Exception {

		BasicCredential credential = new BasicCredential(new SecretKeySpec(new Secret().getValueBytes(), "HmacSha256"));
		String samlAssertion = SAML2AssertionFactory.createAsString(new SAML2AssertionDetails(
				new Issuer("123"),
				new Subject("123"),
				new Audience(ENDPOINT)),
			SignatureConstants.ALGO_ID_MAC_HMAC_SHA256,
			credential);
		SAML2BearerGrant grant = new SAML2BearerGrant(Base64URL.encode(samlAssertion));

		TokenRequest request = new TokenRequest(ENDPOINT, CLIENT_ID, grant);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(CLIENT_ID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(CLIENT_ID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testSAML2BearerGrant_unregisteredClient()
		throws Exception {

		BasicCredential credential = new BasicCredential(new SecretKeySpec(new Secret().getValueBytes(), "HmacSha256"));
		String samlAssertion = SAML2AssertionFactory.createAsString(new SAML2AssertionDetails(
				new Issuer("123"),
				new Subject("123"),
				new Audience(ENDPOINT)),
			SignatureConstants.ALGO_ID_MAC_HMAC_SHA256,
			credential);
		SAML2BearerGrant grant = new SAML2BearerGrant(Base64URL.encode(samlAssertion));

		TokenRequest request = new TokenRequest(ENDPOINT, grant);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(ENDPOINT, request.getEndpointURI());
		assertNull(request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	// https://bitbucket.org/connect2id/openid-connect-dev-client/issues/5/stripping-equal-sign-from-access_code-in
	public void testCodeGrantEqualsCharEncoding() {

		AuthorizationCode code = new AuthorizationCode("abc=");
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(code, URI.create("https://example.com/cb"));

		TokenRequest request = new TokenRequest(URI.create("https://openid.c2id.com/token"), CLIENT_ID, grant);

		HTTPRequest httpRequest = request.toHTTPRequest();

		String query = httpRequest.getQuery();
		List<String> queryTokens = Arrays.asList(query.split("&"));

		assertTrue(queryTokens.contains("client_id=123"));
		assertTrue(queryTokens.contains("grant_type=authorization_code"));
		assertTrue(queryTokens.contains("code=abc%3D"));
		assertTrue(queryTokens.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcb"));
		assertEquals(4, queryTokens.size());
	}


	public void testCustomParams_codeGrant_basicAuth()
		throws Exception {

		AuthorizationGrant grant = new AuthorizationCodeGrant(new AuthorizationCode(), URI.create("https://example.com/cb"));
		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("data", Collections.singletonList("http://xxxxxx/PartyOData"));

		TokenRequest request = new TokenRequest(
			URI.create("https://c2id.com/token"),
			new ClientSecretBasic(new ClientID(), new Secret()),
			grant,
			Scope.parse("read write"),
			Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("example_api")).build()),
			Collections.singletonList(URI.create("https://api.example.com/")),
			customParams);

		assertEquals(customParams, request.getCustomParameters());
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("data"));

		HTTPRequest httpRequest = request.toHTTPRequest();

		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), httpRequest.getQueryParameters().get("data"));
		assertEquals(6, httpRequest.getBodyAsFormParameters().size());

		request = TokenRequest.parse(httpRequest);
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("data"));
		assertEquals(1, request.getCustomParameters().size());
	}


	public void testCustomParams_codeGrant_postAuth()
		throws Exception {

		AuthorizationGrant grant = new AuthorizationCodeGrant(new AuthorizationCode(), URI.create("https://example.com/cb"));
		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("data", Collections.singletonList("http://xxxxxx/PartyOData"));

		TokenRequest request = new TokenRequest(URI.create("https://c2id.com/token"), new ClientSecretPost(new ClientID(), new Secret()), grant, Scope.parse("read write"), null, customParams);

		assertEquals(customParams, request.getCustomParameters());
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("data"));

		HTTPRequest httpRequest = request.toHTTPRequest();

		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), httpRequest.getQueryParameters().get("data"));
		assertEquals(6, httpRequest.getBodyAsFormParameters().size());

		request = TokenRequest.parse(httpRequest);
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("data"));
		assertEquals(1, request.getCustomParameters().size());
	}


	public void testCustomParams_passwordGrant_postAuth()
		throws Exception {

		AuthorizationGrant grant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret());
		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("data", Collections.singletonList("http://xxxxxx/PartyOData"));

		TokenRequest request = new TokenRequest(URI.create("https://c2id.com/token"), new ClientSecretPost(new ClientID(), new Secret()), grant, Scope.parse("read write"), null, customParams);

		assertEquals(customParams, request.getCustomParameters());
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("data"));

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), httpRequest.getQueryParameters().get("data"));
		assertEquals(7, httpRequest.getBodyAsFormParameters().size());

		request = TokenRequest.parse(httpRequest);
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("data"));
		assertEquals(1, request.getCustomParameters().size());
	}


	public void testCustomParams_clientCredentialsGrant_basicAuth()
		throws Exception {

		AuthorizationGrant grant = new ClientCredentialsGrant();
		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("data", Collections.singletonList("http://xxxxxx/PartyOData"));

		TokenRequest request = new TokenRequest(URI.create("https://c2id.com/token"), new ClientSecretBasic(new ClientID(), new Secret()), grant, Scope.parse("read write"), null, customParams);

		assertEquals(customParams, request.getCustomParameters());
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("data"));

		HTTPRequest httpRequest = request.toHTTPRequest();

//		System.out.println(httpRequest.getQuery());
		assertEquals(Collections.singletonList("client_credentials"), httpRequest.getBodyAsFormParameters().get("grant_type"));
		assertEquals(Collections.singletonList("read write"), httpRequest.getBodyAsFormParameters().get("scope"));
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), httpRequest.getBodyAsFormParameters().get("data"));
		assertEquals(3, httpRequest.getBodyAsFormParameters().size());

		request = TokenRequest.parse(httpRequest);
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("data"));
		assertEquals(1, request.getCustomParameters().size());
	}


	public void testCustomParams_clientCredentialsGrant_postAuth()
		throws Exception {

		AuthorizationGrant grant = new ClientCredentialsGrant();
		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("data", Collections.singletonList("http://xxxxxx/PartyOData"));

		TokenRequest request = new TokenRequest(URI.create("https://c2id.com/token"), new ClientSecretPost(new ClientID(), new Secret()), grant, Scope.parse("read write"), null, customParams);

		assertEquals(customParams, request.getCustomParameters());
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("data"));

		HTTPRequest httpRequest = request.toHTTPRequest();

//		System.out.println(httpRequest.getQuery());
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), httpRequest.getBodyAsFormParameters().get("data"));

		request = TokenRequest.parse(httpRequest);
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("data"));
		assertEquals(1, request.getCustomParameters().size());
	}


	public void testCustomParams_clientCredentialsGrant_jwtAuth()
		throws Exception {

		AuthorizationGrant grant = new ClientCredentialsGrant();
		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("data", Collections.singletonList("http://xxxxxx/PartyOData"));

		TokenRequest request = new TokenRequest(URI.create("https://c2id.com/token"), new ClientSecretJWT(new ClientID(), URI.create("https://c2id.com/token"), JWSAlgorithm.HS256, new Secret()), grant, Scope.parse("read write"), null, customParams);

		assertEquals(customParams, request.getCustomParameters());
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("data"));

		HTTPRequest httpRequest = request.toHTTPRequest();

//		System.out.println(httpRequest.getQuery());
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), httpRequest.getBodyAsFormParameters().get("data"));

		request = TokenRequest.parse(httpRequest);
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("data"));
//		System.out.println(request.getCustomParameters());
		assertEquals(1, request.getCustomParameters().size());
	}
	
	
	public void testCodeGrantWithBasicSecret_parseMalformedBasicAuth_missingDelimiter()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		
		httpRequest.setAuthorization("Basic " + Base64.encode("alice"));
		
		String postBody =
			"grant_type=authorization_code" +
				"&code=SplxlOBeZQQYbYS6WxSbIA" +
				"&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb";
		
		httpRequest.setBody(postBody);
		
		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Malformed client secret basic authentication (see RFC 6749, section 2.3.1): Missing credentials delimiter (:)", e.getMessage());
			
			assertEquals(OAuth2Error.INVALID_REQUEST.toString(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Malformed client secret basic authentication (see RFC 6749, section 2.3.1): Missing credentials delimiter (:)", e.getErrorObject().getDescription());
		}
	}
	
	
	// Reject basic + client_secret_jwt auth present in the same token request
	public void testRejectMultipleClientAuthMethods()
		throws Exception {
		
		Secret clientSecret = new Secret();
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setAuthorization(new ClientSecretBasic(CLIENT_ID, clientSecret).toHTTPAuthorizationHeader());
		
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode(), URI.create("https://example.com/cb"));
		
		ClientSecretJWT clientSecretJWT = new ClientSecretJWT(CLIENT_ID, ENDPOINT, JWSAlgorithm.HS256, clientSecret);
		
		Map<String,List<String>> bodyParams = new HashMap<>();
		bodyParams.putAll(grant.toParameters());
		bodyParams.putAll(clientSecretJWT.toParameters());
		
		httpRequest.setBody(URLUtils.serializeParameters(bodyParams));
		
		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Multiple conflicting client authentication methods found: Basic and JWT assertion", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Multiple conflicting client authentication methods found: Basic and JWT assertion", e.getErrorObject().getDescription());
		}
	}
	
	
	// iss208
	public void testClientSecretBasicDecodingException()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setAuthorization("Basic KVQdqB25zeFg4duoJf7ZYo4wDMXtQjqlpxWdgFm06vc");
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setHeader("Cache-Control", "no-cache");
		httpRequest.setBody("grant_type=authorization_code" +
			"&code=a0x3DwU3vE9Ad1CbWdy1LQ.KaPahOgJJjODKWE47-DXzg" +
			"&redirect_uri=dufryred%3A%2F%2Foauth.callback" +
			"&code_verifier=VjdnvRw3_nTdhoWLcwYBjVt2wQnklP-gcXRmFXvQcM6OhMqDQOXWhXQvqHeCbgOlJHsu8xDVyRU0vRaMzuEKbQ" +
			"&client_id=47ub27skbkcf2");
		
		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Malformed client secret basic authentication (see RFC 6749, section 2.3.1): Invalid URL encoding", e.getMessage());
		}
	}


	public void testParseRAR_illegalAuthorizationDetail()
		throws URISyntaxException, ParseException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URI("https://demo.c2id.com/token"));
		httpRequest.setContentType("application/x-www-form-urlencoded");
		httpRequest.setBody(
			"client_id=123" +
			"&grant_type=authorization_code" +
			"&code=Neak8Aig4es4NooS" +
			"&authorization_details=[{},{}]"
		);

		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid authorization details: Invalid authorization detail at position 0: Illegal or missing type", e.getMessage());
		}
	}
	
	
	public void testParseResourceIndicatorsExample()
		throws Exception {
		
		// POST /as/token.oauth2 HTTP/1.1
		// Host: authorization-server.example.com
		// Authorization: Basic czZCaGRSa3F0Mzpoc3FFelFsVW9IQUU5cHg0RlNyNHlJ
		// Content-Type: application/x-www-form-urlencoded
		//
		// grant_type=refresh_token
		// &refresh_token=4LTC8lb0acc6Oy4esc1Nk9BWC0imAwH
		// &resource=https%3A%2F%2Frs.example.com%2F
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://authorization-server.example.com/as/token.oauth2"));
		httpRequest.setAuthorization("Basic czZCaGRSa3F0Mzpoc3FFelFsVW9IQUU5cHg0RlNyNHlJ");
		httpRequest.setContentType("application/x-www-form-urlencoded");
		httpRequest.setBody("grant_type=refresh_token&refresh_token=4LTC8lb0acc6Oy4esc1Nk9BWC0imAwH&resource=https%3A%2F%2Frs.example.com%2F");
		
		TokenRequest request = TokenRequest.parse(httpRequest);
		
		assertEquals(httpRequest.getURL().toURI(), request.getEndpointURI());
		assertTrue(request.getClientAuthentication() instanceof ClientSecretBasic);
		ClientSecretBasic clientSecretBasic = (ClientSecretBasic) request.getClientAuthentication();
		assertEquals("s6BhdRkqt3", clientSecretBasic.getClientID().getValue());
		assertEquals("hsqEzQlUoHAE9px4FSr4yI", clientSecretBasic.getClientSecret().getValue());
		
		assertEquals(new RefreshToken("4LTC8lb0acc6Oy4esc1Nk9BWC0imAwH"), ((RefreshTokenGrant) request.getAuthorizationGrant()).getRefreshToken());
		assertEquals(Collections.singletonList(URI.create("https://rs.example.com/")), request.getResources());
	}
	
	
	public void testParseResource_rejectNonAbsoluteURI()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://authorization-server.example.com/as/token.oauth2"));
		httpRequest.setAuthorization("Basic czZCaGRSa3F0Mzpoc3FFelFsVW9IQUU5cHg0RlNyNHlJ");
		httpRequest.setContentType("application/x-www-form-urlencoded");
		httpRequest.setBody("grant_type=refresh_token&refresh_token=4LTC8lb0acc6Oy4esc1Nk9BWC0imAwH&resource=/api/v1");
		
		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_TARGET, e.getErrorObject());
			assertEquals("Illegal resource parameter: Must be an absolute URI without a fragment: /api/v1", e.getErrorObject().getDescription());
		}
	}
	
	
	public void testParseResource_rejectURIWithFragment()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://authorization-server.example.com/as/token.oauth2"));
		httpRequest.setAuthorization("Basic czZCaGRSa3F0Mzpoc3FFelFsVW9IQUU5cHg0RlNyNHlJ");
		httpRequest.setContentType("application/x-www-form-urlencoded");
		httpRequest.setBody("grant_type=refresh_token&refresh_token=4LTC8lb0acc6Oy4esc1Nk9BWC0imAwH&resource=https%3A%2F%2Frs.example.com%2F#fragment");
		
		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_TARGET, e.getErrorObject());
			assertEquals("Illegal resource parameter: Must be an absolute URI without a fragment: https://rs.example.com/#fragment", e.getErrorObject().getDescription());
		}
	}
	
	
	// https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0-03.html#rfc.section.10.1
	public void testParseCIBAExample()
		throws MalformedURLException, ParseException {
	
		URL endpoint = new URL("https://server.example.com/token");
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpoint);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("grant_type=urn%3Aopenid%3Aparams%3Agrant-type%3Aciba&" +
			"auth_req_id=1c266114-a1be-4252-8ad1-04986c5b9ac1&" +
			"client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&" +
			"client_assertion=eyJraWQiOiJsdGFjZXNidyIsImFsZyI6IkVTMjU2In0.ey" +
			"Jpc3MiOiJzNkJoZFJrcXQzIiwic3ViIjoiczZCaGRSa3F0MyIsImF1ZCI6Imh0d" +
			"HBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwianRpIjoiLV9wMTZqNkhj" +
			"aVhvMzE3aHZaMzEyYyIsImlhdCI6MTUzNzgxOTQ5MSwiZXhwIjoxNTM3ODE5Nzg" +
			"yfQ.BjaEoqZb-81gE5zz4UYwNpC3QVSeX5XhH176vg35zjkbq3Zmv_UpHB2ZugR" +
			"Va344WchTQVpaSSShLbvha4yziA");
		
		TokenRequest request = TokenRequest.parse(httpRequest);
		
		PrivateKeyJWT privateKeyJWT = (PrivateKeyJWT) request.getClientAuthentication();
		assertEquals(new ClientID("s6BhdRkqt3"), privateKeyJWT.getClientID());
		assertEquals(new ClientID("s6BhdRkqt3"), privateKeyJWT.getJWTAuthenticationClaimsSet().getClientID());
		assertEquals(new Issuer("s6BhdRkqt3"), privateKeyJWT.getJWTAuthenticationClaimsSet().getIssuer());
		assertEquals(Collections.singletonList(new Audience("https://server.example.com/token")), privateKeyJWT.getJWTAuthenticationClaimsSet().getAudience());
		assertEquals(new JWTID("-_p16j6HciXo317hvZ312c"), privateKeyJWT.getJWTAuthenticationClaimsSet().getJWTID());
		assertEquals(DateUtils.fromSecondsSinceEpoch(1537819491L), privateKeyJWT.getJWTAuthenticationClaimsSet().getIssueTime());
		assertEquals(DateUtils.fromSecondsSinceEpoch(1537819782L), privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime());
		assertEquals(GrantType.CIBA, request.getAuthorizationGrant().getType());
		CIBAGrant cibaGrant = (CIBAGrant) request.getAuthorizationGrant();
		assertEquals(new AuthRequestID("1c266114-a1be-4252-8ad1-04986c5b9ac1"), cibaGrant.getAuthRequestID());
	}
	
	
	// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/345/token-and-authz-request-must-fail-with-400
	public void testParse_repeatedParameter()
		throws Exception {
		
		ClientAuthentication clientAuth = new ClientSecretBasic(CLIENT_ID, CLIENT_SECRET);
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(CODE, null);
		Scope scope = new Scope("openid", "email");

		TokenRequest request = new TokenRequest(ENDPOINT, clientAuth, grant, scope);
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		Map<String, List<String>> params = httpRequest.getBodyAsFormParameters();
		
		// Duplicate param
		for (String paramName: Arrays.asList("grant_type", "code")) {
			Map<String, List<String>> paramsCopy = new HashMap<>(params);
			String value = MultivaluedMapUtils.getFirstValue(params, paramName);
			paramsCopy.put(paramName, Arrays.asList("injected", value));
			httpRequest.setBody(URLUtils.serializeParameters(paramsCopy));
			
			try {
				TokenRequest.parse(httpRequest);
				fail();
			} catch (ParseException e) {
				assertEquals("Parameter(s) present more than once: [" + paramName  + "]", e.getMessage());
				assertEquals(400, e.getErrorObject().getHTTPStatusCode());
				assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
				assertEquals("Parameter(s) present more than once: [" + paramName  + "]", e.getErrorObject().getDescription());
			}
		}
	}
	
	
	public void testBasicTokenExchange()
		throws URISyntaxException, MalformedURLException, ParseException {
		
		URI endpoint = new URI("https://c2id.com/token");
		
		Secret clientSecret = new Secret("eef7cheemooPhohp2aihaesah7ohzais");
		ClientSecretBasic basicAuth = new ClientSecretBasic(CLIENT_ID, clientSecret);
		
		TypelessToken subjectToken = new TypelessToken("aexo7OMaiphivoot");
		TokenTypeURI subjectTokenType = TokenTypeURI.ACCESS_TOKEN;
		AuthorizationGrant grant = new TokenExchangeGrant(
			subjectToken,
			subjectTokenType,
			null,
			null,
			null,
			null
		);
		
		Scope scope = new Scope("read", "write");
		
		TokenRequest request = new TokenRequest(endpoint, basicAuth, grant, scope);
		
		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(basicAuth, request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertEquals(scope, request.getScope());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(endpoint.toURL(), httpRequest.getURL());
		assertEquals(basicAuth.toHTTPAuthorizationHeader(), httpRequest.getAuthorization());
		assertEquals(ContentType.APPLICATION_URLENCODED, httpRequest.getEntityContentType());
		
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.TOKEN_EXCHANGE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList(subjectToken.getValue()), params.get("subject_token"));
		assertEquals(Collections.singletonList(subjectTokenType.toString()), params.get("subject_token_type"));
		assertEquals(Collections.singletonList(scope.toString()), params.get("scope"));
		assertEquals(4, params.size());
		
		request = TokenRequest.parse(httpRequest);
		
		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(basicAuth.getClientID(), request.getClientAuthentication().getClientID());
		assertEquals(basicAuth.getClientSecret(), ((ClientSecretBasic)request.getClientAuthentication()).getClientSecret());
		assertTrue(request.getAuthorizationGrant() instanceof TokenExchangeGrant);
		TokenExchangeGrant parsedGrant = (TokenExchangeGrant)request.getAuthorizationGrant();
		assertEquals(subjectToken, parsedGrant.getSubjectToken());
		assertEquals(subjectTokenType, parsedGrant.getSubjectTokenType());
		assertEquals(grant.toParameters(), parsedGrant.toParameters());
		assertEquals(scope, request.getScope());
	}

	
	public void testParseTokenExchangeExample() throws MalformedURLException, ParseException {

		URL endpoint = new URL("https://server.example.com/token");
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpoint);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&"
				+ "audience=urn%3Aexample%3Acooperation-context&"
				+ "subject_token=eyJhbGciOiJFUzI1NiIsImtpZCI6IjE2In0.eyJhdWQiOiJodHRwczovL2FzLmV4YW1wbGUuY29tIiwiaXNzIjoiaHR0c"
				+ "HM6Ly9vcmlnaW5hbC1pc3N1ZXIuZXhhbXBsZS5uZXQiLCJleHAiOjE0NDE5MTA2MDAsIm5iZiI6MTQ0MTkwOTAwMCwic3ViIjoiYmRjQGV4"
				+ "YW1wbGUubmV0Iiwic2NvcGUiOiJvcmRlcnMgcHJvZmlsZSBoaXN0b3J5In0.PRBg-jXn4cJuj1gmYXFiGkZzRuzbXZ_sDxdE98ddW44ufsb"
				+ "WLKd3JJ1VZhF64pbTtfjy4VXFVBDaQpKjn5JzAw&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt");

		TokenRequest request = TokenRequest.parse(httpRequest);

		ClientAuthentication clientAuthentication = request.getClientAuthentication();
		assertNull(clientAuthentication);
		assertEquals(GrantType.TOKEN_EXCHANGE, request.getAuthorizationGrant().getType());
		assertNull(request.getResources());
		TokenExchangeGrant tokenExchangeGrant = (TokenExchangeGrant) request.getAuthorizationGrant();
		assertEquals(new Audience("urn:example:cooperation-context").toSingleAudienceList(), tokenExchangeGrant.getAudience());
		assertNull(request.getScope());
		assertNull(tokenExchangeGrant.getRequestedTokenType());
		String expectedSubjectToken = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjE2In0.eyJhdWQiOiJodHRwczovL2FzLmV4YW1wbGUuY29tIiwiaXNzI"
				+ "joiaHR0cHM6Ly9vcmlnaW5hbC1pc3N1ZXIuZXhhbXBsZS5uZXQiLCJleHAiOjE0NDE5MTA2MDAsIm5iZiI6MTQ0MTkwOTAwMCwic3ViIjoiYm"
				+ "RjQGV4YW1wbGUubmV0Iiwic2NvcGUiOiJvcmRlcnMgcHJvZmlsZSBoaXN0b3J5In0.PRBg-jXn4cJuj1gmYXFiGkZzRuzbXZ_sDxdE98ddW44"
				+ "ufsbWLKd3JJ1VZhF64pbTtfjy4VXFVBDaQpKjn5JzAw";
		assertEquals(expectedSubjectToken, tokenExchangeGrant.getSubjectToken().getValue());
		assertEquals("urn:ietf:params:oauth:token-type:jwt", tokenExchangeGrant.getSubjectTokenType().getURI().toString());
		assertNull(tokenExchangeGrant.getActorToken());
		assertNull(tokenExchangeGrant.getActorTokenType());
	}
	

	public void testParseTokenExchangeWithMultipleAudience()
			throws MalformedURLException, ParseException, URISyntaxException {

		URL endpoint = new URL("https://server.example.com/token");
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpoint);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&"
				+ "audience=urn%3Aexample%3Acooperation-context1&audience=urn%3Aexample%3Acooperation-context2&"
				+ "resource=https%3A%2F%2Fbackend.example.com%2Fapi&"
				+ "subject_token=subjectToken&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token");

		TokenRequest request = TokenRequest.parse(httpRequest);

		ClientAuthentication clientAuthentication = request.getClientAuthentication();
		assertNull(clientAuthentication);
		assertEquals(GrantType.TOKEN_EXCHANGE, request.getAuthorizationGrant().getType());
		assertEquals(Collections.singletonList(new URI("https://backend.example.com/api")), request.getResources());
		TokenExchangeGrant tokenExchangeGrant = (TokenExchangeGrant) request.getAuthorizationGrant();
		assertEquals(Audience.create("urn:example:cooperation-context1", "urn:example:cooperation-context2"), tokenExchangeGrant.getAudience());
		assertNull(request.getScope());
		assertNull(tokenExchangeGrant.getRequestedTokenType());
		assertEquals("subjectToken", tokenExchangeGrant.getSubjectToken().getValue());
		assertEquals("urn:ietf:params:oauth:token-type:access_token", tokenExchangeGrant.getSubjectTokenType().getURI().toString());
		assertNull(tokenExchangeGrant.getActorToken());
		assertNull(tokenExchangeGrant.getActorTokenType());
	}
	
	
	public void _testTokenExchangeDocExample() throws Exception {
	
		// The client credentials for a basic authentication
		ClientID clientID = new ClientID("rs08");
		Secret clientSecret = new Secret("eij8teegie3aequuQu9quahp7Vea7ohf");
		ClientSecretBasic clientSecretBasic = new ClientSecretBasic(clientID, clientSecret);
		
		// The upstream access token (must have been validated)
		AccessToken accessToken = new BearerAccessToken("accVkjcJyb4BWCxGsndESCJQbdFMogUC5PbRDqceLTC");
		
		// Compose the token exchange request
		URI tokenEndpoint = new URI("https://as.example.com/as/token.oauth2");
		List<URI> resources = Collections.singletonList(new URI("https://backend.example.com/api"));
		Scope scope = null; // default scope for resource
		
		TokenRequest tokenRequest = new TokenRequest(
			tokenEndpoint,
			clientSecretBasic,
			new TokenExchangeGrant(
				accessToken,
				TokenTypeURI.ACCESS_TOKEN),
			scope,
			resources,
			null);
		
		// Send the token request
		HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
		HTTPResponse httpResponse = httpRequest.send();
		
		// Parse the token response
		TokenResponse tokenResponse = TokenResponse.parse(httpResponse);
		
		if (! tokenResponse.indicatesSuccess()) {
			// The token request failed
			ErrorObject errorObject = tokenResponse.toErrorResponse().getErrorObject();
			System.out.println(errorObject.getHTTPStatusCode());
			return;
		}
		
		AccessTokenResponse tokenSuccessResponse = tokenResponse.toSuccessResponse();
		
		// Expecting access token of type Bearer
		AccessToken downstreamToken = tokenSuccessResponse.getTokens().getAccessToken();
		
		if (! AccessTokenType.BEARER.equals(downstreamToken.getType()) &&
		    ! TokenTypeURI.ACCESS_TOKEN.equals(downstreamToken.getIssuedTokenType())) {
			// Unexpected token type
			System.out.println("Received unexpected token:" + downstreamToken.getIssuedTokenType());
			return;
		}
		
		// Use the downstream token...
	}
	

	public void testParseTokenExchange_missingSubjectToken() {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody(
			"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&" +
			"subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"
		);

		try{
			TokenRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals(400, e.getErrorObject().getHTTPStatusCode());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing or empty subject_token parameter", e.getErrorObject().getDescription());
		}
	}


	public void testScopeRequirementInTokenRequest()
		throws Exception {

		ClientAuthentication clientAuth = new ClientSecretBasic(CLIENT_ID, CLIENT_SECRET);

		for (AuthorizationGrant grant: Arrays.asList(
                        new AuthorizationCodeGrant(CODE, null),
			new ClientCredentialsGrant(),
			new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("iecohw6aek2cohchoh5Uicheexe9eemu")),
			new RefreshTokenGrant(REFRESH_TOKEN),
			new DeviceCodeGrant(DEVICE_CODE),
			new CIBAGrant(AUTH_REQUEST_ID)
		)) {

			TokenRequest request = new TokenRequest(ENDPOINT, clientAuth, grant, SCOPE);

			assertEquals(SCOPE, request.getScope());
			HTTPRequest httpRequest = request.toHTTPRequest();
			Map<String, List<String>> params = httpRequest.getBodyAsFormParameters();
			if (grant.getType().getScopeRequirementInTokenRequest() != ParameterRequirement.NOT_ALLOWED) {
				assertEquals(Collections.singletonList(SCOPE.toString()), params.get("scope"));
			} else {
				assertNull(params.get("scope"));
			}
		}
	}
}
