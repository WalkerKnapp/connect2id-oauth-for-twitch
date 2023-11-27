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


import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSocketFactory;

import com.nimbusds.oauth2.sdk.device.DeviceCode;
import com.nimbusds.oauth2.sdk.device.DeviceCodeGrant;
import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail;
import com.nimbusds.oauth2.sdk.rar.AuthorizationType;
import junit.framework.TestCase;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.xmlsec.signature.P;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

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
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.*;
import com.nimbusds.oauth2.sdk.tokenexchange.TokenExchangeGrant;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;


public class TokenRequestTest extends TestCase {


	public void testConstructorWithClientAuthentication()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID("123"), new Secret("secret"));
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), null);
		Scope scope = Scope.parse("openid email");

		TokenRequest request = new TokenRequest(uri, clientAuth, grant, scope);

		assertEquals(uri, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertEquals(scope, request.getScope());
		assertNull(request.getAuthorizationDetails());
		assertNull(request.getResources());
		assertNull(request.getExistingGrant());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		ClientSecretBasic basic = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertEquals("123", basic.getClientID().getValue());
		assertEquals("secret", basic.getClientSecret().getValue());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList("abc"), params.get("code"));
		assertEquals(2, params.size());
	}


	public void testFullConstructorWithClientAuthentication()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientSecretBasic clientAuth = new ClientSecretBasic(new ClientID("123"), new Secret("secret"));
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), null);
		Scope scope = Scope.parse("openid email");
		List<AuthorizationDetail> authorizationDetails = Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("example_api")).build());
		List<URI> resources = Arrays.asList(URI.create("https://rs1.com"), URI.create("https://rs2.com"));
		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("x", Collections.singletonList("100"));
		customParams.put("y", Collections.singletonList("200"));

		TokenRequest request = new TokenRequest(uri, clientAuth, grant, scope, authorizationDetails, resources, customParams);

		assertEquals(uri, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertEquals(scope, request.getScope());
		assertEquals(resources, request.getResources());
		assertNull(request.getExistingGrant());
		assertEquals(customParams, request.getCustomParameters());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		ClientSecretBasic basic = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertEquals(clientAuth.getClientID(), basic.getClientID());
		assertEquals(clientAuth.getClientSecret(), basic.getClientSecret());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList("abc"), params.get("code"));
		assertEquals(AuthorizationDetail.toJSONString(authorizationDetails), MultivaluedMapUtils.getFirstValue(params, "authorization_details"));
		assertEquals(Arrays.asList("https://rs1.com", "https://rs2.com"), params.get("resource"));
		assertEquals("100", MultivaluedMapUtils.getFirstValue(params, "x"));
		assertEquals("200", MultivaluedMapUtils.getFirstValue(params, "y"));
		assertEquals(6, params.size());
	}


	public void testConstructorWithClientAuthenticationAndNoScope()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID("123"), new Secret("secret"));
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), null);

		TokenRequest request = new TokenRequest(uri, clientAuth, grant);

		assertEquals(uri, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
		assertNull(request.getResources());
		assertNull(request.getExistingGrant());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		ClientSecretBasic basic = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertEquals("123", basic.getClientID().getValue());
		assertEquals("secret", basic.getClientSecret().getValue());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList("abc"), params.get("code"));
		assertEquals(2, params.size());
	}


	public void testConstructorWithPubKeyTLSClientAuth()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientAuthentication clientAuth = new SelfSignedTLSClientAuthentication(new ClientID("123"), (SSLSocketFactory)null);
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), null);

		TokenRequest request = new TokenRequest(uri, clientAuth, grant);

		assertEquals(uri, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
		assertNull(request.getResources());
		assertNull(request.getExistingGrant());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList("abc"), params.get("code"));
		assertEquals(Collections.singletonList("123"), params.get("client_id"));
		assertEquals(3, params.size());
	}


	public void testConstructorWithTLSClientAuth()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientAuthentication clientAuth = new PKITLSClientAuthentication(new ClientID("123"), (SSLSocketFactory) null);
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), null);

		TokenRequest request = new TokenRequest(uri, clientAuth, grant);

		assertEquals(uri, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
		assertNull(request.getResources());
		assertNull(request.getExistingGrant());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList("abc"), params.get("code"));
		assertEquals(Collections.singletonList("123"), params.get("client_id"));
		assertEquals(3, params.size());
	}


	public void testRejectNullClientAuthentication()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");

		try {
			new TokenRequest(uri, (ClientAuthentication)null, new ClientCredentialsGrant(), null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The client authentication must not be null", e.getMessage());
		}
	}


	public void testPublicClientConstructor_minimal()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), new URI("http://example.com/in"));

		TokenRequest request = new TokenRequest(uri, clientID, grant, null, null, null, null);

		assertEquals(uri, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(clientID, request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
		assertNull(request.getAuthorizationDetails());
		assertNull(request.getResources());
		assertNull(request.getExistingGrant());
		assertTrue(request.getCustomParameters().isEmpty());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertNull(httpRequest.getAuthorization());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList("abc"), params.get("code"));
		assertEquals(Collections.singletonList("123"), params.get("client_id"));
		assertEquals(Collections.singletonList("http://example.com/in"), params.get("redirect_uri"));
		assertEquals(4, params.size());
		
		request = TokenRequest.parse(httpRequest);
		
		assertEquals(uri, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(clientID, request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
		assertNull(request.getAuthorizationDetails());
		assertNull(request.getResources());
		assertNull(request.getExistingGrant());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testPublicClientConstructor_allSet()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), new URI("http://example.com/in"));
		Scope scope = new Scope("read", "write");
		List<AuthorizationDetail> authorizationDetails = Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("example_api")).build());
		List<URI> resources = Collections.singletonList(URI.create("https://rs1.com"));
		RefreshToken existingGrant = new RefreshToken("shei6zoGhijohquu");
		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("x", Collections.singletonList("100"));
		customParams.put("y", Collections.singletonList("200"));

		TokenRequest request = new TokenRequest(uri, clientID, grant, scope, authorizationDetails, resources, existingGrant, customParams);

		assertEquals(uri, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(clientID, request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertEquals(scope, request.getScope());
		assertEquals(authorizationDetails, request.getAuthorizationDetails());
		assertEquals(resources, request.getResources());
		assertEquals(existingGrant, request.getExistingGrant());
		assertEquals(customParams, request.getCustomParameters());
		assertEquals(Collections.singletonList("100"), request.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameter("y"));

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertNull(httpRequest.getAuthorization());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList("abc"), params.get("code"));
		assertEquals(Collections.singletonList("123"), params.get("client_id"));
		assertEquals(Collections.singletonList("http://example.com/in"), params.get("redirect_uri"));
		assertEquals(Collections.singletonList(AuthorizationDetail.toJSONString(authorizationDetails)), params.get("authorization_details"));
		assertEquals(Collections.singletonList("https://rs1.com"), params.get("resource"));
		assertEquals(Collections.singletonList(existingGrant.getValue()), params.get("existing_grant"));
		assertEquals(Collections.singletonList("100"), params.get("x"));
		assertEquals(Collections.singletonList("200"), params.get("y"));
		assertEquals(9, params.size());
		
		request = TokenRequest.parse(httpRequest);
		
		assertEquals(uri, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(clientID, request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertEquals(authorizationDetails, request.getAuthorizationDetails());
		assertEquals(resources, request.getResources());
		assertEquals(existingGrant, request.getExistingGrant());
		assertEquals(customParams, request.getCustomParameters());
		assertEquals(Collections.singletonList("100"), request.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameter("y"));
	}


	public void testConstructorWithClientIDAndNoScope()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), new URI("http://example.com/in"));

		TokenRequest request = new TokenRequest(uri, clientID, grant);

		assertEquals(uri, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(clientID, request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
		assertNull(request.getResources());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertNull(httpRequest.getAuthorization());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList("abc"), params.get("code"));
		assertEquals(Collections.singletonList("123"), params.get("client_id"));
		assertEquals(Collections.singletonList("http://example.com/in"), params.get("redirect_uri"));
		assertEquals(4, params.size());
	}


	public void testConstructorMissingClientID()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientID clientID = null;
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), new URI("http://example.com/in"));

		try {
			new TokenRequest(uri, clientID, grant, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The \"authorization_code\" grant type requires a \"client_id\" parameter", e.getMessage());
		}
	}


	public void testMinimalConstructor()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		AuthorizationGrant grant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"));
		Scope scope = Scope.parse("openid email");

		TokenRequest tokenRequest = new TokenRequest(uri, grant, scope);

		assertEquals(uri, tokenRequest.getEndpointURI());
		assertNull(tokenRequest.getClientAuthentication());
		assertNull(tokenRequest.getClientID());
		assertEquals(grant, tokenRequest.getAuthorizationGrant());
		assertEquals(scope, tokenRequest.getScope());
		assertNull(tokenRequest.getAuthorizationDetails());
		assertNull(tokenRequest.getResources());

		HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertNull(httpRequest.getAuthorization());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.PASSWORD.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList("alice"), params.get("username"));
		assertEquals(Collections.singletonList("secret"), params.get("password"));
		assertEquals(Scope.parse("openid email"), Scope.parse(MultivaluedMapUtils.getFirstValue(params, "scope")));
		assertEquals(4, params.size());
	}


	public void testMinimalConstructorWithNoScope()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		AuthorizationGrant grant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"));

		TokenRequest tokenRequest = new TokenRequest(uri, grant);

		assertEquals(uri, tokenRequest.getEndpointURI());
		assertNull(tokenRequest.getClientAuthentication());
		assertNull(tokenRequest.getClientID());
		assertEquals(grant, tokenRequest.getAuthorizationGrant());
		assertNull(tokenRequest.getScope());
		assertNull(tokenRequest.getResources());

		HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertNull(httpRequest.getAuthorization());
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.PASSWORD.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList("alice"), params.get("username"));
		assertEquals(Collections.singletonList("secret"), params.get("password"));
		assertEquals(3, params.size());
	}


	public void testMissingClientCredentialsAuthentication()
		throws Exception {

		try {
			new TokenRequest(new URI("https://c2id.com/token"), new ClientCredentialsGrant(), null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The \"client_credentials\" grant type requires client authentication", e.getMessage());
		}
	}


	public void testConstructorIllegalResourceURI()
		throws Exception {

		try {
			new TokenRequest(
				new URI("https://c2id.com/token"),
				new ClientSecretBasic(new ClientID("123"), new Secret("ni8ohr2ideng4euD")),
				new ClientCredentialsGrant(),
				new Scope("read", "write"),
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
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		
		String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);
		
		String postBody = 
			"grant_type=authorization_code" +
			"&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb";
		
		httpRequest.setBody(postBody);
		
		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertEquals(new URI("https://connect2id.com/token/"), tr.getEndpointURI());

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
		
		assertEquals(new URL("https://connect2id.com/token/"), httpRequest.getURL());
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
		
		TokenRequest tokenRequest = new TokenRequest(
			URI.create("https://c2id.com/token"),
			new ClientID("123"),
			new AuthorizationCodeGrant(code, redirectURI, pkceVerifier));
		
		HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
		
		assertNull(httpRequest.getAuthorization()); // no client auth here
		
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList(code.getValue()), params.get("code"));
		assertEquals(Collections.singletonList(redirectURI.toString()), params.get("redirect_uri"));
		assertEquals(Collections.singletonList("123"), params.get("client_id"));
		assertEquals(Collections.singletonList(pkceVerifier.getValue()), params.get("code_verifier"));
		assertNull(params.get("scope"));
		assertEquals(5, params.size());
	}


	public void testParseCodeGrantWithPKCE()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		String postBody =
			"grant_type=authorization_code" +
			"&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb" +
			"&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" +
			"&client_id=123";

		httpRequest.setBody(postBody);

		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertEquals(new URI("https://connect2id.com/token/"), tr.getEndpointURI());

		assertNull(tr.getClientAuthentication());
		assertEquals(new ClientID("123"), tr.getClientID());

		AuthorizationCodeGrant codeGrant = (AuthorizationCodeGrant)tr.getAuthorizationGrant();
		assertEquals(GrantType.AUTHORIZATION_CODE, codeGrant.getType());
		assertEquals("SplxlOBeZQQYbYS6WxSbIA", codeGrant.getAuthorizationCode().getValue());
		assertEquals("https://client.example.com/cb", codeGrant.getRedirectionURI().toString());
		assertEquals("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", codeGrant.getCodeVerifier().getValue());

		httpRequest = tr.toHTTPRequest();
		
		assertEquals(new URL("https://connect2id.com/token/"), httpRequest.getURL());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		assertNull(httpRequest.getAuthorization());
		assertEquals(Collections.singletonList("authorization_code"), httpRequest.getBodyAsFormParameters().get("grant_type"));
		assertEquals(Collections.singletonList("SplxlOBeZQQYbYS6WxSbIA"), httpRequest.getBodyAsFormParameters().get("code"));
		assertEquals(Collections.singletonList("https://client.example.com/cb"), httpRequest.getBodyAsFormParameters().get("redirect_uri"));
		assertEquals(Collections.singletonList("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), httpRequest.getBodyAsFormParameters().get("code_verifier"));
		assertEquals(Collections.singletonList("123"), httpRequest.getBodyAsFormParameters().get("client_id"));
		assertEquals(5, httpRequest.getBodyAsFormParameters().size());
	}

	public void testParseCodeGrantWithPKCE_illegalCodeVerifier()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
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
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		
		final String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);
		
		final String postBody = 
			"grant_type=refresh_token" +
			"&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA";
		
		httpRequest.setBody(postBody);
		
		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertEquals(new URI("https://connect2id.com/token/"), tr.getEndpointURI());

		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, authBasic.getMethod());
		assertEquals("Basic " + authBasicString, authBasic.toHTTPAuthorizationHeader());
		assertEquals("s6BhdRkqt3", authBasic.getClientID().getValue());

		RefreshTokenGrant rtGrant = (RefreshTokenGrant)tr.getAuthorizationGrant();
		assertEquals(GrantType.REFRESH_TOKEN, rtGrant.getType());
		assertEquals("tGzv3JOkF0XG5Qx2TlKWIA", rtGrant.getRefreshToken().getValue());
		
		httpRequest = tr.toHTTPRequest();
		
		assertEquals(new URL("https://connect2id.com/token/"), httpRequest.getURL());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(postBody, httpRequest.getBody());
	}


	public void testParsePasswordCredentialsGrant()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		final String postBody = "grant_type=password&username=johndoe&password=A3ddj3w";

		httpRequest.setBody(postBody);

		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertEquals(new URI("https://connect2id.com/token/"), tr.getEndpointURI());

		assertNull(tr.getClientAuthentication());
		assertNull(tr.getClientID());

		ResourceOwnerPasswordCredentialsGrant pwdGrant = (ResourceOwnerPasswordCredentialsGrant)tr.getAuthorizationGrant();
		assertEquals(GrantType.PASSWORD, pwdGrant.getType());
		assertEquals("johndoe", pwdGrant.getUsername());
		assertEquals("A3ddj3w", pwdGrant.getPassword().getValue());

		assertNull(tr.getScope());

		httpRequest = tr.toHTTPRequest();
		
		assertEquals(new URL("https://connect2id.com/token/"), httpRequest.getURL());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		assertNull(httpRequest.getAuthorization());
		assertEquals(Collections.singletonList("password"), httpRequest.getBodyAsFormParameters().get("grant_type"));
		assertEquals(Collections.singletonList("johndoe"), httpRequest.getBodyAsFormParameters().get("username"));
		assertEquals(Collections.singletonList("A3ddj3w"), httpRequest.getBodyAsFormParameters().get("password"));
		assertEquals(3, httpRequest.getBodyAsFormParameters().size());
	}


	public void testParsePasswordCredentialsGrantWithClientAuthentication()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		final String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);

		final String postBody = "grant_type=password&username=johndoe&password=A3ddj3w";

		httpRequest.setBody(postBody);

		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertEquals(new URI("https://connect2id.com/token/"), tr.getEndpointURI());

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
		
		assertEquals(new URL("https://connect2id.com/token/"), httpRequest.getURL());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(Collections.singletonList("password"), httpRequest.getBodyAsFormParameters().get("grant_type"));
		assertEquals(Collections.singletonList("johndoe"), httpRequest.getBodyAsFormParameters().get("username"));
		assertEquals(Collections.singletonList("A3ddj3w"), httpRequest.getBodyAsFormParameters().get("password"));
		assertEquals(3, httpRequest.getBodyAsFormParameters().size());
	}


	public void testParseClientCredentialsGrant()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		final String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);

		final String postBody = "grant_type=client_credentials";

		httpRequest.setBody(postBody);

		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertEquals(new URI("https://connect2id.com/token/"), tr.getEndpointURI());

		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, authBasic.getMethod());
		assertEquals("Basic " + authBasicString, authBasic.toHTTPAuthorizationHeader());
		assertEquals("s6BhdRkqt3", authBasic.getClientID().getValue());

		ClientCredentialsGrant clientCredentialsGrant = (ClientCredentialsGrant)tr.getAuthorizationGrant();
		assertEquals(GrantType.CLIENT_CREDENTIALS, clientCredentialsGrant.getType());

		assertNull(tr.getScope());

		httpRequest = tr.toHTTPRequest();
		
		assertEquals(new URL("https://connect2id.com/token/"), httpRequest.getURL());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(postBody, httpRequest.getBody());
	}


	public void testParseClientCredentialsGrantMissingAuthentication()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
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
		URI endpointUri = new URI("https://token.endpoint.uri/token");
		URI redirectUri = new URI("https://arbitrary.redirect.uri/");
		ClientID clientId = new ClientID("client");
		Secret secret = new Secret("secret");
		ClientSecretPost clientAuthentication = new ClientSecretPost(clientId,secret);
		AuthorizationGrant grant = new AuthorizationCodeGrant(code,redirectUri);
		TokenRequest request = new TokenRequest(endpointUri,clientAuthentication,grant);

		HTTPRequest httpRequest = request.toHTTPRequest();
		TokenRequest reconstructedRequest = TokenRequest.parse(httpRequest);
		
		assertEquals("client", reconstructedRequest.getClientAuthentication().getClientID().getValue());
		assertEquals("secret", ((ClientSecretPost) reconstructedRequest.getClientAuthentication()).getClientSecret().getValue());
		assertEquals(code, ((AuthorizationCodeGrant) reconstructedRequest.getAuthorizationGrant()).getAuthorizationCode());
	}


	// See issue 141
	public void testEmptyClientSecret()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://googleapis.com/oauth2/v3/token"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("code=0a2b49a9-985d-47cb-b36f-be9ed4927b4c&redirect_uri=https%3A%2F%2Fdevelopers.google.com%2Foauthplayground&client_id=google&client_secret=&scope=&grant_type=authorization_code");

		TokenRequest tokenRequest = TokenRequest.parse(httpRequest);

		assertEquals("https://googleapis.com/oauth2/v3/token", tokenRequest.getEndpointURI().toString());
		assertNull(tokenRequest.getClientAuthentication());
		AuthorizationGrant grant = tokenRequest.getAuthorizationGrant();
		assertTrue(grant instanceof AuthorizationCodeGrant);

		AuthorizationCodeGrant codeGrant = (AuthorizationCodeGrant)grant;
		assertEquals("0a2b49a9-985d-47cb-b36f-be9ed4927b4c", codeGrant.getAuthorizationCode().getValue());
		assertEquals("https://developers.google.com/oauthplayground", codeGrant.getRedirectionURI().toString());

		assertEquals("google", tokenRequest.getClientID().getValue());

		assertTrue(tokenRequest.getScope().isEmpty());
	}


	public void testCodeGrant_confidentialClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		Secret clientSecret = new Secret("secret");
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
		AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant(new AuthorizationCode("xyz"), new URI("https://example.com/cb"));

		TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, codeGrant);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertEquals(codeGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientID, request.getClientAuthentication().getClientID());
		assertEquals(clientSecret, ((ClientSecretBasic)request.getClientAuthentication()).getClientSecret());
		assertEquals(codeGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testCodeGrant_publicClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant(new AuthorizationCode("xyz"), new URI("https://example.com/cb"));

		TokenRequest request = new TokenRequest(tokenEndpoint, clientID, codeGrant);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertEquals(clientID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(codeGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertEquals(clientID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(codeGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testCodeGrant_publicClient_pkce()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant(new AuthorizationCode("xyz"), new URI("https://example.com/cb"), new CodeVerifier());

		TokenRequest request = new TokenRequest(tokenEndpoint, clientID, codeGrant);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertEquals(clientID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(codeGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertEquals(clientID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(codeGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testCodeGrant_rejectUnregisteredClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant(new AuthorizationCode("xyz"), new URI("https://example.com/cb"));

		try {
			new TokenRequest(tokenEndpoint, codeGrant);
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
		formParams.put("client_id", Collections.singletonList(new ClientID().getValue()));
		formParams.put("grant_type", Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
		formParams.put("code", Collections.singletonList(new AuthorizationCode().getValue()));
		formParams.put("redirect_uri", Collections.singletonList(URI.create("https://example.com/cb").toString()));
		formParams.put("scope", Collections.singletonList(new Scope("read", "write").toString()));
		httpRequest.setBody(URLUtils.serializeParameters(formParams));

		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("The scope parameter is not allowed", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: The scope parameter is not allowed", e.getErrorObject().getDescription());
		}
	}


	public void testPasswordGrant_confidentialClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		Secret clientSecret = new Secret("secret");
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
		ResourceOwnerPasswordCredentialsGrant passwordGrant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"));

		TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, passwordGrant);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertEquals(passwordGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth.getClientID(), request.getClientAuthentication().getClientID());
		assertEquals(passwordGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testPasswordGrant_publicClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		ResourceOwnerPasswordCredentialsGrant passwordGrant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"));

		TokenRequest request = new TokenRequest(tokenEndpoint, clientID, passwordGrant);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertEquals(clientID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(passwordGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertEquals(clientID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(passwordGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testPasswordGrant_unspecifiedClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ResourceOwnerPasswordCredentialsGrant passwordGrant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"));

		TokenRequest request = new TokenRequest(tokenEndpoint, passwordGrant);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(passwordGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(passwordGrant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testRefreshTokenGrant_confidentialClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		Secret clientSecret = new Secret("secret");
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
		RefreshTokenGrant grant = new RefreshTokenGrant(new RefreshToken("xyz"));

		TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, grant);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth.getClientID(), request.getClientAuthentication().getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testRefreshTokenGrant_publicClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		RefreshTokenGrant grant = new RefreshTokenGrant(new RefreshToken("xyz"));

		TokenRequest request = new TokenRequest(tokenEndpoint, clientID, grant);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertEquals(clientID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertEquals(clientID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testRefreshTokenGrant_unspecifiedClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		RefreshTokenGrant grant = new RefreshTokenGrant(new RefreshToken("xyz"));

		TokenRequest request = new TokenRequest(tokenEndpoint, grant);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testClientCredentialsGrant_confidentialClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		Secret clientSecret = new Secret("secret");
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
		ClientCredentialsGrant grant = new ClientCredentialsGrant();

		TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, grant);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertEquals(GrantType.CLIENT_CREDENTIALS, request.getAuthorizationGrant().getType());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth.getClientID(), request.getClientAuthentication().getClientID());
		assertEquals(GrantType.CLIENT_CREDENTIALS, request.getAuthorizationGrant().getType());
		assertNull(request.getScope());
	}


	public void testClientCredentialsGrant_rejectPublicClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		ClientCredentialsGrant grant = new ClientCredentialsGrant();

		try {
			new TokenRequest(tokenEndpoint, clientID, grant);
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

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientCredentialsGrant grant = new ClientCredentialsGrant();

		try {
			new TokenRequest(tokenEndpoint, grant);
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

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		Secret clientSecret = new Secret("secret");
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

		SignedJWT jwt = JWTAssertionFactory.create(new JWTAssertionDetails(
			new Issuer("123"),
			new Subject("123"),
			new Audience(tokenEndpoint)),
			JWSAlgorithm.HS256,
			new Secret());
		JWTBearerGrant grant = new JWTBearerGrant(jwt);

		TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, grant);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertEquals(GrantType.JWT_BEARER, request.getAuthorizationGrant().getType());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth.getClientID(), request.getClientAuthentication().getClientID());
		assertEquals(GrantType.JWT_BEARER, request.getAuthorizationGrant().getType());
		assertNull(request.getScope());
	}


	public void testJWTBearerGrant_publicClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");

		SignedJWT jwt = JWTAssertionFactory.create(new JWTAssertionDetails(
				new Issuer("123"),
				new Subject("123"),
				new Audience(tokenEndpoint)),
			JWSAlgorithm.HS256,
			new Secret());
		JWTBearerGrant grant = new JWTBearerGrant(jwt);

		TokenRequest request = new TokenRequest(tokenEndpoint, clientID, grant);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertEquals(clientID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(GrantType.JWT_BEARER, request.getAuthorizationGrant().getType());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertEquals(clientID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(GrantType.JWT_BEARER, request.getAuthorizationGrant().getType());
		assertNull(request.getScope());
	}


	public void testJWTBearerGrant_unregisteredClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		SignedJWT jwt = JWTAssertionFactory.create(new JWTAssertionDetails(
				new Issuer("123"),
				new Subject("123"),
				new Audience(tokenEndpoint)),
			JWSAlgorithm.HS256,
			new Secret());
		JWTBearerGrant grant = new JWTBearerGrant(jwt);

		TokenRequest request = new TokenRequest(tokenEndpoint, grant);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(GrantType.JWT_BEARER, request.getAuthorizationGrant().getType());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(GrantType.JWT_BEARER, request.getAuthorizationGrant().getType());
		assertNull(request.getScope());
	}


	public void testSAML2BearerGrant_confidentialClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		Secret clientSecret = new Secret("secret");
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

		BasicCredential credential = new BasicCredential(new SecretKeySpec(new Secret().getValueBytes(), "HmacSha256"));
		String samlAssertion = SAML2AssertionFactory.createAsString(new SAML2AssertionDetails(
			new Issuer("123"),
			new Subject("123"),
			new Audience(tokenEndpoint)),
			SignatureConstants.ALGO_ID_MAC_HMAC_SHA256,
			credential);
		SAML2BearerGrant grant = new SAML2BearerGrant(Base64URL.encode(samlAssertion));

		TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, grant);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertEquals(clientAuth.getClientID(), request.getClientAuthentication().getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testSAML2BearerGrant_publicClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");

		BasicCredential credential = new BasicCredential(new SecretKeySpec(new Secret().getValueBytes(), "HmacSha256"));
		String samlAssertion = SAML2AssertionFactory.createAsString(new SAML2AssertionDetails(
				new Issuer("123"),
				new Subject("123"),
				new Audience(tokenEndpoint)),
			SignatureConstants.ALGO_ID_MAC_HMAC_SHA256,
			credential);
		SAML2BearerGrant grant = new SAML2BearerGrant(Base64URL.encode(samlAssertion));

		TokenRequest request = new TokenRequest(tokenEndpoint, clientID, grant);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertEquals(clientID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertEquals(clientID, request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	public void testSAML2BearerGrant_unregisteredClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		BasicCredential credential = new BasicCredential(new SecretKeySpec(new Secret().getValueBytes(), "HmacSha256"));
		String samlAssertion = SAML2AssertionFactory.createAsString(new SAML2AssertionDetails(
				new Issuer("123"),
				new Subject("123"),
				new Audience(tokenEndpoint)),
			SignatureConstants.ALGO_ID_MAC_HMAC_SHA256,
			credential);
		SAML2BearerGrant grant = new SAML2BearerGrant(Base64URL.encode(samlAssertion));

		TokenRequest request = new TokenRequest(tokenEndpoint, grant);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertEquals(tokenEndpoint, request.getEndpointURI());
		assertNull(request.getClientID());
		assertNull(request.getClientAuthentication());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());
	}


	// https://bitbucket.org/connect2id/openid-connect-dev-client/issues/5/stripping-equal-sign-from-access_code-in
	public void testCodeGrantEqualsCharEncoding() {

		AuthorizationCode code = new AuthorizationCode("abc=");
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(code, URI.create("https://example.com/cb"));

		TokenRequest request = new TokenRequest(URI.create("https://openid.c2id.com/token"), new ClientID("123"), grant);

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
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
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
		
		ClientID clientID = new ClientID("123");
		Secret clientSecret = new Secret();
		
		URL tokenEndpoint = new URL("https://c2id.com/token");
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, tokenEndpoint);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setAuthorization(new ClientSecretBasic(clientID, clientSecret).toHTTPAuthorizationHeader());
		
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode(), URI.create("https://example.com/cb"));
		
		ClientSecretJWT clientSecretJWT = new ClientSecretJWT(clientID, tokenEndpoint.toURI(), JWSAlgorithm.HS256, clientSecret);
		
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
		
		TokenRequest tokenRequest = TokenRequest.parse(httpRequest);
		
		assertEquals(httpRequest.getURL().toURI(), tokenRequest.getEndpointURI());
		assertTrue(tokenRequest.getClientAuthentication() instanceof ClientSecretBasic);
		ClientSecretBasic clientSecretBasic = (ClientSecretBasic) tokenRequest.getClientAuthentication();
		assertEquals("s6BhdRkqt3", clientSecretBasic.getClientID().getValue());
		assertEquals("hsqEzQlUoHAE9px4FSr4yI", clientSecretBasic.getClientSecret().getValue());
		
		assertEquals(new RefreshToken("4LTC8lb0acc6Oy4esc1Nk9BWC0imAwH"), ((RefreshTokenGrant) tokenRequest.getAuthorizationGrant()).getRefreshToken());
		assertEquals(Collections.singletonList(URI.create("https://rs.example.com/")), tokenRequest.getResources());
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
		
		TokenRequest tokenRequest = TokenRequest.parse(httpRequest);
		
		PrivateKeyJWT privateKeyJWT = (PrivateKeyJWT) tokenRequest.getClientAuthentication();
		assertEquals(new ClientID("s6BhdRkqt3"), privateKeyJWT.getClientID());
		assertEquals(new ClientID("s6BhdRkqt3"), privateKeyJWT.getJWTAuthenticationClaimsSet().getClientID());
		assertEquals(new Issuer("s6BhdRkqt3"), privateKeyJWT.getJWTAuthenticationClaimsSet().getIssuer());
		assertEquals(Collections.singletonList(new Audience("https://server.example.com/token")), privateKeyJWT.getJWTAuthenticationClaimsSet().getAudience());
		assertEquals(new JWTID("-_p16j6HciXo317hvZ312c"), privateKeyJWT.getJWTAuthenticationClaimsSet().getJWTID());
		assertEquals(DateUtils.fromSecondsSinceEpoch(1537819491L), privateKeyJWT.getJWTAuthenticationClaimsSet().getIssueTime());
		assertEquals(DateUtils.fromSecondsSinceEpoch(1537819782L), privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime());
		assertEquals(GrantType.CIBA, tokenRequest.getAuthorizationGrant().getType());
		CIBAGrant cibaGrant = (CIBAGrant) tokenRequest.getAuthorizationGrant();
		assertEquals(new AuthRequestID("1c266114-a1be-4252-8ad1-04986c5b9ac1"), cibaGrant.getAuthRequestID());
	}
	
	
	// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/345/token-and-authz-request-must-fail-with-400
	public void testParse_repeatedParameter()
		throws Exception {
		
		URI uri = new URI("https://c2id.com/token");
		ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID("123"), new Secret("secret"));
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), null);
		Scope scope = new Scope("openid", "email");

		TokenRequest request = new TokenRequest(uri, clientAuth, grant, scope);
		
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
		
		ClientID clientID = new ClientID("123");
		Secret clientSecret = new Secret("eef7cheemooPhohp2aihaesah7ohzais");
		ClientSecretBasic basicAuth = new ClientSecretBasic(clientID, clientSecret);
		
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
		
		TokenRequest tokenRequest = new TokenRequest(endpoint, basicAuth, grant, scope);
		
		assertEquals(endpoint, tokenRequest.getEndpointURI());
		assertEquals(basicAuth, tokenRequest.getClientAuthentication());
		assertEquals(grant, tokenRequest.getAuthorizationGrant());
		assertEquals(scope, tokenRequest.getScope());
		
		HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
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
		
		tokenRequest = TokenRequest.parse(httpRequest);
		
		assertEquals(endpoint, tokenRequest.getEndpointURI());
		assertEquals(basicAuth.getClientID(), tokenRequest.getClientAuthentication().getClientID());
		assertEquals(basicAuth.getClientSecret(), ((ClientSecretBasic)tokenRequest.getClientAuthentication()).getClientSecret());
		assertTrue(tokenRequest.getAuthorizationGrant() instanceof TokenExchangeGrant);
		TokenExchangeGrant parsedGrant = (TokenExchangeGrant)tokenRequest.getAuthorizationGrant();
		assertEquals(subjectToken, parsedGrant.getSubjectToken());
		assertEquals(subjectTokenType, parsedGrant.getSubjectTokenType());
		assertEquals(grant.toParameters(), parsedGrant.toParameters());
		assertEquals(scope, tokenRequest.getScope());
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

		TokenRequest tokenRequest = TokenRequest.parse(httpRequest);

		ClientAuthentication clientAuthentication = tokenRequest.getClientAuthentication();
		assertNull(clientAuthentication);
		assertEquals(GrantType.TOKEN_EXCHANGE, tokenRequest.getAuthorizationGrant().getType());
		assertNull(tokenRequest.getResources());
		TokenExchangeGrant tokenExchangeGrant = (TokenExchangeGrant) tokenRequest.getAuthorizationGrant();
		assertEquals(new Audience("urn:example:cooperation-context").toSingleAudienceList(), tokenExchangeGrant.getAudience());
		assertNull(tokenRequest.getScope());
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

		TokenRequest tokenRequest = TokenRequest.parse(httpRequest);

		ClientAuthentication clientAuthentication = tokenRequest.getClientAuthentication();
		assertNull(clientAuthentication);
		assertEquals(GrantType.TOKEN_EXCHANGE, tokenRequest.getAuthorizationGrant().getType());
		assertEquals(Collections.singletonList(new URI("https://backend.example.com/api")), tokenRequest.getResources());
		TokenExchangeGrant tokenExchangeGrant = (TokenExchangeGrant) tokenRequest.getAuthorizationGrant();
		assertEquals(Audience.create("urn:example:cooperation-context1", "urn:example:cooperation-context2"), tokenExchangeGrant.getAudience());
		assertNull(tokenRequest.getScope());
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
	

	public void testParseTokenExchange_missingSubjectToken()
			throws MalformedURLException {

		URL endpoint = new URL("https://server.example.com/token");
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpoint);
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


	public void testAuthorizationCodeGrantScopeRequirementInTokenRequest()
		throws Exception {
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), null);
		testScopeRequirementInTokenRequest(grant);
	}


	public void testClientCredentialsGrantScopeRequirementInTokenRequest()
		throws Exception {
		testScopeRequirementInTokenRequest(new ClientCredentialsGrant());
	}


	public void testPasswordGrantScopeRequirementInTokenRequest()
		throws Exception {
		testScopeRequirementInTokenRequest(new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("s3cr3t")));
	}


	public void testRefreshTokenGrantScopeRequirementInTokenRequest()
		throws Exception {
		testScopeRequirementInTokenRequest(new RefreshTokenGrant(new RefreshToken()));
	}


	public void testDeviceGrantScopeRequirementInTokenRequest()
		throws Exception {
		testScopeRequirementInTokenRequest(new DeviceCodeGrant(new DeviceCode()));
	}


	public void testCIBAGrantScopeRequirementInTokenRequest()
		throws Exception {
		testScopeRequirementInTokenRequest(new CIBAGrant(new AuthRequestID()));
	}


	private void testScopeRequirementInTokenRequest(AuthorizationGrant grant)
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID("123"), new Secret("secret"));
		Scope scope = new Scope("read", "write");
		TokenRequest request = new TokenRequest(uri, clientAuth, grant, scope);

		assertEquals(scope, request.getScope());
		HTTPRequest httpRequest = request.toHTTPRequest();
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		if (grant.getType().getScopeRequirementInTokenRequest() != ParameterRequirement.NOT_ALLOWED) {
			assertEquals(Collections.singletonList(scope.toString()), params.get("scope"));
		} else {
			assertNull(params.get("scope"));
		}
	}
}
