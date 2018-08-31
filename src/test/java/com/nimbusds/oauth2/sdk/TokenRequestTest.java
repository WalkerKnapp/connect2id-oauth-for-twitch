/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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


import java.net.URI;
import java.net.URL;
import java.util.*;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSocketFactory;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionDetails;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionFactory;
import com.nimbusds.oauth2.sdk.assertions.saml2.SAML2AssertionDetails;
import com.nimbusds.oauth2.sdk.assertions.saml2.SAML2AssertionFactory;
import com.nimbusds.oauth2.sdk.auth.*;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import junit.framework.TestCase;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.signature.SignatureConstants;


/**
 * Tests token request serialisation and parsing.
 */
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

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		ClientSecretBasic basic = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertEquals("123", basic.getClientID().getValue());
		assertEquals("secret", basic.getClientSecret().getValue());
		Map<String,List<String>> params = httpRequest.getQueryParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList("abc"), params.get("code"));
		assertTrue(Scope.parse("openid email").containsAll(Scope.parse(URLUtils.getFirstValue(params, "scope"))));
		assertEquals(3, params.size());
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

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		ClientSecretBasic basic = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertEquals("123", basic.getClientID().getValue());
		assertEquals("secret", basic.getClientSecret().getValue());
		Map<String,List<String>> params = httpRequest.getQueryParameters();
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

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		Map<String,List<String>> params = httpRequest.getQueryParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList("abc"), params.get("code"));
		assertEquals(Collections.singletonList("123"), params.get("client_id"));
		assertEquals(3, params.size());
	}


	public void testConstructorWithTLSClientAuth()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientAuthentication clientAuth = new TLSClientAuthentication(new ClientID("123"), (SSLSocketFactory) null);
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), null);

		TokenRequest request = new TokenRequest(uri, clientAuth, grant);

		assertEquals(uri, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		Map<String,List<String>> params = httpRequest.getQueryParameters();
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


	public void testConstructorWithClientID()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), new URI("http://example.com/in"));

		TokenRequest request = new TokenRequest(uri, clientID, grant, null);

		assertEquals(uri, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(clientID, request.getClientID());
		assertEquals(grant, request.getAuthorizationGrant());
		assertNull(request.getScope());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertNull(httpRequest.getAuthorization());
		Map<String,List<String>> params = httpRequest.getQueryParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList("abc"), params.get("code"));
		assertEquals(Collections.singletonList("123"), params.get("client_id"));
		assertEquals(Collections.singletonList("http://example.com/in"), params.get("redirect_uri"));
		assertEquals(4, params.size());
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

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertNull(httpRequest.getAuthorization());
		Map<String,List<String>> params = httpRequest.getQueryParameters();
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

		HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertNull(httpRequest.getAuthorization());
		Map<String,List<String>> params = httpRequest.getQueryParameters();
		assertEquals(Collections.singletonList(GrantType.PASSWORD.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList("alice"), params.get("username"));
		assertEquals(Collections.singletonList("secret"), params.get("password"));
		assertEquals(Scope.parse("openid email"), Scope.parse(URLUtils.getFirstValue(params, "scope")));
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

		HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
		assertEquals(uri.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertNull(httpRequest.getAuthorization());
		Map<String,List<String>> params = httpRequest.getQueryParameters();
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
	
	
	public void testCodeGrantWithBasicSecret()
		throws Exception {
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);
		
		String postBody = 
			"grant_type=authorization_code" +
			"&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb";
		
		httpRequest.setQuery(postBody);
		
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
		
		httpRequest = tr.toHTTPRequest();
		
		assertEquals(new URL("https://connect2id.com/token/"), httpRequest.getURL());
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(Collections.singletonList("authorization_code"), httpRequest.getQueryParameters().get("grant_type"));
		assertEquals(Collections.singletonList("SplxlOBeZQQYbYS6WxSbIA"), httpRequest.getQueryParameters().get("code"));
		assertEquals(Collections.singletonList("https://client.example.com/cb"), httpRequest.getQueryParameters().get("redirect_uri"));
		assertEquals(3, httpRequest.getQueryParameters().size());
	}
	
	
	public void testCodeGrantWithPKCE()
		throws Exception {
		
		AuthorizationCode code = new AuthorizationCode();
		URI redirectURI = URI.create("app://oauth-callback");
		CodeVerifier pkceVerifier = new CodeVerifier();
		
		TokenRequest tokenRequest = new TokenRequest(
			URI.create("https://c2id.com/token"),
			new ClientID("123"),
			new AuthorizationCodeGrant(code, redirectURI, pkceVerifier));
		
		HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
		
		assertNull(httpRequest.getAuthorization()); // no client auth here
		
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		
		Map<String,List<String>> params = httpRequest.getQueryParameters();
		assertEquals(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()), params.get("grant_type"));
		assertEquals(Collections.singletonList(code.getValue()), params.get("code"));
		assertEquals(Collections.singletonList(redirectURI.toString()), params.get("redirect_uri"));
		assertEquals(Collections.singletonList("123"), params.get("client_id"));
		assertEquals(Collections.singletonList(pkceVerifier.getValue()), params.get("code_verifier"));
		assertEquals(5, params.size());
	}


	public void testParseCodeGrantWithPKCE()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		String postBody =
			"grant_type=authorization_code" +
			"&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb" +
			"&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" +
			"&client_id=123";

		httpRequest.setQuery(postBody);

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
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertNull(httpRequest.getAuthorization());
		assertEquals(Collections.singletonList("authorization_code"), httpRequest.getQueryParameters().get("grant_type"));
		assertEquals(Collections.singletonList("SplxlOBeZQQYbYS6WxSbIA"), httpRequest.getQueryParameters().get("code"));
		assertEquals(Collections.singletonList("https://client.example.com/cb"), httpRequest.getQueryParameters().get("redirect_uri"));
		assertEquals(Collections.singletonList("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), httpRequest.getQueryParameters().get("code_verifier"));
		assertEquals(Collections.singletonList("123"), httpRequest.getQueryParameters().get("client_id"));
		assertEquals(5, httpRequest.getQueryParameters().size());
	}


	public void testParseRefreshTokenGrantWithBasicSecret()
		throws Exception {
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		final String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);
		
		final String postBody = 
			"grant_type=refresh_token" +
			"&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA";
		
		httpRequest.setQuery(postBody);
		
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
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(postBody, httpRequest.getQuery());
	}


	public void testParsePasswordCredentialsGrant()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		final String postBody = "grant_type=password&username=johndoe&password=A3ddj3w";

		httpRequest.setQuery(postBody);

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
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertNull(httpRequest.getAuthorization());
		assertEquals(Collections.singletonList("password"), httpRequest.getQueryParameters().get("grant_type"));
		assertEquals(Collections.singletonList("johndoe"), httpRequest.getQueryParameters().get("username"));
		assertEquals(Collections.singletonList("A3ddj3w"), httpRequest.getQueryParameters().get("password"));
		assertEquals(3, httpRequest.getQueryParameters().size());
	}


	public void testParsePasswordCredentialsGrantWithClientAuthentication()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		final String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);

		final String postBody = "grant_type=password&username=johndoe&password=A3ddj3w";

		httpRequest.setQuery(postBody);

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
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(Collections.singletonList("password"), httpRequest.getQueryParameters().get("grant_type"));
		assertEquals(Collections.singletonList("johndoe"), httpRequest.getQueryParameters().get("username"));
		assertEquals(Collections.singletonList("A3ddj3w"), httpRequest.getQueryParameters().get("password"));
		assertEquals(3, httpRequest.getQueryParameters().size());
	}


	public void testParseClientCredentialsGrant()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		final String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);

		final String postBody = "grant_type=client_credentials";

		httpRequest.setQuery(postBody);

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
		assertEquals(CommonContentTypes.APPLICATION_URLENCODED.toString(), httpRequest.getContentType().toString());
		assertEquals("Basic " + authBasicString, httpRequest.getAuthorization());
		assertEquals(postBody, httpRequest.getQuery());
	}


	public void testParseClientCredentialsGrantMissingAuthentication()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		final String postBody = "grant_type=client_credentials";

		httpRequest.setQuery(postBody);

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
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery("code=0a2b49a9-985d-47cb-b36f-be9ed4927b4c&redirect_uri=https%3A%2F%2Fdevelopers.google.com%2Foauthplayground&client_id=google&client_secret=&scope=&grant_type=authorization_code");

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
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery(URLUtils.serializeParameters(codeGrant.toParameters()));

		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing required \"client_id\" parameter", e.getMessage());
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


	public void testPasswordGrant_unregisteredClient()
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


	public void testRefreshTokenGrant_unregisteredClient()
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
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery(URLUtils.serializeParameters(grant.toParameters()));

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
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery(URLUtils.serializeParameters(grant.toParameters()));

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

		BasicCredential credential = new BasicCredential();
		credential.setSecretKey(new SecretKeySpec(new Secret().getValueBytes(), "HmacSha256"));
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

		BasicCredential credential = new BasicCredential();
		credential.setSecretKey(new SecretKeySpec(new Secret().getValueBytes(), "HmacSha256"));
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
		BasicCredential credential = new BasicCredential();
		credential.setSecretKey(new SecretKeySpec(new Secret().getValueBytes(), "HmacSha256"));
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
	public void testCodeGrantEqualsCharEncoding()
		throws Exception {

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
		customParams.put("resource", Collections.singletonList("http://xxxxxx/PartyOData"));

		TokenRequest request = new TokenRequest(URI.create("https://c2id.com/token"), new ClientSecretBasic(new ClientID(), new Secret()), grant, Scope.parse("read write"), customParams);

		assertEquals(customParams, request.getCustomParameters());
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("resource"));

		HTTPRequest httpRequest = request.toHTTPRequest();

		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), httpRequest.getQueryParameters().get("resource"));
		assertEquals(5, httpRequest.getQueryParameters().size());

		request = TokenRequest.parse(httpRequest);
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("resource"));
		assertEquals(1, request.getCustomParameters().size());
	}


	public void testCustomParams_codeGrant_postAuth()
		throws Exception {

		AuthorizationGrant grant = new AuthorizationCodeGrant(new AuthorizationCode(), URI.create("https://example.com/cb"));
		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("resource", Collections.singletonList("http://xxxxxx/PartyOData"));

		TokenRequest request = new TokenRequest(URI.create("https://c2id.com/token"), new ClientSecretPost(new ClientID(), new Secret()), grant, Scope.parse("read write"), customParams);

		assertEquals(customParams, request.getCustomParameters());
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("resource"));

		HTTPRequest httpRequest = request.toHTTPRequest();

		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), httpRequest.getQueryParameters().get("resource"));
		assertEquals(7, httpRequest.getQueryParameters().size());

		request = TokenRequest.parse(httpRequest);
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("resource"));
		assertEquals(1, request.getCustomParameters().size());
	}


	public void testCustomParams_passwordGrant_postAuth()
		throws Exception {

		AuthorizationGrant grant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret());
		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("resource", Collections.singletonList("http://xxxxxx/PartyOData"));

		TokenRequest request = new TokenRequest(URI.create("https://c2id.com/token"), new ClientSecretPost(new ClientID(), new Secret()), grant, Scope.parse("read write"), customParams);

		assertEquals(customParams, request.getCustomParameters());
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("resource"));

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), httpRequest.getQueryParameters().get("resource"));
		assertEquals(7, httpRequest.getQueryParameters().size());

		request = TokenRequest.parse(httpRequest);
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("resource"));
		assertEquals(1, request.getCustomParameters().size());
	}


	public void testCustomParams_clientCredentialsGrant_basicAuth()
		throws Exception {

		AuthorizationGrant grant = new ClientCredentialsGrant();
		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("resource", Collections.singletonList("http://xxxxxx/PartyOData"));

		TokenRequest request = new TokenRequest(URI.create("https://c2id.com/token"), new ClientSecretBasic(new ClientID(), new Secret()), grant, Scope.parse("read write"), customParams);

		assertEquals(customParams, request.getCustomParameters());
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("resource"));

		HTTPRequest httpRequest = request.toHTTPRequest();

		System.out.println(httpRequest.getQuery());
		assertEquals(Collections.singletonList("client_credentials"), httpRequest.getQueryParameters().get("grant_type"));
		assertEquals(Collections.singletonList("read write"), httpRequest.getQueryParameters().get("scope"));
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), httpRequest.getQueryParameters().get("resource"));
		assertEquals(3, httpRequest.getQueryParameters().size());

		request = TokenRequest.parse(httpRequest);
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("resource"));
		assertEquals(1, request.getCustomParameters().size());
	}


	public void testCustomParams_clientCredentialsGrant_postAuth()
		throws Exception {

		AuthorizationGrant grant = new ClientCredentialsGrant();
		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("resource", Collections.singletonList("http://xxxxxx/PartyOData"));

		TokenRequest request = new TokenRequest(URI.create("https://c2id.com/token"), new ClientSecretPost(new ClientID(), new Secret()), grant, Scope.parse("read write"), customParams);

		assertEquals(customParams, request.getCustomParameters());
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("resource"));

		HTTPRequest httpRequest = request.toHTTPRequest();

		System.out.println(httpRequest.getQuery());
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), httpRequest.getQueryParameters().get("resource"));

		request = TokenRequest.parse(httpRequest);
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("resource"));
		assertEquals(1, request.getCustomParameters().size());
	}


	public void testCustomParams_clientCredentialsGrant_jwtAuth()
		throws Exception {

		AuthorizationGrant grant = new ClientCredentialsGrant();
		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("resource", Collections.singletonList("http://xxxxxx/PartyOData"));

		TokenRequest request = new TokenRequest(URI.create("https://c2id.com/token"), new ClientSecretJWT(new ClientID(), URI.create("https://c2id.com/token"), JWSAlgorithm.HS256, new Secret()), grant, Scope.parse("read write"), customParams);

		assertEquals(customParams, request.getCustomParameters());
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("resource"));

		HTTPRequest httpRequest = request.toHTTPRequest();

		System.out.println(httpRequest.getQuery());
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), httpRequest.getQueryParameters().get("resource"));

		request = TokenRequest.parse(httpRequest);
		assertEquals(Collections.singletonList("http://xxxxxx/PartyOData"), request.getCustomParameter("resource"));
		System.out.println(request.getCustomParameters());
		assertEquals(1, request.getCustomParameters().size());
	}
	
	
	public void testCodeGrantWithBasicSecret_parseMalformedBasicAuth_missingDelimiter()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		httpRequest.setAuthorization("Basic " + Base64.encode("alice"));
		
		String postBody =
			"grant_type=authorization_code" +
				"&code=SplxlOBeZQQYbYS6WxSbIA" +
				"&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb";
		
		httpRequest.setQuery(postBody);
		
		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Malformed client secret basic authentication (see RFC 6749, section 2.3.1): Missing credentials delimiter \":\"", e.getMessage());
			
			assertEquals(OAuth2Error.INVALID_REQUEST.toString(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Malformed client secret basic authentication (see RFC 6749, section 2.3.1): Missing credentials delimiter \":\"", e.getErrorObject().getDescription());
		}
	}
	
	
	// Reject basic + client_secret_jwt auth present in the same token request
	public void testRejectMultipleClientAuthMethods()
		throws Exception {
		
		ClientID clientID = new ClientID("123");
		Secret clientSecret = new Secret();
		
		URL tokenEndpoint = new URL("https://c2id.com/token");
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, tokenEndpoint);
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setAuthorization(new ClientSecretBasic(clientID, clientSecret).toHTTPAuthorizationHeader());
		
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode(), URI.create("https://example.com/cb"));
		
		ClientSecretJWT clientSecretJWT = new ClientSecretJWT(clientID, tokenEndpoint.toURI(), JWSAlgorithm.HS256, clientSecret);
		
		Map<String,List<String>> bodyParams = new HashMap<>();
		bodyParams.putAll(grant.toParameters());
		bodyParams.putAll(clientSecretJWT.toParameters());
		
		httpRequest.setQuery(URLUtils.serializeParameters(bodyParams));
		
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
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setHeader("Cache-Control", "no-cache");
		httpRequest.setQuery("grant_type=authorization_code" +
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
}

