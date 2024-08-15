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

package com.nimbusds.openid.connect.sdk;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.jarm.JARMUtils;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import junit.framework.TestCase;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;


public class AuthenticationSuccessResponseTest extends TestCase {
	
	private static final RSAPrivateKey RSA_PRIVATE_KEY;
	
	
	private static final URI REDIRECT_URI = URI.create("https://client.com/cb");

	
	static {
		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(2048);
			KeyPair keyPair = gen.generateKeyPair();
			RSA_PRIVATE_KEY = (RSAPrivateKey) keyPair.getPrivate();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}


	public void testIDTokenResponse()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer("https://c2id.com")
			.audience(Collections.singletonList("https://client.com"))
			.subject("alice")
			.issueTime(new Date(10000L))
			.expirationTime(new Date(20000L))
			.claim("nonce", "123")
			.build();

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

		idToken.sign(new MACSigner("01234567890123456789012345678901"));

		AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
			REDIRECT_URI, null, idToken, null, new State("abc"), null, ResponseMode.FRAGMENT);

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertEquals(idToken, response.getIDToken());
		assertNull(response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertNull(response.getSessionState());
		assertNull(response.getIssuer());
		
		assertEquals(new ResponseType("id_token"), response.impliedResponseType());
		assertEquals(ResponseMode.FRAGMENT, response.impliedResponseMode());

		URI responseURI = response.toURI();

		String[] parts = responseURI.toString().split("#");
		assertEquals(REDIRECT_URI.toString(), parts[0]);

		response = AuthenticationSuccessResponse.parse(responseURI);

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertEquals("https://c2id.com", response.getIDToken().getJWTClaimsSet().getIssuer());
		assertEquals("https://client.com", response.getIDToken().getJWTClaimsSet().getAudience().get(0));
		assertEquals("alice", response.getIDToken().getJWTClaimsSet().getSubject());
		assertEquals(10000L, response.getIDToken().getJWTClaimsSet().getIssueTime().getTime());
		assertEquals(20000L, response.getIDToken().getJWTClaimsSet().getExpirationTime().getTime());
		assertEquals("123", (String)response.getIDToken().getJWTClaimsSet().getClaim("nonce"));
		assertNull(response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertNull(response.getSessionState());
		assertNull(response.getIssuer());
		assertEquals(ResponseMode.FRAGMENT, response.impliedResponseMode());
	}


	public void testCodeIDTokenResponse()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode();

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer("https://c2id.com")
			.audience(Collections.singletonList("https://client.com"))
			.subject("alice")
			.issueTime(new Date(10000L))
			.expirationTime(new Date(20000L))
			.claim("nonce", "123")
			.build();

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

		idToken.sign(new MACSigner("01234567890123456789012345678901"));

		AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
			REDIRECT_URI, code, idToken, null, new State("abc"), null, ResponseMode.FRAGMENT);

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertEquals(idToken, response.getIDToken());
		assertEquals(code, response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertNull(response.getSessionState());
		assertNull(response.getIssuer());
		
		assertEquals(new ResponseType("code", "id_token"), response.impliedResponseType());
		assertEquals(ResponseMode.FRAGMENT, response.impliedResponseMode());

		URI responseURI = response.toURI();

		String[] parts = responseURI.toString().split("#");
		assertEquals(REDIRECT_URI.toString(), parts[0]);

		response = AuthenticationSuccessResponse.parse(responseURI);

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertEquals("https://c2id.com", response.getIDToken().getJWTClaimsSet().getIssuer());
		assertEquals("https://client.com", response.getIDToken().getJWTClaimsSet().getAudience().get(0));
		assertEquals("alice", response.getIDToken().getJWTClaimsSet().getSubject());
		assertEquals(10000L, response.getIDToken().getJWTClaimsSet().getIssueTime().getTime());
		assertEquals(20000L, response.getIDToken().getJWTClaimsSet().getExpirationTime().getTime());
		assertEquals("123", (String)response.getIDToken().getJWTClaimsSet().getClaim("nonce"));
		assertEquals(code, response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertNull(response.getSessionState());
		assertNull(response.getIssuer());
		assertEquals(ResponseMode.FRAGMENT, response.impliedResponseMode());
	}


	public void testCodeIDTokenResponseWithSessionState()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode();

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer("https://c2id.com")
			.audience(Collections.singletonList("https://client.com"))
			.subject("alice")
			.issueTime(new Date(10000L))
			.expirationTime(new Date(20000L))
			.claim("nonce", "123")
			.build();

		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

		idToken.sign(new MACSigner("01234567890123456789012345678901"));

		AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
			REDIRECT_URI, code, idToken, null, new State("abc"), new State("xyz"), ResponseMode.FRAGMENT);

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertEquals(idToken, response.getIDToken());
		assertEquals(code, response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertEquals("xyz", response.getSessionState().getValue());
		assertNull(response.getIssuer());
		
		assertEquals(new ResponseType("code", "id_token"), response.impliedResponseType());
		assertEquals(ResponseMode.FRAGMENT, response.impliedResponseMode());

		URI responseURI = response.toURI();

		String[] parts = responseURI.toString().split("#");
		assertEquals(REDIRECT_URI.toString(), parts[0]);

		response = AuthenticationSuccessResponse.parse(responseURI);

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertEquals("https://c2id.com", response.getIDToken().getJWTClaimsSet().getIssuer());
		assertEquals("https://client.com", response.getIDToken().getJWTClaimsSet().getAudience().get(0));
		assertEquals("alice", response.getIDToken().getJWTClaimsSet().getSubject());
		assertEquals(10000L, response.getIDToken().getJWTClaimsSet().getIssueTime().getTime());
		assertEquals(20000L, response.getIDToken().getJWTClaimsSet().getExpirationTime().getTime());
		assertEquals("123", (String)response.getIDToken().getJWTClaimsSet().getClaim("nonce"));
		assertEquals(code, response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertEquals("xyz", response.getSessionState().getValue());
		assertNull(response.getIssuer());
		assertEquals(ResponseMode.FRAGMENT, response.impliedResponseMode());
	}


	public void testCodeResponse()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode();

		AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
			REDIRECT_URI, code, null, null, new State("abc"), null, ResponseMode.QUERY);

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertNull(response.getIDToken());
		assertEquals(code, response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertNull(response.getSessionState());
		assertNull(response.getIssuer());
		
		assertEquals(new ResponseType("code"), response.impliedResponseType());
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode());

		URI responseURI = response.toURI();

		String[] parts = responseURI.toString().split("\\?");
		assertEquals(REDIRECT_URI.toString(), parts[0]);

		response = AuthenticationSuccessResponse.parse(responseURI);

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertNull(response.getIDToken());
		assertEquals(code, response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertNull(response.getSessionState());
		assertNull(response.getIssuer());
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode());
	}


	public void testCodeResponse_withIssuer()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode();
		
		Issuer issuer = new Issuer("https://login.c2id.com");

		AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
			REDIRECT_URI, code, null, null, new State("abc"), null, issuer, ResponseMode.QUERY);

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertNull(response.getIDToken());
		assertEquals(code, response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertNull(response.getSessionState());
		assertEquals(issuer, response.getIssuer());
		
		assertEquals(new ResponseType("code"), response.impliedResponseType());
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode());

		URI responseURI = response.toURI();

		String[] parts = responseURI.toString().split("\\?");
		assertEquals(REDIRECT_URI.toString(), parts[0]);

		response = AuthenticationSuccessResponse.parse(responseURI);

		assertTrue(response.indicatesSuccess());
		assertEquals(REDIRECT_URI, response.getRedirectionURI());
		assertNull(response.getIDToken());
		assertEquals(code, response.getAuthorizationCode());
		assertNull(response.getAccessToken());
		assertEquals("abc", response.getState().getValue());
		assertNull(response.getSessionState());
		assertEquals(issuer, response.getIssuer());
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode());
	}
	
	
	// See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/140
	public void testRedirectionURIWithQueryString() {
		
		URI redirectURI = URI.create("https://example.com/myservice/?action=oidccallback");
		assertEquals("action=oidccallback", redirectURI.getQuery());

		AuthorizationCode code = new AuthorizationCode();
		State state = new State();

		AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(redirectURI, code, null, null, state, null, ResponseMode.QUERY);

		Map<String,List<String>> params = response.toParameters();
		assertEquals(Collections.singletonList(code.getValue()), params.get("code"));
		assertEquals(Collections.singletonList(state.getValue()), params.get("state"));
		assertEquals(2, params.size());

		URI uri = response.toURI();

		params = URLUtils.parseParameters(uri.getQuery());
		assertEquals(Collections.singletonList("oidccallback"), params.get("action"));
		assertEquals(Collections.singletonList(code.getValue()), params.get("code"));
		assertEquals(Collections.singletonList(state.getValue()), params.get("state"));
		assertEquals(3, params.size());
	}
	
	
	public void testJARM_successLifeCycle_query()
		throws Exception {
		
		AuthenticationSuccessResponse successResponse = new AuthenticationSuccessResponse(
			URI.create("https://example.com/cb"),
			new AuthorizationCode(),
			null,
			null,
			new State(),
			null,
			ResponseMode.QUERY_JWT);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			new Date(),
			successResponse);
		
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
		signedJWT.sign(new RSASSASigner(RSA_PRIVATE_KEY));
		
		AuthenticationSuccessResponse jwtSuccessResponse = new AuthenticationSuccessResponse(
			successResponse.getRedirectionURI(),
			signedJWT,
			successResponse.getResponseMode());
		
		assertEquals(successResponse.getRedirectionURI(), jwtSuccessResponse.getRedirectionURI());
		assertEquals(signedJWT, jwtSuccessResponse.getJWTResponse());
		assertEquals(successResponse.getResponseMode(), jwtSuccessResponse.getResponseMode());
		
		Map<String,List<String>> params = jwtSuccessResponse.toParameters();
		assertEquals(((JWT) signedJWT).serialize(), MultivaluedMapUtils.getFirstValue(params, "response"));
		assertEquals(1, params.size());
		
		URI uri = jwtSuccessResponse.toURI();
		
		assertTrue(uri.toString().startsWith(successResponse.getRedirectionURI().toString()));
		assertEquals("response=" + ((JWT) signedJWT).serialize(), uri.getQuery());
		assertNull(uri.getFragment());
		
		jwtSuccessResponse = AuthenticationResponseParser.parse(uri).toSuccessResponse();
		assertEquals(successResponse.getRedirectionURI(), jwtSuccessResponse.getRedirectionURI());
		assertEquals(((JWT) signedJWT).serialize(), jwtSuccessResponse.getJWTResponse().serialize());
		assertEquals(ResponseMode.JWT, jwtSuccessResponse.getResponseMode());
	}
	
	
	public void testJARM_successLifeCycle_fragment()
		throws Exception {
		
		AuthenticationSuccessResponse successResponse = new AuthenticationSuccessResponse(
			URI.create("https://example.com/cb"),
			new AuthorizationCode(),
			null,
			null,
			new State(),
			null,
			ResponseMode.FRAGMENT_JWT);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			new Date(),
			successResponse);
		
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
		signedJWT.sign(new RSASSASigner(RSA_PRIVATE_KEY));
		
		AuthenticationSuccessResponse jwtSuccessResponse = new AuthenticationSuccessResponse(
			successResponse.getRedirectionURI(),
			signedJWT,
			successResponse.getResponseMode());
		
		assertEquals(successResponse.getRedirectionURI(), jwtSuccessResponse.getRedirectionURI());
		assertEquals(signedJWT, jwtSuccessResponse.getJWTResponse());
		assertEquals(successResponse.getResponseMode(), jwtSuccessResponse.getResponseMode());
		
		Map<String,List<String>> params = jwtSuccessResponse.toParameters();
		assertEquals(((JWT) signedJWT).serialize(), MultivaluedMapUtils.getFirstValue(params, "response"));
		assertEquals(1, params.size());
		
		URI uri = jwtSuccessResponse.toURI();
		
		assertTrue(uri.toString().startsWith(successResponse.getRedirectionURI().toString()));
		assertNull(uri.getQuery());
		assertEquals("response=" + ((JWT) signedJWT).serialize(), uri.getFragment());
		
		jwtSuccessResponse = AuthenticationResponseParser.parse(uri).toSuccessResponse();
		assertEquals(successResponse.getRedirectionURI(), jwtSuccessResponse.getRedirectionURI());
		assertEquals(((JWT) signedJWT).serialize(), jwtSuccessResponse.getJWTResponse().serialize());
		assertEquals(ResponseMode.JWT, jwtSuccessResponse.getResponseMode());
	}


	public void testParse_httpRequest() throws Exception {

		AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
			URI.create("https://example.com/cb"),
			new AuthorizationCode(),
			null,
			null,
			new State(),
			null,
			ResponseMode.FORM_POST
		);

		HTTPRequest httpRequest = response.toHTTPRequest();

		AuthenticationSuccessResponse parsedResponse = AuthenticationSuccessResponse.parse(httpRequest);

		assertEquals(response.getRedirectionURI(), parsedResponse.getRedirectionURI());
		assertEquals(response.getState(), parsedResponse.getState());
		assertNull(parsedResponse.getIssuer());
		assertNull(parsedResponse.getResponseMode());
	}
}
