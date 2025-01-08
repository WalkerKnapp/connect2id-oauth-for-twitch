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


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.LogoutTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import junit.framework.TestCase;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;


public class BackChannelLogoutRequestTest extends TestCase {
	
	
	private static final RSAKey RSA_JWK;
	
	
	private static final URI LOGOUT_ENDPOINT_URI = URI.create("https://rp.example.com/logout");
	
	
	private static final URL LOGOUT_ENDPOINT_URL;
	
	
	static {
		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(2048);
			KeyPair kp = gen.generateKeyPair();
			RSA_JWK = new RSAKey.Builder((RSAPublicKey)kp.getPublic())
				.privateKey((RSAPrivateKey)kp.getPrivate())
				.keyIDFromThumbprint()
				.build();
			
			LOGOUT_ENDPOINT_URL = LOGOUT_ENDPOINT_URI.toURL();
			
		} catch (NoSuchAlgorithmException | JOSEException | MalformedURLException e) {
			throw new RuntimeException(e);
		}
	}
	
	
	private static JWTClaimsSet createLogoutTokenClaimsSet() {
		
		LogoutTokenClaimsSet claimsSet = new LogoutTokenClaimsSet(
			new Issuer(URI.create("https://c2id.com")),
			new Subject("alice"),
			new Audience("123").toSingleAudienceList(),
			new Date(),
			new JWTID(),
			new SessionID(UUID.randomUUID().toString()));
		
		try {
			return claimsSet.toJWTClaimsSet();
		} catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}
	

	private static JWT createSignedLogoutToken() {
		
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.keyID(RSA_JWK.getKeyID())
				.build(),
			createLogoutTokenClaimsSet());
		
		try {
			jwt.sign(new RSASSASigner(RSA_JWK));
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
		
		return jwt;
	}
	
	
	public void testLifeCycle()
		throws Exception {
		
		JWT logoutToken = createSignedLogoutToken();
		
		BackChannelLogoutRequest request = new BackChannelLogoutRequest(LOGOUT_ENDPOINT_URI, logoutToken);
		
		assertEquals(LOGOUT_ENDPOINT_URI, request.getEndpointURI());
		assertEquals(logoutToken, request.getLogoutToken());
		
		Map<String,List<String>> params = request.toParameters();
		assertEquals(Collections.singletonList(logoutToken.serialize()), params.get("logout_token"));
		assertEquals(1, params.size());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		params = httpRequest.getBodyAsFormParameters();
		assertEquals(Collections.singletonList(logoutToken.serialize()), params.get("logout_token"));
		assertEquals(1, params.size());
		
		// Parse from HTTP request
		request = BackChannelLogoutRequest.parse(httpRequest);
		assertEquals(LOGOUT_ENDPOINT_URI, request.getEndpointURI());
		assertEquals(logoutToken.serialize(), request.getLogoutToken().serialize());
		
		// Parse from URI + parameters
		request = BackChannelLogoutRequest.parse(LOGOUT_ENDPOINT_URI, params);
		assertEquals(LOGOUT_ENDPOINT_URI, request.getEndpointURI());
		assertEquals(logoutToken.serialize(), request.getLogoutToken().serialize());
		
		// Parse from parameters
		request = BackChannelLogoutRequest.parse(params);
		assertNull(request.getEndpointURI());
		assertEquals(logoutToken.serialize(), request.getLogoutToken().serialize());
	}
	
	
	public void testParseMissingParams() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, LOGOUT_ENDPOINT_URL);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		
		try {
			BackChannelLogoutRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing URI query string", e.getMessage());
		}
	}
	
	
	public void testParseInvalidJWT() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, LOGOUT_ENDPOINT_URL);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("logout_token=ey...");
		
		try {
			BackChannelLogoutRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid logout token: Invalid unsecured/JWS/JWE header: Invalid JSON object", e.getMessage());
		}
	}
	
	
	public void testRejectPlainJWT_constructor() {
		
		URI LOGOUT_ENDPOINT_URI = URI.create("https://rp.example.com/logout");
		
		PlainJWT jwt = new PlainJWT(createLogoutTokenClaimsSet());
		
		try {
			new BackChannelLogoutRequest(LOGOUT_ENDPOINT_URI, jwt);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The logout token must not be unsecured (plain)", e.getMessage());
		}
	}
	
	
	public void testRejectPlainJWT_parse() {
		
		PlainJWT jwt = new PlainJWT(createLogoutTokenClaimsSet());
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, LOGOUT_ENDPOINT_URL);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("logout_token=" + jwt.serialize());
		
		try {
			BackChannelLogoutRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("The logout token must not be unsecured (plain)", e.getMessage());
		}
	}
	
	
	public void testRejectGET() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, LOGOUT_ENDPOINT_URL);
		JWT logoutToken = createSignedLogoutToken();
		httpRequest.appendQueryString("logout_token=" + logoutToken.serialize());
		
		try {
			BackChannelLogoutRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("HTTP POST required", e.getMessage());
		}
	}
	
	
	public void testIgnoreMissingContentType()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, LOGOUT_ENDPOINT_URL);
		JWT logoutToken = createSignedLogoutToken();
		httpRequest.setBody("logout_token=" + logoutToken.serialize());
		
		BackChannelLogoutRequest request = BackChannelLogoutRequest.parse(httpRequest);
		assertEquals(LOGOUT_ENDPOINT_URI, request.getEndpointURI());
		assertEquals(logoutToken.serialize(), request.getLogoutToken().serialize());
	}
	
	
	public void testIgnoreMismatchedContentType()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, LOGOUT_ENDPOINT_URL);
		httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);
		JWT logoutToken = createSignedLogoutToken();
		httpRequest.setBody("logout_token=" + logoutToken.serialize());
		
		BackChannelLogoutRequest request = BackChannelLogoutRequest.parse(httpRequest);
		assertEquals(LOGOUT_ENDPOINT_URI, request.getEndpointURI());
		assertEquals(logoutToken.serialize(), request.getLogoutToken().serialize());
	}
}
