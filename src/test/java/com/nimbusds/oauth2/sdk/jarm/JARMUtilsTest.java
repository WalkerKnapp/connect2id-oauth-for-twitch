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

package com.nimbusds.oauth2.sdk.jarm;


import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;


public class JARMUtilsTest extends TestCase {
	
	
	private static final Issuer ISSUER = new Issuer("https://c2id.com");
	
	private static final URI JWKS_URI = URI.create("https://c2id.com/jwks.json");
	
	private static final RSAPrivateKey RSA_PRIVATE_KEY;
	
	private static final RSAPublicKey RSA_PUBLIC_KEY;
	
	
	static {
		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(2048);
			KeyPair keyPair = gen.generateKeyPair();
			RSA_PRIVATE_KEY = (RSAPrivateKey) keyPair.getPrivate();
			RSA_PUBLIC_KEY = (RSAPublicKey) keyPair.getPublic();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public void testResponseModes() {
		
		assertTrue(JARMUtils.RESPONSE_MODES.contains(ResponseMode.JWT));
		assertTrue(JARMUtils.RESPONSE_MODES.contains(ResponseMode.QUERY_JWT));
		assertTrue(JARMUtils.RESPONSE_MODES.contains(ResponseMode.FRAGMENT_JWT));
		assertTrue(JARMUtils.RESPONSE_MODES.contains(ResponseMode.FORM_POST_JWT));
		assertEquals(4, JARMUtils.RESPONSE_MODES.size());
	}
	
	
	public void testSupportsJARM() {
		
		OIDCProviderMetadata opMetadata = new OIDCProviderMetadata(ISSUER, Collections.singletonList(SubjectType.PAIRWISE), JWKS_URI);
		opMetadata.applyDefaults();
		
		assertFalse("Default OP metadata", JARMUtils.supportsJARM(opMetadata));
		
		opMetadata.setAuthorizationJWSAlgs(Collections.singletonList(JWSAlgorithm.RS256));
		
		assertFalse(JARMUtils.supportsJARM(opMetadata));
		
		opMetadata.setResponseModes(Arrays.asList(ResponseMode.QUERY, ResponseMode.QUERY_JWT));
		
		assertTrue(JARMUtils.supportsJARM(opMetadata));
	}
	
	
	public void testToJWTClaimsSet_successResponse() throws ParseException {
		
		Issuer issuer = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date exp = new Date(); // now
		AuthorizationSuccessResponse response = new AuthorizationSuccessResponse(
			URI.create("https://exmaple.com?cb"),
			new AuthorizationCode(),
			null,
			new State(),
			null
		);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
			issuer,
			clientID,
			exp,
			response
		);
		
		assertEquals(issuer.getValue(), jwtClaimsSet.getIssuer());
		assertEquals(clientID.getValue(), jwtClaimsSet.getAudience().get(0));
		assertEquals(DateUtils.toSecondsSinceEpoch(exp), DateUtils.toSecondsSinceEpoch(jwtClaimsSet.getExpirationTime()));
		
		assertEquals(response.getAuthorizationCode().getValue(), jwtClaimsSet.getStringClaim("code"));
		assertEquals(response.getState().getValue(), jwtClaimsSet.getStringClaim("state"));
		
		assertEquals(5, jwtClaimsSet.getClaims().size());
	}
	
	
	public void testToJWTClaimsSet_oidcAuthSuccessResponse() throws ParseException {
		
		Issuer issuer = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date exp = new Date(); // now
		AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
			URI.create("https://exmaple.com?cb"),
			new AuthorizationCode(),
			null,
			null,
			new State(),
			new State(), // session_state
			null
		);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
			issuer,
			clientID,
			exp,
			response
		);
		
		assertEquals(issuer.getValue(), jwtClaimsSet.getIssuer());
		assertEquals(clientID.getValue(), jwtClaimsSet.getAudience().get(0));
		assertEquals(DateUtils.toSecondsSinceEpoch(exp), DateUtils.toSecondsSinceEpoch(jwtClaimsSet.getExpirationTime()));
		
		assertEquals(response.getAuthorizationCode().getValue(), jwtClaimsSet.getStringClaim("code"));
		assertEquals(response.getState().getValue(), jwtClaimsSet.getStringClaim("state"));
		assertEquals(response.getSessionState().getValue(), jwtClaimsSet.getStringClaim("session_state"));
		
		assertEquals(6, jwtClaimsSet.getClaims().size());
	}
	
	
	public void testToJWTClaimsSet_errorResponse() throws ParseException {
		
		Issuer issuer = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date exp = new Date(); // now
		AuthorizationErrorResponse response = new AuthorizationErrorResponse(
			URI.create("https://exmaple.com?cb"),
			OAuth2Error.ACCESS_DENIED,
			new State(),
			null
		);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
			issuer,
			clientID,
			exp,
			response
		);
		
		assertEquals(issuer.getValue(), jwtClaimsSet.getIssuer());
		assertEquals(clientID.getValue(), jwtClaimsSet.getAudience().get(0));
		assertEquals(DateUtils.toSecondsSinceEpoch(exp), DateUtils.toSecondsSinceEpoch(jwtClaimsSet.getExpirationTime()));
		
		
		assertEquals(response.getState().getValue(), jwtClaimsSet.getStringClaim("state"));
		assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), jwtClaimsSet.getStringClaim("error"));
		assertEquals(OAuth2Error.ACCESS_DENIED.getDescription(), jwtClaimsSet.getStringClaim("error_description"));
		assertEquals(6, jwtClaimsSet.getClaims().size());
	}
	
	
	// OAuth 2.0 Authorization Server Issuer Identification (RFC 9207)
	public void testToJWTClaimsSet_issuerInResponse() throws ParseException {
		
		Issuer issuer = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date exp = new Date(); // now
		AuthorizationSuccessResponse response = new AuthorizationSuccessResponse(
			URI.create("https://exmaple.com?cb"),
			new AuthorizationCode(),
			null,
			new State(),
			issuer, //
			null
		);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
			issuer,
			clientID,
			exp,
			response
		);
		
		assertEquals(issuer.getValue(), jwtClaimsSet.getIssuer());
		assertEquals(clientID.getValue(), jwtClaimsSet.getAudience().get(0));
		assertEquals(DateUtils.toSecondsSinceEpoch(exp), DateUtils.toSecondsSinceEpoch(jwtClaimsSet.getExpirationTime()));
		
		assertEquals(response.getAuthorizationCode().getValue(), jwtClaimsSet.getStringClaim("code"));
		assertEquals(response.getState().getValue(), jwtClaimsSet.getStringClaim("state"));
		
		assertEquals(5, jwtClaimsSet.getClaims().size());
	}
	
	
	// OAuth 2.0 Authorization Server Issuer Identification (RFC 9207)
	public void testToJWTClaimsSet_issuerInResponseMustMatch() {
		
		Issuer issuer = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date exp = new Date(); // now
		AuthorizationSuccessResponse response = new AuthorizationSuccessResponse(
			URI.create("https://exmaple.com?cb"),
			new AuthorizationCode(),
			null,
			new State(),
			new Issuer("https://example.com/login"), // no match
			null
		);
		
		IllegalArgumentException ex = null;
		try {
			JARMUtils.toJWTClaimsSet(
				issuer,
				clientID,
				exp,
				response
			);
			fail();
		} catch (IllegalArgumentException e) {
			ex = e;
		}
		assertEquals("Authorization response iss doesn't match JWT iss claim: " + response.getIssuer(), ex.getMessage());
	}
	
	
	public void testToJWTClaimsSet_issNotNull() {
		
		try {
			JARMUtils.toJWTClaimsSet(
				null,
				new ClientID("123"),
				new Date(),
				new AuthorizationSuccessResponse(
					URI.create("https://exmaple.com?cb"),
					new AuthorizationCode(),
					null,
					new State(),
					null
				)
			);
		} catch (NullPointerException e) {
			// ok
		}
	}
	
	
	public void testToJWTClaimsSet_audNotNull() {
		
		try {
			JARMUtils.toJWTClaimsSet(
				new Issuer("https://c2id.com"),
				null,
				new Date(),
				new AuthorizationSuccessResponse(
					URI.create("https://exmaple.com?cb"),
					new AuthorizationCode(),
					null,
					new State(),
					null
				)
			);
		} catch (NullPointerException e) {
			// ok
		}
	}
	
	
	public void testToJWTClaimsSet_expNotNull() {
		
		try {
			JARMUtils.toJWTClaimsSet(
				new Issuer("https://c2id.com"),
				new ClientID("123"),
				null,
				new AuthorizationSuccessResponse(
					URI.create("https://exmaple.com?cb"),
					new AuthorizationCode(),
					null,
					new State(),
					null
				)
			);
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testImpliesAuthorizationErrorResponse_positive()
		throws Exception {
		
		AuthorizationErrorResponse response = new AuthorizationErrorResponse(
			URI.create("https://exmaple.com?cb"),
			OAuth2Error.ACCESS_DENIED,
			new State(),
			null
		);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(new Issuer("https://c2id.com"), new ClientID("123"), new Date(), response);
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
		jwt.sign(new RSASSASigner(RSA_PRIVATE_KEY));
		
		assertTrue(JARMUtils.impliesAuthorizationErrorResponse((JWT)jwt));
	}
	
	
	public void testImpliesAuthorizationErrorResponse_negative()
		throws Exception {
		
		JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder().build(); // simply no "error" claim
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
		jwt.sign(new RSASSASigner(RSA_PRIVATE_KEY));
		
		assertFalse(JARMUtils.impliesAuthorizationErrorResponse((JWT)jwt));
	}
	
	
	public void testImpliesAuthorizationErrorResponse_rejectPlain() {
		
		AuthorizationErrorResponse response = new AuthorizationErrorResponse(
			URI.create("https://exmaple.com?cb"),
			OAuth2Error.ACCESS_DENIED,
			new State(),
			null
		);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(new Issuer("https://c2id.com"), new ClientID("123"), new Date(), response);
		JWT jwt = new PlainJWT(jwtClaimsSet);
		
		try {
			JARMUtils.impliesAuthorizationErrorResponse(jwt);
			fail();
		} catch (com.nimbusds.oauth2.sdk.ParseException e) {
			assertEquals("Invalid JWT-secured authorization response: The JWT must not be plain (unsecured)", e.getMessage());
		}
	}
	
	
	public void testImpliesAuthorizationErrorResponse_encryptedJWTAlwaysAssumesSuccessfulResponse()
		throws Exception {
		
		AuthorizationErrorResponse response = new AuthorizationErrorResponse(
			URI.create("https://exmaple.com?cb"),
			OAuth2Error.ACCESS_DENIED,
			new State(),
			null
		);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(new Issuer("https://c2id.com"), new ClientID("123"), new Date(), response);
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
		signedJWT.sign(new RSASSASigner(RSA_PRIVATE_KEY));
		
		JWEObject jweObject = new JWEObject(new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM), new Payload(signedJWT));
		jweObject.encrypt(new RSAEncrypter(RSA_PUBLIC_KEY));
		
		JWT jwt = JWTParser.parse(jweObject.serialize());
		
		assertFalse(JARMUtils.impliesAuthorizationErrorResponse(jwt));
	}
}
