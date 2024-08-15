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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.jarm.JARMUtils;
import com.nimbusds.oauth2.sdk.jarm.JARMValidator;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import junit.framework.TestCase;

import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;
import java.util.Map;


public class AuthenticationResponseParserTest extends TestCase {


	public void testParseSuccess()
		throws Exception {

		URI redirectURI = new URI("https://example.com/in");
		AuthorizationCode code = new AuthorizationCode();
		State state = new State();

		AuthenticationSuccessResponse successResponse = new AuthenticationSuccessResponse(
			redirectURI,
			code,
			null,
			null,
			state,
			null,
			null);

		HTTPResponse httpResponse = successResponse.toHTTPResponse();

		AuthenticationResponse response = AuthenticationResponseParser.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(state, response.getState());
		assertNull(response.getIssuer());
		assertNull(response.getJWTResponse());
		assertNull(response.getResponseMode());
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode());

		successResponse = response.toSuccessResponse();
		assertEquals(code, successResponse.getAuthorizationCode());
		assertEquals(state, successResponse.getState());
	}


	public void testParseSuccess_withIssuer()
		throws Exception {

		URI redirectURI = new URI("https://example.com/in");
		AuthorizationCode code = new AuthorizationCode();
		State state = new State();
		Issuer issuer = new Issuer("https://c2id.com");

		AuthenticationSuccessResponse successResponse = new AuthenticationSuccessResponse(
			redirectURI,
			code,
			null,
			null,
			state,
			null,
			issuer,
			null);

		HTTPResponse httpResponse = successResponse.toHTTPResponse();

		AuthenticationResponse response = AuthenticationResponseParser.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(state, response.getState());
		assertEquals(issuer, response.getIssuer());
		assertNull(response.getJWTResponse());
		assertNull(response.getResponseMode());
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode());

		successResponse = response.toSuccessResponse();
		assertEquals(code, successResponse.getAuthorizationCode());
		assertEquals(state, successResponse.getState());
	}


	public void testParseError()
		throws Exception {

		URI redirectURI = new URI("https://example.com/in");
		State state = new State("xyz");

		AuthenticationErrorResponse errorResponse = new AuthenticationErrorResponse(
			redirectURI,
			OAuth2Error.ACCESS_DENIED,
			state,
			ResponseMode.QUERY);

		assertFalse(errorResponse.indicatesSuccess());

		HTTPResponse httpResponse = errorResponse.toHTTPResponse();

		AuthenticationResponse response = AuthenticationResponseParser.parse(httpResponse);

		assertFalse(response.indicatesSuccess());
		assertEquals(redirectURI, response.getRedirectionURI());
		assertEquals(state, response.getState());
		assertNull(response.getIssuer());
		assertNull(response.getJWTResponse());
		assertNull(response.getResponseMode());
		assertEquals(ResponseMode.QUERY, response.impliedResponseMode());

		errorResponse = response.toErrorResponse();
		assertEquals(OAuth2Error.ACCESS_DENIED, errorResponse.getErrorObject());
		assertEquals(state, errorResponse.getState());
	}


	// see https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/162/authenticationresponseparser-does-not
	public void testParseAbsoluteURI()
		throws Exception {

		URI redirectURI = URI.create("http:///?code=Qcb0Orv1&state=af0ifjsldkj");

		AuthenticationResponse response = AuthenticationResponseParser.parse(redirectURI);

		AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse)response;

		assertEquals("Qcb0Orv1", successResponse.getAuthorizationCode().getValue());
		assertEquals("af0ifjsldkj", successResponse.getState().getValue());
	}
	
	
	public void testJARM_parse_queryExample()
		throws Exception {
		
		URI uri = URI.create("https://client.example.com/cb?" +
			"response=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLm" +
			"V4YW1wbGUuY29tIiwiYXVkIjoiczZCaGRSa3F0MyIsImV4cCI6MTMxMTI4MTk3MCwiY29kZSI6IlB5eU" +
			"ZhdXgybzdRMFlmWEJVMzJqaHcuNUZYU1FwdnI4YWt2OUNlUkRTZDBRQSIsInN0YXRlIjoiUzhOSjd1cW" +
			"s1Zlk0RWpOdlBfR19GdHlKdTZwVXN2SDlqc1luaTlkTUFKdyJ9.HkdJ_TYgwBBj10C-aWuNUiA062Amq" +
			"2b0_oyuc5P0aMTQphAqC2o9WbGSkpfuHVBowlb-zJ15tBvXDIABL_t83q6ajvjtq_pqsByiRK2dLVdUw" +
			"KhW3P_9wjvI0K20gdoTNbNlP9Z41mhart4BqraIoI8e-L_EfAHfhCG_DDDv7Yg");
		
		AuthenticationResponse response = AuthenticationResponseParser.parse(uri);
		assertTrue(response.indicatesSuccess());
		assertEquals(URI.create("https://client.example.com/cb"), response.getRedirectionURI());
		assertNull(response.getState());
		assertNull(response.getIssuer());
		assertTrue(response.getJWTResponse() instanceof SignedJWT);
		assertEquals(ResponseMode.JWT, response.getResponseMode());
		assertEquals(ResponseMode.JWT, response.impliedResponseMode());
		
		AuthenticationSuccessResponse successResponse = response.toSuccessResponse();
		assertNull(successResponse.getAuthorizationCode());
		assertNull(successResponse.getAccessToken());
		assertNull(successResponse.getState());
		assertEquals(ResponseMode.JWT, successResponse.getResponseMode());
		
		JWT jwtResponse = successResponse.getJWTResponse();
		
		JWTClaimsSet jwtClaimsSet = jwtResponse.getJWTClaimsSet();
		
		assertEquals("https://accounts.example.com", jwtClaimsSet.getIssuer());
		assertEquals("s6BhdRkqt3", jwtClaimsSet.getAudience().get(0));
		assertEquals(1311281970L, jwtClaimsSet.getExpirationTime().getTime() / 1000L);
		assertEquals("PyyFaux2o7Q0YfXBU32jhw.5FXSQpvr8akv9CeRDSd0QA", jwtClaimsSet.getStringClaim("code"));
		assertEquals("S8NJ7uqk5fY4EjNvP_G_FtyJu6pUsvH9jsYni9dMAJw", jwtClaimsSet.getStringClaim("state"));
		assertEquals(5, jwtClaimsSet.getClaims().size());
	}
	
	
	public void testJARM_parse_fragmentExample()
		throws Exception {
		
		URI uri = URI.create("https://client.example.com/cb#" +
			"response=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLm" +
			"V4YW1wbGUuY29tIiwiYXVkIjoiczZCaGRSa3F0MyIsImV4cCI6MTMxMTI4MTk3MCwiYWNjZXNzX3Rva2" +
			"VuIjoiMllvdG5GWkZFanIxekNzaWNNV3BBQSIsInN0YXRlIjoiUzhOSjd1cWs1Zlk0RWpOdlBfR19GdH" +
			"lKdTZwVXN2SDlqc1luaTlkTUFKdyIsInRva2VuX3R5cGUiOiJiZWFyZXIiLCJleHBpcmVzX2luIjoiMz" +
			"YwMCIsInNjb3BlIjoiZXhhbXBsZSJ9.bgHLOu2dlDjtCnvTLK7hTN_JNwoZXEBnbXQx5vd9z17v1Hyzf" +
			"Mqz00Vi002T-SWf2JEs3IVSvAe1xWLIY0TeuaiegklJx_gvB59SQIhXX2ifzRmqPoDdmJGaWZ3tnRyFW" +
			"NnEogJDqGFCo2RHtk8fXkE5IEiBD0g-tN0GS_XnxlE");
		
		AuthenticationResponse response = AuthenticationResponseParser.parse(uri);
		
		AuthenticationSuccessResponse successResponse = response.toSuccessResponse();
		assertNull(successResponse.getAuthorizationCode());
		assertNull(successResponse.getAccessToken());
		assertNull(successResponse.getState());
		assertEquals(ResponseMode.JWT, successResponse.getResponseMode());
		
		JWT jwtResponse = successResponse.getJWTResponse();
		
		JWTClaimsSet jwtClaimsSet = jwtResponse.getJWTClaimsSet();
		
		assertEquals("https://accounts.example.com", jwtClaimsSet.getIssuer());
		assertEquals("s6BhdRkqt3", jwtClaimsSet.getAudience().get(0));
		assertEquals(1311281970L, jwtClaimsSet.getExpirationTime().getTime() / 1000L);
		assertEquals("2YotnFZFEjr1zCsicMWpAA", jwtClaimsSet.getStringClaim("access_token"));
		assertEquals("example", jwtClaimsSet.getStringClaim("scope"));
		assertEquals("bearer", jwtClaimsSet.getStringClaim("token_type"));
		assertEquals("3600", jwtClaimsSet.getStringClaim("expires_in"));
		assertEquals("S8NJ7uqk5fY4EjNvP_G_FtyJu6pUsvH9jsYni9dMAJw", jwtClaimsSet.getStringClaim("state"));
		assertEquals(8, jwtClaimsSet.getClaims().size());
	}
	
	
	public void testJARM_parse_formPOSTExample()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://client.example.org/cb"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("response=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2" +
			"FjY291bnRzLmV4YW1wbGUuY29tIiwiYXVkIjoiczZCaGRSa3F0MyIsImV4cCI6MTM" +
			"xMTI4MTk3MCwiYWNjZXNzX3Rva2VuIjoiMllvdG5GWkZFanIxekNzaWNNV3BBQSIs" +
			"InN0YXRlIjoiUzhOSjd1cWs1Zlk0RWpOdlBfR19GdHlKdTZwVXN2SDlqc1luaTlkT" +
			"UFKdyIsInRva2VuX3R5cGUiOiJiZWFyZXIiLCJleHBpcmVzX2luIjoiMzYwMCIsIn" +
			"Njb3BlIjoiZXhhbXBsZSJ9.bgHLOu2dlDjtCnvTLK7hTN_JNwoZXEBnbXQx5vd9z1" +
			"7v1HyzfMqz00Vi002T-SWf2JEs3IVSvAe1xWLIY0TeuaiegklJx_gvB59SQIhXX2i" +
			"fzRmqPoDdmJGaWZ3tnRyFWNnEogJDqGFCo2RHtk8fXkE5IEiBD0g-tN0GS_XnxlE");
		
		AuthenticationResponse response = AuthenticationResponseParser.parse(httpRequest);
		
		AuthenticationSuccessResponse successResponse = response.toSuccessResponse();
		assertNull(successResponse.getAuthorizationCode());
		assertNull(successResponse.getAccessToken());
		assertNull(successResponse.getState());
		assertEquals(ResponseMode.JWT, successResponse.getResponseMode());
		
		JWT jwtResponse = successResponse.getJWTResponse();
		
		JWTClaimsSet jwtClaimsSet = jwtResponse.getJWTClaimsSet();
		
		assertEquals("https://accounts.example.com", jwtClaimsSet.getIssuer());
		assertEquals("s6BhdRkqt3", jwtClaimsSet.getAudience().get(0));
		assertEquals(1311281970L, jwtClaimsSet.getExpirationTime().getTime() / 1000L);
		assertEquals("2YotnFZFEjr1zCsicMWpAA", jwtClaimsSet.getStringClaim("access_token"));
		assertEquals("example", jwtClaimsSet.getStringClaim("scope"));
		assertEquals("bearer", jwtClaimsSet.getStringClaim("token_type"));
		assertEquals("3600", jwtClaimsSet.getStringClaim("expires_in"));
		assertEquals("S8NJ7uqk5fY4EjNvP_G_FtyJu6pUsvH9jsYni9dMAJw", jwtClaimsSet.getStringClaim("state"));
		assertEquals(8, jwtClaimsSet.getClaims().size());
	}
	
	
	/// JARM Lifecycle Tests ///
	
	
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
		
		JWT jwt = signedJWT;
		
		AuthenticationSuccessResponse jwtSuccessResponse = new AuthenticationSuccessResponse(
			successResponse.getRedirectionURI(),
			jwt,
			successResponse.getResponseMode());
		
		assertEquals(successResponse.getRedirectionURI(), jwtSuccessResponse.getRedirectionURI());
		assertEquals(jwt, jwtSuccessResponse.getJWTResponse());
		assertEquals(successResponse.getResponseMode(), jwtSuccessResponse.getResponseMode());
		
		Map<String,List<String>> params = jwtSuccessResponse.toParameters();
		assertEquals(jwt.serialize(), MultivaluedMapUtils.getFirstValue(params, "response"));
		assertEquals(1, params.size());
		
		URI uri = jwtSuccessResponse.toURI();
		
		assertTrue(uri.toString().startsWith(successResponse.getRedirectionURI().toString()));
		assertEquals("response=" + jwt.serialize(), uri.getQuery());
		assertNull(uri.getFragment());
		
		jwtSuccessResponse = AuthenticationResponseParser.parse(uri).toSuccessResponse();
		assertEquals(successResponse.getRedirectionURI(), jwtSuccessResponse.getRedirectionURI());
		assertEquals(jwt.serialize(), jwtSuccessResponse.getJWTResponse().serialize());
		assertEquals(ResponseMode.JWT, jwtSuccessResponse.getResponseMode());
		
		// Parse with validator now
		JARMValidator jarmValidator = new JARMValidator(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			JWSAlgorithm.RS256,
			new JWKSet(new RSAKey.Builder(RSA_PUBLIC_KEY).build()));
		
		AuthenticationSuccessResponse validatedResponse = AuthenticationResponseParser.parse(uri, jarmValidator).toSuccessResponse();
		
		assertEquals(successResponse.getAuthorizationCode(), validatedResponse.getAuthorizationCode());
		assertEquals(successResponse.getState(), validatedResponse.getState());
	}
	
	
	public void testJARM_successLifeCycle_fragment()
		throws Exception {
		
		AuthenticationSuccessResponse successResponse = new AuthenticationSuccessResponse(
			URI.create("https://example.com/cb"),
			null,
			null,
			new BearerAccessToken(),
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
		
		JWT jwt = signedJWT;
		
		AuthenticationSuccessResponse jwtSuccessResponse = new AuthenticationSuccessResponse(
			successResponse.getRedirectionURI(),
			jwt,
			successResponse.getResponseMode());
		
		assertEquals(successResponse.getRedirectionURI(), jwtSuccessResponse.getRedirectionURI());
		assertEquals(jwt, jwtSuccessResponse.getJWTResponse());
		assertEquals(successResponse.getResponseMode(), jwtSuccessResponse.getResponseMode());
		
		Map<String,List<String>> params = jwtSuccessResponse.toParameters();
		assertEquals(jwt.serialize(), MultivaluedMapUtils.getFirstValue(params, "response"));
		assertEquals(1, params.size());
		
		URI uri = jwtSuccessResponse.toURI();
		
		assertTrue(uri.toString().startsWith(successResponse.getRedirectionURI().toString()));
		assertNull(uri.getQuery());
		assertEquals("response=" + jwt.serialize(), uri.getFragment());
		
		jwtSuccessResponse = AuthenticationResponseParser.parse(uri).toSuccessResponse();
		assertEquals(successResponse.getRedirectionURI(), jwtSuccessResponse.getRedirectionURI());
		assertEquals(jwt.serialize(), jwtSuccessResponse.getJWTResponse().serialize());
		assertEquals(ResponseMode.JWT, jwtSuccessResponse.getResponseMode());
		
		// Parse with validator now
		JARMValidator jarmValidator = new JARMValidator(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			JWSAlgorithm.RS256,
			new JWKSet(new RSAKey.Builder(RSA_PUBLIC_KEY).build()));
		
		AuthenticationSuccessResponse validatedResponse = AuthenticationResponseParser.parse(uri, jarmValidator).toSuccessResponse();
		
		assertEquals(successResponse.getAccessToken(), validatedResponse.getAccessToken());
		assertEquals(successResponse.getState(), validatedResponse.getState());
	}
	
	
	public void testJARM_errorLifeCycle_query()
		throws Exception {
		
		AuthenticationErrorResponse errorResponse = new AuthenticationErrorResponse(
			URI.create("https://example.com/cb"),
			OAuth2Error.ACCESS_DENIED,
			new State(),
			ResponseMode.QUERY_JWT);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			new Date(),
			errorResponse);
		
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
		signedJWT.sign(new RSASSASigner(RSA_PRIVATE_KEY));
		
		JWT jwt = signedJWT;
		
		AuthenticationErrorResponse jwtErrorResponse = new AuthenticationErrorResponse(
			errorResponse.getRedirectionURI(),
			jwt,
			errorResponse.getResponseMode());
		
		assertEquals(errorResponse.getRedirectionURI(), jwtErrorResponse.getRedirectionURI());
		assertEquals(jwt, jwtErrorResponse.getJWTResponse());
		assertEquals(errorResponse.getResponseMode(), jwtErrorResponse.getResponseMode());
		
		Map<String,List<String>> params = jwtErrorResponse.toParameters();
		assertEquals(jwt.serialize(), MultivaluedMapUtils.getFirstValue(params, "response"));
		assertEquals(1, params.size());
		
		URI uri = jwtErrorResponse.toURI();
		
		assertTrue(uri.toString().startsWith(errorResponse.getRedirectionURI().toString()));
		assertEquals("response=" + jwt.serialize(), uri.getQuery());
		assertNull(uri.getFragment());
		
		jwtErrorResponse = AuthenticationResponseParser.parse(uri).toErrorResponse();
		assertEquals(errorResponse.getRedirectionURI(), jwtErrorResponse.getRedirectionURI());
		assertEquals(jwt.serialize(), jwtErrorResponse.getJWTResponse().serialize());
		assertEquals(ResponseMode.JWT, jwtErrorResponse.getResponseMode());
		
		// Parse with validator now
		JARMValidator jarmValidator = new JARMValidator(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			JWSAlgorithm.RS256,
			new JWKSet(new RSAKey.Builder(RSA_PUBLIC_KEY).build()));
		
		AuthenticationErrorResponse validatedResponse = AuthenticationResponseParser.parse(uri, jarmValidator).toErrorResponse();
		
		assertEquals(errorResponse.getErrorObject(), validatedResponse.getErrorObject());
		assertEquals(errorResponse.getState(), validatedResponse.getState());
	}
	
	
	public void testJARM_errorLifeCycle_fragment()
		throws Exception {
		
		AuthenticationErrorResponse errorResponse = new AuthenticationErrorResponse(
			URI.create("https://example.com/cb"),
			OAuth2Error.ACCESS_DENIED,
			new State(),
			ResponseMode.FRAGMENT_JWT);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			new Date(),
			errorResponse);
		
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
		signedJWT.sign(new RSASSASigner(RSA_PRIVATE_KEY));
		
		JWT jwt = signedJWT;
		
		AuthenticationErrorResponse jwtErrorResponse = new AuthenticationErrorResponse(
			errorResponse.getRedirectionURI(),
			jwt,
			errorResponse.getResponseMode());
		
		assertEquals(errorResponse.getRedirectionURI(), jwtErrorResponse.getRedirectionURI());
		assertEquals(jwt, jwtErrorResponse.getJWTResponse());
		assertEquals(errorResponse.getResponseMode(), jwtErrorResponse.getResponseMode());
		
		Map<String,List<String>> params = jwtErrorResponse.toParameters();
		assertEquals(jwt.serialize(), MultivaluedMapUtils.getFirstValue(params, "response"));
		assertEquals(1, params.size());
		
		URI uri = jwtErrorResponse.toURI();
		
		assertTrue(uri.toString().startsWith(errorResponse.getRedirectionURI().toString()));
		assertNull(uri.getQuery());
		assertEquals("response=" + jwt.serialize(), uri.getFragment());
		
		jwtErrorResponse = AuthenticationResponseParser.parse(uri).toErrorResponse();
		assertEquals(errorResponse.getRedirectionURI(), jwtErrorResponse.getRedirectionURI());
		assertEquals(jwt.serialize(), jwtErrorResponse.getJWTResponse().serialize());
		assertEquals(ResponseMode.JWT, jwtErrorResponse.getResponseMode());
		
		// Parse with validator now
		JARMValidator jarmValidator = new JARMValidator(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			JWSAlgorithm.RS256,
			new JWKSet(new RSAKey.Builder(RSA_PUBLIC_KEY).build()));
		
		AuthenticationErrorResponse validatedResponse = AuthenticationResponseParser.parse(uri, jarmValidator).toErrorResponse();
		
		assertEquals(errorResponse.getErrorObject(), validatedResponse.getErrorObject());
		assertEquals(errorResponse.getState(), validatedResponse.getState());
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

		AuthenticationSuccessResponse parsedResponse = AuthenticationResponseParser.parse(httpRequest).toSuccessResponse();

		assertEquals(response.getRedirectionURI(), parsedResponse.getRedirectionURI());
		assertEquals(response.getState(), parsedResponse.getState());
		assertNull(parsedResponse.getIssuer());
		assertNull(parsedResponse.getResponseMode());
	}


	public void testParse_httpRequest_jarmValidator() throws Exception {

		Issuer issuer = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("123");
		Date exp = new Date(); // now
		AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
			URI.create("https://example.com/cb"),
			new AuthorizationCode(),
			null,
			null,
			new State(),
			null,
			null
		);

		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
			issuer,
			clientID,
			exp,
			response
		);

		Secret clientSecret = new Secret();

		SignedJWT jarm = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), jwtClaimsSet);
		jarm.sign(new MACSigner(clientSecret.getValueBytes()));

		AuthenticationSuccessResponse jarmResponse = new AuthenticationSuccessResponse(
			response.getRedirectionURI(),
			jarm,
			ResponseMode.FORM_POST_JWT
		);

		HTTPRequest httpRequest = jarmResponse.toHTTPRequest();

		JARMValidator jarmValidator = new JARMValidator(issuer, clientID, JWSAlgorithm.HS256, clientSecret);

		AuthenticationSuccessResponse parsedResponse = AuthenticationResponseParser.parse(httpRequest, jarmValidator).toSuccessResponse();

		assertEquals(response.getRedirectionURI(), parsedResponse.getRedirectionURI());
		assertEquals(response.getState(), parsedResponse.getState());
		assertEquals(issuer, parsedResponse.getIssuer());
		assertEquals(response.getResponseMode(), parsedResponse.getResponseMode());
	}
}
