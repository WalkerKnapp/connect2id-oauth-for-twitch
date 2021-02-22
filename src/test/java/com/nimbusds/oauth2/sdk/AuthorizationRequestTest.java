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


import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.*;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.Prompt;


public class AuthorizationRequestTest extends TestCase {


	public void testRegisteredParameters() {

		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("response_type"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("response_mode"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("client_id"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("redirect_uri"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("scope"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("state"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("code_challenge"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("code_challenge_method"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("resource"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("include_granted_scopes"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("request"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("request_uri"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("prompt"));
		assertEquals(13, AuthorizationRequest.getRegisteredParameterNames().size());
	}
	
	
	public void testMinimal()
		throws Exception {
		
		URI uri = new URI("https://c2id.com/authz/");

		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		ClientID clientID = new ClientID("123456");

		AuthorizationRequest req = new AuthorizationRequest(uri, rts, clientID);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(clientID, req.getClientID());

		assertNull(req.getRedirectionURI());
		assertNull(req.getScope());
		assertNull(req.getState());
		assertNull(req.getResponseMode());
		assertEquals(ResponseMode.QUERY, req.impliedResponseMode());
		
		assertNull(req.getResources());
		
		assertFalse(req.includeGrantedScopes());

		assertNull(req.getCustomParameter("custom-param"));
		assertTrue(req.getCustomParameters().isEmpty());

		String query = req.toQueryString();

		System.out.println("Authorization query: " + query);

		Map<String,List<String>> params = URLUtils.parseParameters(query);
		assertEquals(Collections.singletonList("code"), params.get("response_type"));
		assertEquals(Collections.singletonList("123456"), params.get("client_id"));
		assertEquals(2, params.size());

		HTTPRequest httpReq = req.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpReq.getMethod());
		assertEquals(uri, httpReq.getURL().toURI());
		assertEquals(query, httpReq.getQuery());

		req = AuthorizationRequest.parse(uri, query);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(clientID, req.getClientID());

		assertNull(req.getResponseMode());
		assertNull(req.getRedirectionURI());
		assertNull(req.getScope());
		assertNull(req.getState());
		assertNull(req.getResponseMode());
		assertEquals(ResponseMode.QUERY, req.impliedResponseMode());
		assertNull(req.getResources());
		assertFalse(req.includeGrantedScopes());

		assertNull(req.getCustomParameter("custom-param"));
		assertTrue(req.getCustomParameters().isEmpty());
	}


	public void testMinimalAltParse()
		throws Exception {

		URI uri = new URI("https://c2id.com/authz/");

		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		ClientID clientID = new ClientID("123456");

		AuthorizationRequest req = new AuthorizationRequest(uri, rts, clientID);

		String query = req.toQueryString();

		req = AuthorizationRequest.parse(query);

		assertNull(req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(clientID, req.getClientID());
		assertNull(req.getResponseMode());
		assertNull(req.getRedirectionURI());
		assertNull(req.getScope());
		assertNull(req.getState());
		assertNull(req.getResponseMode());
		assertEquals(ResponseMode.QUERY, req.impliedResponseMode());
		assertNull(req.getResources());
		assertFalse(req.includeGrantedScopes());
		assertNull(req.getCustomParameter("custom-param"));
		assertTrue(req.getCustomParameters().isEmpty());
	}


	public void testToRequestURIWithParse()
		throws Exception {

		URI redirectURI = new URI("https://client.com/cb");
		ResponseType rts = new ResponseType("code");
		ClientID clientID = new ClientID("123456");
		URI endpointURI = new URI("https://c2id.com/login");

		AuthorizationRequest req = new AuthorizationRequest.Builder(rts, clientID).
			redirectionURI(redirectURI).
			endpointURI(endpointURI).
			build();

		URI requestURI = req.toURI();

		assertTrue(requestURI.toString().startsWith(endpointURI.toString() + "?"));
		req = AuthorizationRequest.parse(requestURI);

		assertEquals(endpointURI, req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertNull(req.getResponseMode());
		assertEquals(ResponseMode.QUERY, req.impliedResponseMode());
		assertNull(req.getScope());
		assertNull(req.getState());
		assertNull(req.getResources());
		assertFalse(req.includeGrantedScopes());
		assertNull(req.getCustomParameter("custom-param"));
		assertTrue(req.getCustomParameters().isEmpty());
	}


	public void testFull()
		throws Exception {

		URI uri = new URI("https://c2id.com/authz/");

		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		ResponseMode rm = ResponseMode.FORM_POST;

		ClientID clientID = new ClientID("123456");

		URI redirectURI = new URI("https://example.com/oauth2/");

		Scope scope = Scope.parse("read write");

		State state = new State();

		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.S256;
		CodeChallenge codeChallenge = CodeChallenge.compute(codeChallengeMethod, codeVerifier);
		
		List<URI> resources = Arrays.asList(URI.create("https://rs1.com"), URI.create("https://rs2.com"));
		
		Prompt prompt = new Prompt(Prompt.Type.LOGIN);

		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("x", Collections.singletonList("100"));
		customParams.put("y", Collections.singletonList("200"));
		customParams.put("z", Collections.singletonList("300"));


		AuthorizationRequest req = new AuthorizationRequest(uri, rts, rm, clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod, resources, true, null, null, prompt, customParams);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(rm, req.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, req.impliedResponseMode());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertEquals(scope, req.getScope());
		assertEquals(state, req.getState());
		assertEquals(resources, req.getResources());
		assertEquals(prompt, req.getPrompt());

		String query = req.toQueryString();

		System.out.println("Authorization query: " + query);

		Map<String,List<String>> params = URLUtils.parseParameters(query);

		assertEquals(Collections.singletonList("code"), params.get("response_type"));
		assertEquals(Collections.singletonList("form_post"), params.get("response_mode"));
		assertEquals(Collections.singletonList("123456"), params.get("client_id"));
		assertEquals(Collections.singletonList(redirectURI.toString()), params.get("redirect_uri"));
		assertEquals(Collections.singletonList(scope.toString()), params.get("scope"));
		assertEquals(Collections.singletonList(state.getValue()), params.get("state"));
		assertEquals(Collections.singletonList(codeChallenge.getValue()), params.get("code_challenge"));
		assertEquals(Collections.singletonList(codeChallengeMethod.getValue()), params.get("code_challenge_method"));
		assertEquals(Arrays.asList("https://rs1.com", "https://rs2.com"), params.get("resource"));
		assertEquals(Collections.singletonList(prompt.toString()), params.get("prompt"));
		assertEquals(Collections.singletonList("true"), params.get("include_granted_scopes"));
		assertEquals(Collections.singletonList("100"), params.get("x"));
		assertEquals(Collections.singletonList("200"), params.get("y"));
		assertEquals(Collections.singletonList("300"), params.get("z"));
		assertEquals(14, params.size());

		HTTPRequest httpReq = req.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpReq.getMethod());
		assertEquals(query, httpReq.getQuery());

		req = AuthorizationRequest.parse(uri, query);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(rm, req.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, req.impliedResponseMode());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertEquals(scope, req.getScope());
		assertEquals(state, req.getState());
		assertEquals(codeChallenge, req.getCodeChallenge());
		assertEquals(codeChallengeMethod, req.getCodeChallengeMethod());
		assertEquals(resources, req.getResources());
		assertTrue(req.includeGrantedScopes());
		assertEquals(prompt, req.getPrompt());
		assertEquals(Collections.singletonList("100"), req.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), req.getCustomParameter("y"));
		assertEquals(Collections.singletonList("300"), req.getCustomParameter("z"));
		assertEquals(Collections.singletonList("100"), req.getCustomParameters().get("x"));
		assertEquals(Collections.singletonList("200"), req.getCustomParameters().get("y"));
		assertEquals(Collections.singletonList("300"), req.getCustomParameters().get("z"));
		assertEquals(3, req.getCustomParameters().size());
	}


	public void testFullAltParse()
		throws Exception {

		URI uri = new URI("https://c2id.com/authz/");
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		ClientID clientID = new ClientID("123456");

		URI redirectURI = new URI("https://example.com/oauth2/");

		Scope scope = Scope.parse("read write");

		State state = new State();

		CodeVerifier verifier = new CodeVerifier();
		CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.PLAIN, verifier);
		
		List<URI> resources = Collections.singletonList(URI.create("https://rs1.com"));

		AuthorizationRequest req = new AuthorizationRequest(uri, rts, null, clientID, redirectURI, scope, state, codeChallenge, null, resources, false, null, null, null, null);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertNull(req.getResponseMode());
		assertEquals(ResponseMode.QUERY, req.impliedResponseMode());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertEquals(scope, req.getScope());
		assertEquals(state, req.getState());
		assertEquals(resources, req.getResources());
		assertNull(req.getPrompt());

		String query = req.toQueryString();

		req = AuthorizationRequest.parse(query);

		assertNull(req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertNull(req.getResponseMode());
		assertEquals(ResponseMode.QUERY, req.impliedResponseMode());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertEquals(scope, req.getScope());
		assertEquals(state, req.getState());
		assertEquals(codeChallenge, req.getCodeChallenge());
		assertEquals(resources, req.getResources());
		assertFalse(req.includeGrantedScopes());
		assertNull(req.getCodeChallengeMethod());
	}


	public void testBuilderMinimal() {

		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123")).build();
		
		assertEquals(new ResponseType("code"), request.getResponseType());
		assertEquals(new ClientID("123"), request.getClientID());
		assertNull(request.getEndpointURI());
		assertNull(request.getRedirectionURI());
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.QUERY, request.impliedResponseMode());
		assertNull(request.getScope());
		assertNull(request.getState());
		assertNull(request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());
		assertNull(request.getResources());
		assertFalse(request.includeGrantedScopes());
		assertNull(request.getPrompt());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testBuilderMinimalAlt() {

		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("token"), new ClientID("123")).build();
		
		assertEquals(new ResponseType("token"), request.getResponseType());
		assertEquals(new ClientID("123"), request.getClientID());
		assertNull(request.getEndpointURI());
		assertNull(request.getRedirectionURI());
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.FRAGMENT, request.impliedResponseMode());
		assertNull(request.getScope());
		assertNull(request.getState());
		assertNull(request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());
		assertFalse(request.includeGrantedScopes());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testBuilderMinimalNullCodeChallenge() {

		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("token"), new ClientID("123"))
			.codeChallenge((CodeVerifier) null, null)
			.build();
		
		assertEquals(new ResponseType("token"), request.getResponseType());
		assertEquals(new ClientID("123"), request.getClientID());
		assertNull(request.getEndpointURI());
		assertNull(request.getRedirectionURI());
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.FRAGMENT, request.impliedResponseMode());
		assertNull(request.getScope());
		assertNull(request.getState());
		assertNull(request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());
		assertFalse(request.includeGrantedScopes());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testBuilderMinimalNullCodeChallenge_deprecated() {

		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("token"), new ClientID("123"))
			.codeChallenge((CodeChallenge) null, null)
			.build();
		
		assertEquals(new ResponseType("token"), request.getResponseType());
		assertEquals(new ClientID("123"), request.getClientID());
		assertNull(request.getEndpointURI());
		assertNull(request.getRedirectionURI());
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.FRAGMENT, request.impliedResponseMode());
		assertNull(request.getScope());
		assertNull(request.getState());
		assertNull(request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());
		assertFalse(request.includeGrantedScopes());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testBuilderFull()
		throws Exception {

		CodeVerifier codeVerifier = new CodeVerifier();

		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
			.endpointURI(new URI("https://c2id.com/login"))
			.redirectionURI(new URI("https://client.com/cb"))
			.scope(new Scope("openid", "email"))
			.state(new State("123"))
			.responseMode(ResponseMode.FORM_POST)
			.codeChallenge(codeVerifier, CodeChallengeMethod.S256)
			.resources(URI.create("https://rs1.com"), URI.create("https://rs2.com"))
			.includeGrantedScopes(true)
			.prompt(new Prompt(Prompt.Type.LOGIN))
			.build();
		
		assertEquals(new ResponseType("code"), request.getResponseType());
		assertEquals(ResponseMode.FORM_POST, request.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, request.impliedResponseMode());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals("https://c2id.com/login", request.getEndpointURI().toString());
		assertEquals("https://client.com/cb", request.getRedirectionURI().toString());
		assertEquals(new Scope("openid", "email"), request.getScope());
		assertEquals(new State("123"), request.getState());
		assertEquals(CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier), request.getCodeChallenge());
		assertEquals(CodeChallengeMethod.S256, request.getCodeChallengeMethod());
		assertEquals(Arrays.asList(URI.create("https://rs1.com"), URI.create("https://rs2.com")), request.getResources());
		assertTrue(request.includeGrantedScopes());
		assertEquals(new Prompt(Prompt.Type.LOGIN), request.getPrompt());
	}


	public void testBuilderFullAlt()
		throws Exception {

		CodeVerifier codeVerifier = new CodeVerifier();

		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
			.endpointURI(new URI("https://c2id.com/login"))
			.redirectionURI(new URI("https://client.com/cb"))
			.scope(new Scope("openid", "email"))
			.state(new State("123"))
			.responseMode(ResponseMode.FORM_POST)
			.codeChallenge(codeVerifier, null)
			.resources(URI.create("https://rs1.com"))
			.includeGrantedScopes(false)
			.customParameter("x", "100")
			.customParameter("y", "200")
			.customParameter("z", "300")
			.build();
		
		assertEquals(new ResponseType("code"), request.getResponseType());
		assertEquals(ResponseMode.FORM_POST, request.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, request.impliedResponseMode());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals("https://c2id.com/login", request.getEndpointURI().toString());
		assertEquals("https://client.com/cb", request.getRedirectionURI().toString());
		assertEquals(new Scope("openid", "email"), request.getScope());
		assertEquals(new State("123"), request.getState());
		assertEquals(CodeChallenge.compute(CodeChallengeMethod.PLAIN, codeVerifier), request.getCodeChallenge());
		assertEquals(CodeChallengeMethod.PLAIN, request.getCodeChallengeMethod());
		assertEquals(Collections.singletonList(URI.create("https://rs1.com")), request.getResources());
		assertFalse(request.includeGrantedScopes());
		assertEquals(Collections.singletonList("100"), request.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameter("y"));
		assertEquals(Collections.singletonList("300"), request.getCustomParameter("z"));
		assertEquals(Collections.singletonList("100"), request.getCustomParameters().get("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameters().get("y"));
		assertEquals(Collections.singletonList("300"), request.getCustomParameters().get("z"));
		assertEquals(3, request.getCustomParameters().size());
	}


	public void testBuilderFull_codeChallengeDeprecated()
		throws Exception {

		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier);

		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123")).
			endpointURI(new URI("https://c2id.com/login")).
			redirectionURI(new URI("https://client.com/cb")).
			scope(new Scope("openid", "email")).
			state(new State("123")).
			responseMode(ResponseMode.FORM_POST).
			codeChallenge(codeChallenge, CodeChallengeMethod.S256).
			build();
		
		assertEquals(new ResponseType("code"), request.getResponseType());
		assertEquals(ResponseMode.FORM_POST, request.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, request.impliedResponseMode());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals("https://c2id.com/login", request.getEndpointURI().toString());
		assertEquals("https://client.com/cb", request.getRedirectionURI().toString());
		assertEquals(new Scope("openid", "email"), request.getScope());
		assertEquals(new State("123"), request.getState());
		assertEquals(codeChallenge, request.getCodeChallenge());
		assertEquals(CodeChallengeMethod.S256, request.getCodeChallengeMethod());
	}


	public void testBuilderFullAlt_codeChallengeDeprecated()
		throws Exception {

		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.PLAIN, codeVerifier);


		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
			.endpointURI(new URI("https://c2id.com/login"))
			.redirectionURI(new URI("https://client.com/cb"))
			.scope(new Scope("openid", "email"))
			.state(new State("123"))
			.responseMode(ResponseMode.FORM_POST)
			.codeChallenge(codeChallenge, null)
			.customParameter("x", "100")
			.customParameter("y", "200")
			.customParameter("z", "300")
			.build();
		
		assertEquals(new ResponseType("code"), request.getResponseType());
		assertEquals(ResponseMode.FORM_POST, request.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, request.impliedResponseMode());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals("https://c2id.com/login", request.getEndpointURI().toString());
		assertEquals("https://client.com/cb", request.getRedirectionURI().toString());
		assertEquals(new Scope("openid", "email"), request.getScope());
		assertEquals(new State("123"), request.getState());
		assertEquals(codeChallenge, request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());
		assertEquals(Collections.singletonList("100"), request.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameter("y"));
		assertEquals(Collections.singletonList("300"), request.getCustomParameter("z"));
		assertEquals(Collections.singletonList("100"), request.getCustomParameters().get("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameters().get("y"));
		assertEquals(Collections.singletonList("300"), request.getCustomParameters().get("z"));
		assertEquals(3, request.getCustomParameters().size());
	}


	public void testParseExceptionMissingClientID()
		throws Exception {

		URI requestURI = new URI("https://server.example.com/authorize?" +
			"response_type=code" +
			"&state=xyz" +
			"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb");

		try {
			AuthorizationRequest.parse(requestURI);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing client_id parameter", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing client_id parameter", e.getErrorObject().getDescription());
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testParseExceptionInvalidRedirectionURI()
		throws Exception {

		URI requestURI = new URI("https://server.example.com/authorize?" +
			"response_type=code" +
			"&client_id=s6BhdRkqt3" +
			"&state=xyz" +
			"&redirect_uri=%3A");

		try {
			AuthorizationRequest.parse(requestURI);
			fail();
		} catch (ParseException e) {
			assertTrue(e.getMessage().startsWith("Invalid redirect_uri parameter"));
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertTrue(e.getErrorObject().getDescription().startsWith("Invalid request: Invalid redirect_uri parameter"));
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testParseExceptionMissingResponseType()
		throws Exception {

		URI requestURI = new URI("https://server.example.com/authorize?" +
			"response_type=" +
			"&client_id=123" +
			"&state=xyz" +
			"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb");

		try {
			AuthorizationRequest.parse(requestURI);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing response_type parameter", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing response_type parameter", e.getErrorObject().getDescription());
			assertNull(e.getErrorObject().getURI());
		}
	}


	// See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/147/authorizationrequestparse-final-uri-uri
	public void testParseWithEncodedEqualsChar()
		throws Exception {

		URI redirectURI = URI.create("https://client.com/in?app=123");

		String encodedRedirectURI = URLEncoder.encode(redirectURI.toString(), "UTF-8");

		URI requestURI = URI.create("https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz&redirect_uri=" +
			encodedRedirectURI);

		AuthorizationRequest request = AuthorizationRequest.parse(requestURI);

		assertEquals(ResponseType.parse("code"), request.getResponseType());
		assertEquals(new ClientID("s6BhdRkqt3"), request.getClientID());
		assertEquals(new State("xyz"), request.getState());
		assertEquals(redirectURI, request.getRedirectionURI());
	}
	
	
	public void testCopyConstructorBuilder()
		throws Exception {
		
		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("apples", Collections.singletonList("10"));
		
		AuthorizationRequest in = new AuthorizationRequest(
			new URI("https://example.com/cb"),
			new ResponseType("code"),
			ResponseMode.FORM_POST,
			new ClientID("123"),
			new URI("https://example.com/cb"),
			new Scope("openid"),
			new State(),
			CodeChallenge.compute(CodeChallengeMethod.S256, new CodeVerifier()),
			CodeChallengeMethod.S256,
			Collections.singletonList(URI.create("https://rs1.com")),
			true,
			null,
			null,
			new Prompt(Prompt.Type.LOGIN, Prompt.Type.CONSENT),
			customParams);
		
		AuthorizationRequest out = new AuthorizationRequest.Builder(in).build();
		
		assertEquals(in.getResponseType(), out.getResponseType());
		assertEquals(in.getScope(), out.getScope());
		assertEquals(in.getClientID(), out.getClientID());
		assertEquals(in.getRedirectionURI(), out.getRedirectionURI());
		assertEquals(in.getState(), out.getState());
		assertEquals(in.getResponseMode(), out.getResponseMode());
		assertEquals(in.getCodeChallenge(), out.getCodeChallenge());
		assertEquals(in.getCodeChallengeMethod(), out.getCodeChallengeMethod());
		assertEquals(in.getResources(), out.getResources());
		assertEquals(in.includeGrantedScopes(), out.includeGrantedScopes());
		assertEquals(in.getPrompt(), out.getPrompt());
		assertEquals(in.getCustomParameters(), out.getCustomParameters());
		assertEquals(in.getEndpointURI(), out.getEndpointURI());
	}
	
	
	public void testQueryParamsInEndpoint()
		throws Exception {
		
		URI endpoint = new URI("https://c2id.com/login?foo=bar");
		
		AuthorizationRequest request = new AuthorizationRequest(endpoint, new ResponseType(ResponseType.Value.CODE), new ClientID("123"));
		
		// query parameters belonging to the authz endpoint not included here
		Map<String,List<String>> requestParameters = request.toParameters();
		assertEquals(Collections.singletonList("code"), requestParameters.get("response_type"));
		assertEquals(Collections.singletonList("123"), requestParameters.get("client_id"));
		assertEquals(2, requestParameters.size());
		
		Map<String,List<String>> queryParams = URLUtils.parseParameters(request.toQueryString());
		assertEquals(Collections.singletonList("bar"), queryParams.get("foo"));
		assertEquals(Collections.singletonList("code"), queryParams.get("response_type"));
		assertEquals(Collections.singletonList("123"), queryParams.get("client_id"));
		assertEquals(3, queryParams.size());
		
		URI redirectToAS = request.toURI();
		
		Map<String,List<String>> finalParameters = URLUtils.parseParameters(redirectToAS.getQuery());
		assertEquals(Collections.singletonList("bar"), finalParameters.get("foo"));
		assertEquals(Collections.singletonList("code"), finalParameters.get("response_type"));
		assertEquals(Collections.singletonList("123"), finalParameters.get("client_id"));
		assertEquals(3, finalParameters.size());
	}
	
	
	public void testBuilderWithResource_rejectNonAbsoluteURI() {
		
		try {
			new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
				.resources(URI.create("https:///api/v1"))
				.build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Resource URI must be absolute and with no query or fragment: https:///api/v1", e.getMessage());
		}
	}
	
	
	public void testBuilderWithResource_rejectURIWithQuery() {
		
		try {
			new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
				.resources(URI.create("https://rs1.com/api/v1?query"))
				.build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Resource URI must be absolute and with no query or fragment: https://rs1.com/api/v1?query", e.getMessage());
		}
	}
	
	
	public void testBuilderWithResource_rejectURIWithFragment() {
		
		try {
			new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
				.resources(URI.create("https://rs1.com/api/v1#fragment"))
				.build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Resource URI must be absolute and with no query or fragment: https://rs1.com/api/v1#fragment", e.getMessage());
		}
	}
	
	
	public void testParseResourceIndicatorsExample()
		throws ParseException {
		
		AuthorizationRequest request = AuthorizationRequest.parse(
			URI.create(
				"https://authorization-server.example.com" +
				"/as/authorization.oauth2?response_type=token" +
				"&client_id=s6BhdRkqt3&state=laeb" +
				"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb" +
				"&resource=https%3A%2F%2Frs.example.com%2F"));
		
		assertEquals(new ClientID("s6BhdRkqt3"), request.getClientID());
		assertEquals(new State("laeb"), request.getState());
		assertEquals(new ResponseType("token"), request.getResponseType());
		assertEquals(URI.create("https://client.example.com/cb"), request.getRedirectionURI());
		assertEquals(Collections.singletonList(URI.create("https://rs.example.com/")), request.getResources());
	}
	
	
	public void testParse_rejectResourceURIWithHostNotAbsolute() {
		
		try {
			AuthorizationRequest.parse(URI.create("https://authorization-server.example.com" +
				"/as/authorization.oauth2?response_type=token" +
				"&client_id=s6BhdRkqt3&state=laeb" +
				"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb" +
				"&resource=https%3A%2F%2F%2F"));
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_RESOURCE, e.getErrorObject());
			assertEquals("Illegal resource parameter: Must be an absolute URI and with no query or fragment: https:///", e.getErrorObject().getDescription());
		}
	}
	
	
	public void testParse_rejectResourceURIWithQuery()
		throws UnsupportedEncodingException {
		
		try {
			AuthorizationRequest.parse(URI.create("https://authorization-server.example.com" +
				"/as/authorization.oauth2?response_type=token" +
				"&client_id=s6BhdRkqt3&state=laeb" +
				"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb" +
				"&resource=" + URLEncoder.encode("https://rs.example.com/?query", "utf-8")));
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_RESOURCE, e.getErrorObject());
			assertEquals("Illegal resource parameter: Must be an absolute URI and with no query or fragment: https://rs.example.com/?query", e.getErrorObject().getDescription());
		}
	}
	
	
	public void testParse_rejectResourceURIWithFragment()
		throws UnsupportedEncodingException {
		
		try {
			AuthorizationRequest.parse(URI.create("https://authorization-server.example.com" +
				"/as/authorization.oauth2?response_type=token" +
				"&client_id=s6BhdRkqt3&state=laeb" +
				"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb" +
				"&resource=" + URLEncoder.encode("https://rs.example.com/#fragment", "utf-8")));
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_RESOURCE, e.getErrorObject());
			assertEquals("Illegal resource parameter: Must be an absolute URI and with no query or fragment: https://rs.example.com/#fragment", e.getErrorObject().getDescription());
		}
	}
	
	
	public void testImpliedResponseMode_JARM_JWT() {
		
		assertEquals(
			ResponseMode.QUERY_JWT,
			new AuthorizationRequest.Builder(new ResponseType(ResponseType.Value.CODE), new ClientID("123"))
				.responseMode(ResponseMode.JWT)
				.build()
				.impliedResponseMode()
		);
		
		assertEquals(
			ResponseMode.QUERY_JWT,
			new AuthorizationRequest.Builder(new ResponseType(ResponseType.Value.CODE), new ClientID("123"))
				.responseMode(ResponseMode.QUERY_JWT)
				.build()
				.impliedResponseMode()
		);
		
		assertEquals(
			ResponseMode.FRAGMENT_JWT,
			new AuthorizationRequest.Builder(new ResponseType(ResponseType.Value.TOKEN), new ClientID("123"))
				.responseMode(ResponseMode.JWT)
				.build()
				.impliedResponseMode()
		);
		
		assertEquals(
			ResponseMode.FRAGMENT_JWT,
			new AuthorizationRequest.Builder(new ResponseType(ResponseType.Value.TOKEN), new ClientID("123"))
				.responseMode(ResponseMode.FRAGMENT_JWT)
				.build()
				.impliedResponseMode()
		);
	}
	
	
	public void testToJWTClaimsSet() throws java.text.ParseException {
		
		AuthorizationRequest ar = new AuthorizationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new ClientID("123"))
			.redirectionURI(URI.create("https://example.com/cb"))
			.state(new State())
			.build();
		
		JWTClaimsSet jwtClaimsSet = ar.toJWTClaimsSet();
		
		assertEquals(ar.getResponseType().toString(), jwtClaimsSet.getStringClaim("response_type"));
		assertEquals(ar.getClientID().toString(), jwtClaimsSet.getStringClaim("client_id"));
		assertEquals(ar.getRedirectionURI().toString(), jwtClaimsSet.getStringClaim("redirect_uri"));
		assertEquals(ar.getState().toString(), jwtClaimsSet.getStringClaim("state"));
		
		assertEquals(4, jwtClaimsSet.getClaims().size());
	}
	
	
	public void testToJWTClaimsSet_multipleResourceParams() throws java.text.ParseException {
		
		AuthorizationRequest ar = new AuthorizationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new ClientID("123"))
			.redirectionURI(URI.create("https://example.com/cb"))
			.state(new State())
			.resources(URI.create("https://one.rs.com"), URI.create("https://two.rs.com"))
			.build();
		
		JWTClaimsSet jwtClaimsSet = ar.toJWTClaimsSet();
		
		assertEquals(ar.getResponseType().toString(), jwtClaimsSet.getStringClaim("response_type"));
		assertEquals(ar.getClientID().toString(), jwtClaimsSet.getStringClaim("client_id"));
		assertEquals(ar.getRedirectionURI().toString(), jwtClaimsSet.getStringClaim("redirect_uri"));
		assertEquals(ar.getState().toString(), jwtClaimsSet.getStringClaim("state"));
		assertEquals(ar.getResources().get(0).toString(), jwtClaimsSet.getStringListClaim("resource").get(0));
		assertEquals(ar.getResources().get(1).toString(), jwtClaimsSet.getStringListClaim("resource").get(1));
		assertEquals(ar.getResources().size(), jwtClaimsSet.getStringListClaim("resource").size());
		
		assertEquals(5, jwtClaimsSet.getClaims().size());
	}
	
	
	public void testJAR_requestURI_minimal()
		throws ParseException {
		
		URI endpointURI = URI.create("https://c2id.com/login");
		URI requestURI = URI.create("urn:requests:ahy4ohgo");
		ClientID clientID = new ClientID("123");
		
		AuthorizationRequest ar = new AuthorizationRequest.Builder(requestURI, clientID)
			.endpointURI(endpointURI)
			.build();
		
		assertNull(ar.getResponseType());
		assertEquals(clientID, ar.getClientID());
		assertNull(ar.getRedirectionURI());
		assertNull(ar.getScope());
		assertNull(ar.getState());
		assertNull(ar.getResponseMode());
		assertEquals(ResponseMode.QUERY, ar.impliedResponseMode());
		assertNull(ar.getResources());
		assertFalse(ar.includeGrantedScopes());
		assertNull(ar.getCustomParameter("custom-param"));
		assertTrue(ar.getCustomParameters().isEmpty());
		
		assertEquals(endpointURI, ar.getEndpointURI());
		assertEquals(requestURI, ar.getRequestURI());
		assertNull(ar.getRequestObject());
		assertTrue(ar.specifiesRequestObject());
		
		assertEquals(Collections.singletonList(requestURI.toString()), ar.toParameters().get("request_uri"));
		assertEquals(Collections.singletonList(clientID.getValue()), ar.toParameters().get("client_id"));
		assertEquals(2, ar.toParameters().size());
		
		ar = AuthorizationRequest.parse(ar.toURI());
		
		assertNull(ar.getResponseType());
		assertEquals(clientID, ar.getClientID());
		assertNull(ar.getRedirectionURI());
		assertNull(ar.getScope());
		assertNull(ar.getState());
		assertNull(ar.getResponseMode());
		assertEquals(ResponseMode.QUERY, ar.impliedResponseMode());
		assertNull(ar.getResources());
		assertFalse(ar.includeGrantedScopes());
		assertNull(ar.getCustomParameter("custom-param"));
		assertTrue(ar.getCustomParameters().isEmpty());
		
		assertEquals(endpointURI, ar.getEndpointURI());
		assertEquals(requestURI, ar.getRequestURI());
		assertNull(ar.getRequestObject());
		assertTrue(ar.specifiesRequestObject());
	}
	
	
	public void testBuilder_requestURI_coreTopLevelParams() {
		
		URI requestURI = URI.create("urn:requests:ahy4ohgo");
		ResponseType rt = new ResponseType("code");
		ClientID clientID = new ClientID("123");
		
		AuthorizationRequest ar = new AuthorizationRequest.Builder(requestURI, clientID)
			.responseType(rt)
			.build();
		
		assertEquals(requestURI, ar.getRequestURI());
		assertEquals(rt, ar.getResponseType());
		assertEquals(clientID, ar.getClientID());
		
		try {
			new AuthorizationRequest.Builder(requestURI, clientID).responseType(null);
			fail("Core response_type when set not null");
		} catch (IllegalArgumentException e) {
			assertEquals("The response type must not be null", e.getMessage());
		}
	}
	
	
	public void testJAR_requestURI_requiredTopLevelParams()
		throws ParseException {
		
		URI endpointURI = URI.create("https://c2id.com/login");
		ResponseType rt = new ResponseType("code");
		ClientID clientID = new ClientID("123");
		URI requestURI = URI.create("urn:requests:ahy4ohgo");
		
		AuthorizationRequest ar = new AuthorizationRequest.Builder(rt, clientID)
			.requestURI(requestURI)
			.endpointURI(endpointURI)
			.build();
		
		assertEquals(rt, ar.getResponseType());
		assertEquals(clientID, ar.getClientID());
		assertNull(ar.getRedirectionURI());
		assertNull(ar.getScope());
		assertNull(ar.getState());
		assertNull(ar.getResponseMode());
		assertEquals(ResponseMode.QUERY, ar.impliedResponseMode());
		assertNull(ar.getResources());
		assertFalse(ar.includeGrantedScopes());
		assertNull(ar.getCustomParameter("custom-param"));
		assertTrue(ar.getCustomParameters().isEmpty());
		
		assertEquals(endpointURI, ar.getEndpointURI());
		assertEquals(requestURI, ar.getRequestURI());
		assertNull(ar.getRequestObject());
		assertTrue(ar.specifiesRequestObject());
		
		ar = AuthorizationRequest.parse(ar.toURI());
		
		assertEquals(rt, ar.getResponseType());
		assertEquals(clientID, ar.getClientID());
		assertNull(ar.getRedirectionURI());
		assertNull(ar.getScope());
		assertNull(ar.getState());
		assertNull(ar.getResponseMode());
		assertEquals(ResponseMode.QUERY, ar.impliedResponseMode());
		assertNull(ar.getResources());
		assertFalse(ar.includeGrantedScopes());
		assertNull(ar.getCustomParameter("custom-param"));
		assertTrue(ar.getCustomParameters().isEmpty());
		
		assertEquals(endpointURI, ar.getEndpointURI());
		assertEquals(requestURI, ar.getRequestURI());
		assertNull(ar.getRequestObject());
		assertTrue(ar.specifiesRequestObject());
	}
	
	
	public void testJAR_requestObject_minimal()
		throws ParseException {
		
		URI endpointURI = URI.create("https://c2id.com/login");
		ResponseType rt = new ResponseType("code");
		ClientID clientID = new ClientID("123");
		
		AuthorizationRequest jar = new AuthorizationRequest.Builder(rt, clientID)
			.build();
		
		JWTClaimsSet jwtClaimsSet = jar.toJWTClaimsSet();
		
		JWT requestObject = new PlainJWT(jwtClaimsSet);
		
		AuthorizationRequest ar = new AuthorizationRequest.Builder(requestObject, clientID)
			.endpointURI(endpointURI)
			.build();
		
		assertNull(ar.getResponseType());
		assertEquals(clientID, ar.getClientID());
		assertNull(ar.getRedirectionURI());
		assertNull(ar.getScope());
		assertNull(ar.getState());
		assertNull(ar.getResponseMode());
		assertEquals(ResponseMode.QUERY, ar.impliedResponseMode());
		assertNull(ar.getResources());
		assertFalse(ar.includeGrantedScopes());
		assertNull(ar.getCustomParameter("custom-param"));
		assertTrue(ar.getCustomParameters().isEmpty());
		
		assertEquals(endpointURI, ar.getEndpointURI());
		assertNull(ar.getRequestURI());
		assertEquals(requestObject, ar.getRequestObject());
		assertTrue(ar.specifiesRequestObject());
		
		assertEquals(Collections.singletonList(requestObject.serialize()), ar.toParameters().get("request"));
		assertEquals(Collections.singletonList(clientID.getValue()), ar.toParameters().get("client_id"));
		assertEquals(2, ar.toParameters().size());
		
		ar = AuthorizationRequest.parse(ar.toURI());
		
		assertNull(ar.getResponseType());
		assertEquals(clientID, ar.getClientID());
		assertNull(ar.getRedirectionURI());
		assertNull(ar.getScope());
		assertNull(ar.getState());
		assertNull(ar.getResponseMode());
		assertEquals(ResponseMode.QUERY, ar.impliedResponseMode());
		assertNull(ar.getResources());
		assertFalse(ar.includeGrantedScopes());
		assertNull(ar.getCustomParameter("custom-param"));
		assertTrue(ar.getCustomParameters().isEmpty());
		
		assertEquals(endpointURI, ar.getEndpointURI());
		assertNull(ar.getRequestURI());
		assertEquals(requestObject.serialize(), ar.getRequestObject().serialize());
		assertTrue(ar.specifiesRequestObject());
	}
	
	
	// docs example
	public void testJAR_requestObject_example()
		throws Exception {
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.keyIDFromThumbprint(true)
			.keyUse(KeyUse.SIGNATURE)
			.generate();
		
		URI endpointURI = URI.create("https://c2id.com/login");
		ResponseType rt = new ResponseType("code");
		ClientID clientID = new ClientID("123");
		URI redirectURI = new URI("https://example.com");
		Scope scope = new Scope("read", "write");
		State state = new State("81c33d57-59c7-4b41-9a15-80e2ed1482e2");
		
		SignedJWT jar = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.keyID(rsaJWK.getKeyID())
				.build(),
			new AuthorizationRequest.Builder(rt, clientID)
				.redirectionURI(redirectURI)
				.scope(scope)
				.state(state)
				.build()
				.toJWTClaimsSet()
		);
		
		jar.sign(new RSASSASigner(rsaJWK));
		
		AuthorizationRequest ar = new AuthorizationRequest.Builder(jar, clientID)
			.endpointURI(endpointURI)
			.build();
	}
	
	
	public void testJAR_requestObject_requiredTopLevelParams()
		throws ParseException {
		
		URI endpointURI = URI.create("https://c2id.com/login");
		ResponseType rt = new ResponseType("code");
		ClientID clientID = new ClientID("123");
		
		AuthorizationRequest jar = new AuthorizationRequest.Builder(rt, clientID)
			.build();
		
		JWTClaimsSet jwtClaimsSet = jar.toJWTClaimsSet();
		
		JWT requestObject = new PlainJWT(jwtClaimsSet);
		
		AuthorizationRequest ar = new AuthorizationRequest.Builder(rt, clientID)
			.requestObject(requestObject)
			.endpointURI(endpointURI)
			.build();
		
		assertEquals(rt, ar.getResponseType());
		assertEquals(clientID, ar.getClientID());
		assertNull(ar.getRedirectionURI());
		assertNull(ar.getScope());
		assertNull(ar.getState());
		assertNull(ar.getResponseMode());
		assertEquals(ResponseMode.QUERY, ar.impliedResponseMode());
		assertNull(ar.getResources());
		assertFalse(ar.includeGrantedScopes());
		assertNull(ar.getCustomParameter("custom-param"));
		assertTrue(ar.getCustomParameters().isEmpty());
		
		assertEquals(endpointURI, ar.getEndpointURI());
		assertNull(ar.getRequestURI());
		assertEquals(requestObject, ar.getRequestObject());
		assertTrue(ar.specifiesRequestObject());
		
		ar = AuthorizationRequest.parse(ar.toURI());
		
		assertEquals(rt, ar.getResponseType());
		assertEquals(clientID, ar.getClientID());
		assertNull(ar.getRedirectionURI());
		assertNull(ar.getScope());
		assertNull(ar.getState());
		assertNull(ar.getResponseMode());
		assertEquals(ResponseMode.QUERY, ar.impliedResponseMode());
		assertNull(ar.getResources());
		assertFalse(ar.includeGrantedScopes());
		assertNull(ar.getCustomParameter("custom-param"));
		assertTrue(ar.getCustomParameters().isEmpty());
		
		assertEquals(endpointURI, ar.getEndpointURI());
		assertNull(ar.getRequestURI());
		assertEquals(requestObject.serialize(), ar.getRequestObject().serialize());
		assertTrue(ar.specifiesRequestObject());
	}
	
	
	// https://tools.ietf.org/html/draft-ietf-oauth-jwsreq-29#section-10.8
	public void testJAR_requestObject_construct_rejectWithSubjectClaimsEqualsClientID()
		throws JOSEException {
		
		URI endpointURI = URI.create("https://c2id.com/login");
		ResponseType rt = new ResponseType("code");
		ClientID clientID = new ClientID("123");
		
		AuthorizationRequest jar = new AuthorizationRequest.Builder(rt, clientID)
			.build();
		
		JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder(jar.toJWTClaimsSet())
			.subject(clientID.getValue())
			.build();
		
		SignedJWT requestObject = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), jwtClaimsSet);
		requestObject.sign(new MACSigner(new OctetSequenceKeyGenerator(256).generate()));
		
		try {
			new AuthorizationRequest.Builder(rt, clientID)
				.requestObject(requestObject)
				.endpointURI(endpointURI)
				.build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Illegal request parameter: The JWT sub (subject) claim must not equal the client_id", e.getMessage());
			assertTrue(e.getCause() instanceof IllegalArgumentException);
			assertEquals("Illegal request parameter: The JWT sub (subject) claim must not equal the client_id", e.getCause().getMessage());
		}
	}
	
	
	// https://tools.ietf.org/html/draft-ietf-oauth-jwsreq-29#section-10.8
	public void testJAR_requestObject_parse_rejectWithSubjectClaimsEqualsClientID()
		throws JOSEException {
		
		URI endpointURI = URI.create("https://c2id.com/login");
		ResponseType rt = new ResponseType("code");
		ClientID clientID = new ClientID("123");
		
		JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
			.subject(clientID.getValue()) // illegal
			.claim("client_id", clientID.getValue())
			.claim("response_type", rt.toString())
			.build();
		
		SignedJWT requestObject = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), jwtClaimsSet);
		requestObject.sign(new MACSigner(new OctetSequenceKeyGenerator(256).generate()));
		
		URI request = URI.create(endpointURI + "?client_id=" + clientID + "&request=" + requestObject.serialize());
		
		try {
			AuthorizationRequest.parse(request);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid request parameter: The JWT sub (subject) claim must not equal the client_id", e.getMessage());
			assertEquals(clientID, e.getClientID());
		}
	}
	
	
	public void testBuilder_nullRequestObject_clientID() {
		
		try {
			new AuthorizationRequest.Builder((JWT)null, new ClientID("123"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The request object must not be null", e.getMessage());
		}
	}
	
	
	public void testBuilder_requestObject_nullClientID() throws java.text.ParseException {
		
		try {
			new AuthorizationRequest.Builder(PlainJWT.parse("eyJhbGciOiJub25lIn0.eyJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6IjEyMyJ9."), null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The client ID must not be null", e.getMessage());
		}
	}
	
	
	public void testBuilder_nullRequestURI_clientID() {
		
		try {
			new AuthorizationRequest.Builder((URI)null, new ClientID("123"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The request URI must not be null", e.getMessage());
		}
	}
	
	
	public void testBuilder_requestURI_nullClientID() {
		
		try {
			new AuthorizationRequest.Builder(URI.create("urn:requests:ahy4ohgo"), null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The client ID must not be null", e.getMessage());
		}
	}
	
	
	public void testBuilder_copyConstructor_requestObject() {
		
		URI endpointURI = URI.create("https://c2id.com/login");
		ResponseType rt = new ResponseType("code");
		ClientID clientID = new ClientID("123");
		
		AuthorizationRequest jar = new AuthorizationRequest.Builder(rt, clientID)
			.build();
		
		JWTClaimsSet jwtClaimsSet = jar.toJWTClaimsSet();
		
		JWT requestObject = new PlainJWT(jwtClaimsSet);
		
		AuthorizationRequest ar = new AuthorizationRequest.Builder(requestObject, clientID)
			.endpointURI(endpointURI)
			.build();
		
		ar = new AuthorizationRequest.Builder(ar)
			.build();
		
		assertNull(ar.getResponseType());
		assertEquals(clientID, ar.getClientID());
		assertNull(ar.getRedirectionURI());
		assertNull(ar.getScope());
		assertNull(ar.getState());
		assertNull(ar.getResponseMode());
		assertEquals(ResponseMode.QUERY, ar.impliedResponseMode());
		assertNull(ar.getResources());
		assertFalse(ar.includeGrantedScopes());
		assertNull(ar.getCustomParameter("custom-param"));
		assertTrue(ar.getCustomParameters().isEmpty());
		
		assertEquals(endpointURI, ar.getEndpointURI());
		assertNull(ar.getRequestURI());
		assertEquals(requestObject, ar.getRequestObject());
		assertTrue(ar.specifiesRequestObject());
	}
	
	
	public void testBuilder_copyConstructor_requestURI() {
		
		URI endpointURI = URI.create("https://c2id.com/login");
		ResponseType rt = new ResponseType("code");
		ClientID clientID = new ClientID("123");
		URI requestURI = URI.create("urn:requests:ahy4ohgo");
		
		AuthorizationRequest ar = new AuthorizationRequest.Builder(rt, clientID)
			.requestURI(requestURI)
			.endpointURI(endpointURI)
			.build();
		
		ar = new AuthorizationRequest.Builder(ar)
			.build();
		
		assertEquals(rt, ar.getResponseType());
		assertEquals(clientID, ar.getClientID());
		assertNull(ar.getRedirectionURI());
		assertNull(ar.getScope());
		assertNull(ar.getState());
		assertNull(ar.getResponseMode());
		assertEquals(ResponseMode.QUERY, ar.impliedResponseMode());
		assertNull(ar.getResources());
		assertFalse(ar.includeGrantedScopes());
		assertNull(ar.getCustomParameter("custom-param"));
		assertTrue(ar.getCustomParameters().isEmpty());
		
		assertEquals(endpointURI, ar.getEndpointURI());
		assertEquals(requestURI, ar.getRequestURI());
		assertNull(ar.getRequestObject());
		assertTrue(ar.specifiesRequestObject());
	}
	
	
	public void testBuilder_reject_requestObjectWithRequestURI() {
		
		URI endpointURI = URI.create("https://c2id.com/login");
		ResponseType rt = new ResponseType("code");
		ClientID clientID = new ClientID("123");
		
		AuthorizationRequest jar = new AuthorizationRequest.Builder(rt, clientID)
			.build();
		
		JWTClaimsSet jwtClaimsSet = jar.toJWTClaimsSet();
		
		JWT requestObject = new PlainJWT(jwtClaimsSet);
		
		try {
			new AuthorizationRequest.Builder(requestObject, clientID)
				.endpointURI(endpointURI)
				.requestURI(URI.create("urn:requests:uogo3ora"))
				.build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Either a request object or a request URI must be specified, but not both", e.getMessage());
			assertTrue(e.getCause() instanceof IllegalArgumentException);
			assertEquals("Either a request object or a request URI must be specified, but not both", e.getCause().getMessage());
		}
	}
	
	
	public void test_toJWTClaimsSet_rejectIfNestedRequestObject() {
		
		URI endpointURI = URI.create("https://c2id.com/login");
		ResponseType rt = new ResponseType("code");
		ClientID clientID = new ClientID("123");
		
		AuthorizationRequest jar = new AuthorizationRequest.Builder(rt, clientID)
			.build();
		
		JWTClaimsSet jwtClaimsSet = jar.toJWTClaimsSet();
		
		JWT requestObject = new PlainJWT(jwtClaimsSet);
		
		AuthorizationRequest ar = new AuthorizationRequest.Builder(requestObject, clientID)
			.endpointURI(endpointURI)
			.build();
		
		try {
			ar.toJWTClaimsSet();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Cannot create nested JWT secured authorization request", e.getMessage());
		}
	}
	
	
	public void test_toJWTClaimsSet_rejectIfNestedRequestURI() {
		
		URI endpointURI = URI.create("https://c2id.com/login");
		URI requestURI = URI.create("urn:requests:uogo3ora");
		ClientID clientID = new ClientID("123");
		
		AuthorizationRequest ar = new AuthorizationRequest.Builder(requestURI, clientID)
			.endpointURI(endpointURI)
			.build();
		
		try {
			ar.toJWTClaimsSet();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Cannot create nested JWT secured authorization request", e.getMessage());
		}
	}
	
	
	public void testParseRequestURI_missingClientID() {
		
		try {
			AuthorizationRequest.parse(URI.create("https://c2id.com/login?request_uri=https%3A%2F%2Fexample.org%2Frequest.jwt"));
			fail();
		} catch (ParseException e) {
			assertEquals("Missing client_id parameter", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		}
	}
	
	
	public void testParseInvalidRequestURI() {
		
		try {
			AuthorizationRequest.parse(URI.create("https://c2id.com/login?request_uri=%3A&client_id=123"));
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid request_uri parameter: Expected scheme name at index 0: :", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		}
	}
	
	
	public void testParseRequestObject_missingClientID() {
		
		try {
			AuthorizationRequest.parse(URI.create("https://c2id.com/login?request=eyJhbGciOiJub25lIn0.eyJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6IjEyMyJ9."));
			fail();
		} catch (ParseException e) {
			assertEquals("Missing client_id parameter", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		}
	}
	
	
	public void testParseInvalidRequestObject() {
		
		try {
			AuthorizationRequest.parse(URI.create("https://c2id.com/login?request=abc&client_id=123"));
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid request parameter: Invalid JWT serialization: Missing dot delimiter(s)", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		}
	}
	
	
	public void testParseInvalidRequestURI_redirectionInfo() {
		
		ResponseType rt = new ResponseType("code");
		ClientID clientID = new ClientID("123");
		URI redirectionURI = URI.create("https://example.com/cb");
		State state = new State();
		
		Map<String,List<String>> params = new AuthorizationRequest.Builder(rt, clientID)
			.redirectionURI(redirectionURI)
			.state(state)
			.build()
			.toParameters();
		params.put("request_uri", Collections.singletonList(":"));
		
		try {
			AuthorizationRequest.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid request_uri parameter: Expected scheme name at index 0: :", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
			assertEquals("Invalid request: Invalid request_uri parameter: Expected scheme name at index 0: :", e.getErrorObject().getDescription());
			assertEquals(clientID, e.getClientID());
			assertEquals(redirectionURI, e.getRedirectionURI());
			assertEquals(state, e.getState());
		}
	}
	
	
	public void testParseInvalidRequestObject_redirectionInfo() {
		
		ResponseType rt = new ResponseType("code");
		ClientID clientID = new ClientID("123");
		URI redirectionURI = URI.create("https://example.com/cb");
		State state = new State();
		
		Map<String,List<String>> params = new AuthorizationRequest.Builder(rt, clientID)
			.redirectionURI(redirectionURI)
			.state(state)
			.build()
			.toParameters();
		params.put("request", Collections.singletonList("abc"));
		
		try {
			AuthorizationRequest.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid request parameter: Invalid JWT serialization: Missing dot delimiter(s)", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
			assertEquals("Invalid request: Invalid request parameter: Invalid JWT serialization: Missing dot delimiter(s)", e.getErrorObject().getDescription());
			assertEquals(clientID, e.getClientID());
			assertEquals(redirectionURI, e.getRedirectionURI());
			assertEquals(state, e.getState());
		}
	}
	
	
	public void testParse_missingResponseType() {
		
		ResponseType rt = new ResponseType("code");
		ClientID clientID = new ClientID("123");
		URI redirectionURI = URI.create("https://example.com/cb");
		State state = new State();
		
		Map<String,List<String>> params = new AuthorizationRequest.Builder(rt, clientID)
			.redirectionURI(redirectionURI)
			.state(state)
			.build()
			.toParameters();
		params.remove("response_type");
		
		try {
			AuthorizationRequest.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing response_type parameter", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
			assertEquals("Invalid request: Missing response_type parameter", e.getErrorObject().getDescription());
			assertEquals(clientID, e.getClientID());
			assertEquals(redirectionURI, e.getRedirectionURI());
			assertEquals("implied", ResponseMode.QUERY, e.getResponseMode());
			assertEquals(e.getState(), e.getState());
		}
	}
	
	
	public void testParse_missingClientID() {
		
		ResponseType rt = new ResponseType("code");
		ClientID clientID = new ClientID("123");
		
		Map<String,List<String>> params = new AuthorizationRequest.Builder(rt, clientID)
			.build()
			.toParameters();
		params.remove("client_id");
		
		try {
			AuthorizationRequest.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing client_id parameter", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
			assertEquals("Invalid request: Missing client_id parameter", e.getErrorObject().getDescription());
			assertNull(e.getClientID());
			assertNull(e.getRedirectionURI());
			assertNull(e.getResponseMode());
			assertNull(e.getState());
		}
	}
	
	
	public void testParse_missingClientID_redirectionInfoIgnored() {
		
		ResponseType rt = new ResponseType("code");
		ClientID clientID = new ClientID("123");
		URI redirectionURI = URI.create("https://example.com/cb");
		State state = new State();
		
		Map<String,List<String>> params = new AuthorizationRequest.Builder(rt, clientID)
			.redirectionURI(redirectionURI)
			.state(state)
			.build()
			.toParameters();
		params.remove("client_id");
		
		try {
			AuthorizationRequest.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing client_id parameter", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
			assertEquals("Invalid request: Missing client_id parameter", e.getErrorObject().getDescription());
			assertNull(e.getClientID());
			assertNull(e.getRedirectionURI());
			assertNull(e.getResponseMode());
			assertNull(e.getState());
		}
	}
	
	
	public void testParseWithIllegalRequestObject() {
		
		URI uri = URI.create("https://example.com/webAuthorize?redirect_uri=//example.io&request=n&client_id=123");
		
		try {
			AuthorizationRequest.parse(uri);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid request parameter: Invalid JWT serialization: Missing dot delimiter(s)", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Invalid request parameter: Invalid JWT serialization: Missing dot delimiter(s)", e.getErrorObject().getDescription());
			assertEquals(URI.create("//example.io"), e.getRedirectionURI());
			assertNull(e.getState());
			assertEquals(new ClientID("123"), e.getClientID());
		}
	}
	
	
	// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/345/token-and-authz-request-must-fail-with-400
	public void testParse_repeatedParameter_clientID()
		throws URISyntaxException {
		
		URI uri = new URI("https://c2id.com/authz/");
		
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);
		
		ClientID clientID = new ClientID("123456");
		
		AuthorizationRequest req = new AuthorizationRequest(uri, rts, clientID);
		
		Map<String,List<String>> params = req.toParameters();
		params.put("client_id", Arrays.asList(clientID.getValue(), clientID.getValue()));
		
		try {
			AuthorizationRequest.parse(uri, params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Parameter(s) present more than once: [client_id]", e.getErrorObject().getDescription());
		}
	}
}
