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


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.client.RedirectURIValidator;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.rar.Action;
import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail;
import com.nimbusds.oauth2.sdk.rar.AuthorizationType;
import com.nimbusds.oauth2.sdk.rar.Location;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementClaimsSet;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChainTest;
import junit.framework.TestCase;
import net.minidev.json.JSONArray;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.*;


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
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("authorization_details"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("resource"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("include_granted_scopes"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("request"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("request_uri"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("prompt"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("dpop_jkt"));
		assertTrue(AuthorizationRequest.getRegisteredParameterNames().contains("trust_chain"));
		assertEquals(16, AuthorizationRequest.getRegisteredParameterNames().size());
	}
	
	
	public void testMinimal()
		throws Exception {
		
		URI uri = new URI("https://c2id.com/authz/");

		ResponseType rts = ResponseType.CODE;

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

		assertNull(req.getAuthorizationDetails());

		assertNull(req.getResources());
		
		assertFalse(req.includeGrantedScopes());
		
		assertNull(req.getTrustChain());

		assertNull(req.getCustomParameter("custom-param"));
		assertTrue(req.getCustomParameters().isEmpty());

		String query = req.toQueryString();

		Map<String,List<String>> params = URLUtils.parseParameters(query);
		assertEquals(Collections.singletonList("code"), params.get("response_type"));
		assertEquals(Collections.singletonList("123456"), params.get("client_id"));
		assertEquals(2, params.size());

		HTTPRequest httpReq = req.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpReq.getMethod());
		assertTrue(httpReq.getURL().toString().startsWith(uri.toString()));
		assertEquals(params, httpReq.getQueryStringParameters());

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
		assertNull(req.getAuthorizationDetails());
		assertNull(req.getResources());
		assertFalse(req.includeGrantedScopes());
		assertNull(req.getTrustChain());

		assertNull(req.getCustomParameter("custom-param"));
		assertTrue(req.getCustomParameters().isEmpty());
	}


	public void testMinimalAltParse()
		throws Exception {

		URI uri = new URI("https://c2id.com/authz/");

		ResponseType rts = ResponseType.CODE;

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
		assertNull(req.getAuthorizationDetails());
		assertNull(req.getResources());
		assertFalse(req.includeGrantedScopes());
		assertNull(req.getTrustChain());
		assertNull(req.getCustomParameter("custom-param"));
		assertTrue(req.getCustomParameters().isEmpty());
	}


	public void testToRequestURIWithParse()
		throws Exception {

		URI redirectURI = new URI("https://client.com/cb");
		ResponseType rts = ResponseType.CODE;
		ClientID clientID = new ClientID("123456");
		URI endpointURI = new URI("https://c2id.com/login");

		AuthorizationRequest req = new AuthorizationRequest.Builder(rts, clientID).
			redirectionURI(redirectURI).
			endpointURI(endpointURI).
			build();

		URI requestURI = req.toURI();

		assertTrue(requestURI.toString().startsWith(endpointURI + "?"));
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

		ResponseType rts = ResponseType.CODE;

		ResponseMode rm = ResponseMode.FORM_POST;

		ClientID clientID = new ClientID("123456");

		URI redirectURI = new URI("https://example.com/oauth2/");

		Scope scope = Scope.parse("read write");

		State state = new State();

		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.S256;
		CodeChallenge codeChallenge = CodeChallenge.compute(codeChallengeMethod, codeVerifier);

		AuthorizationDetail detail_1 = new AuthorizationDetail.Builder(new AuthorizationType("api_1")).build();
		AuthorizationDetail detail_2 = new AuthorizationDetail.Builder(new AuthorizationType("api_2")).build();
		List<AuthorizationDetail> authorizationDetails = Arrays.asList(detail_1, detail_2);

		List<URI> resources = Arrays.asList(URI.create("https://rs1.com"), URI.create("https://rs2.com"));
		
		Prompt prompt = new Prompt(Prompt.Type.LOGIN);
		
		JWKThumbprintConfirmation dpopJKT = new JWKThumbprintConfirmation(new Base64URL("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"));

		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("x", Collections.singletonList("100"));
		customParams.put("y", Collections.singletonList("200"));
		customParams.put("z", Collections.singletonList("300"));


		AuthorizationRequest req = new AuthorizationRequest(
			uri, rts, rm, clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod,
			authorizationDetails, resources, true,
			null, null, prompt, dpopJKT, null, customParams);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(rts, req.getResponseType());
		assertEquals(rm, req.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, req.impliedResponseMode());
		assertEquals(clientID, req.getClientID());
		assertEquals(redirectURI, req.getRedirectionURI());
		assertEquals(scope, req.getScope());
		assertEquals(state, req.getState());
		assertEquals(authorizationDetails, req.getAuthorizationDetails());
		assertEquals(resources, req.getResources());
		assertEquals(prompt, req.getPrompt());
		assertEquals(dpopJKT, req.getDPoPJWKThumbprintConfirmation());

		String query = req.toQueryString();

		Map<String,List<String>> params = URLUtils.parseParameters(query);

		assertEquals(Collections.singletonList("code"), params.get("response_type"));
		assertEquals(Collections.singletonList("form_post"), params.get("response_mode"));
		assertEquals(Collections.singletonList("123456"), params.get("client_id"));
		assertEquals(Collections.singletonList(redirectURI.toString()), params.get("redirect_uri"));
		assertEquals(Collections.singletonList(scope.toString()), params.get("scope"));
		assertEquals(Collections.singletonList(state.getValue()), params.get("state"));
		assertEquals(Collections.singletonList(codeChallenge.getValue()), params.get("code_challenge"));
		assertEquals(Collections.singletonList(codeChallengeMethod.getValue()), params.get("code_challenge_method"));
		assertEquals(Collections.singletonList(AuthorizationDetail.toJSONString(authorizationDetails)), params.get("authorization_details"));
		assertEquals(Arrays.asList("https://rs1.com", "https://rs2.com"), params.get("resource"));
		assertEquals(Collections.singletonList(prompt.toString()), params.get("prompt"));
		assertEquals(Collections.singletonList(dpopJKT.getValue().toString()), params.get("dpop_jkt"));
		assertEquals(Collections.singletonList("true"), params.get("include_granted_scopes"));
		assertEquals(Collections.singletonList("100"), params.get("x"));
		assertEquals(Collections.singletonList("200"), params.get("y"));
		assertEquals(Collections.singletonList("300"), params.get("z"));
		assertEquals(16, params.size());

		HTTPRequest httpReq = req.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpReq.getMethod());
		assertEquals(params, httpReq.getQueryStringParameters());

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
		assertEquals(authorizationDetails, req.getAuthorizationDetails());
		assertEquals(resources, req.getResources());
		assertTrue(req.includeGrantedScopes());
		assertEquals(prompt, req.getPrompt());
		assertEquals(dpopJKT, req.getDPoPJWKThumbprintConfirmation());
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

		AuthorizationRequest req = new AuthorizationRequest(uri, rts, null, clientID, redirectURI, scope, state, codeChallenge, null, resources, false, null, null, null, null, null);

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
		assertNull(req.getDPoPJWKThumbprintConfirmation());

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
		assertNull(req.getDPoPJWKThumbprintConfirmation());
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
		assertNull(request.getAuthorizationDetails());
		assertNull(request.getResources());
		assertFalse(request.includeGrantedScopes());
		assertNull(request.getPrompt());
		assertNull(request.getDPoPJWKThumbprintConfirmation());
		assertNull(request.getTrustChain());
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
		assertNull(request.getAuthorizationDetails());
		assertNull(request.getResources());
		assertFalse(request.includeGrantedScopes());
		assertNull(request.getPrompt());
		assertNull(request.getDPoPJWKThumbprintConfirmation());
		assertNull(request.getTrustChain());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testBuilderMinimalNullCodeChallenge() {

		AuthorizationRequest request = new AuthorizationRequest.Builder(ResponseType.TOKEN, new ClientID("123"))
			.codeChallenge((CodeVerifier) null, null)
			.build();
		
		assertEquals(ResponseType.TOKEN, request.getResponseType());
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
		assertNull(request.getTrustChain());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testBuilderMinimalNullCodeChallenge_deprecated() {

		AuthorizationRequest request = new AuthorizationRequest.Builder(ResponseType.TOKEN, new ClientID("123"))
			.codeChallenge((CodeChallenge) null, null)
			.build();
		
		assertEquals(ResponseType.TOKEN, request.getResponseType());
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
		assertNull(request.getTrustChain());
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
			.authorizationDetails(Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("api_1")).build()))
			.resources(URI.create("https://rs1.com"), URI.create("https://rs2.com"))
			.includeGrantedScopes(true)
			.prompt(new Prompt(Prompt.Type.LOGIN))
			.dPoPJWKThumbprintConfirmation(new JWKThumbprintConfirmation(new Base64URL("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")))
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
		assertEquals(Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("api_1")).build()), request.getAuthorizationDetails());
		assertEquals(Arrays.asList(URI.create("https://rs1.com"), URI.create("https://rs2.com")), request.getResources());
		assertTrue(request.includeGrantedScopes());
		assertEquals(new Prompt(Prompt.Type.LOGIN), request.getPrompt());
		assertEquals(new JWKThumbprintConfirmation(new Base64URL("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")), request.getDPoPJWKThumbprintConfirmation());
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
	
	
	public void testBuilderPromptTypesVarArg() {
		
		ClientID clientID = new ClientID("123");
		
		// One prompt value
		AuthorizationRequest request = new AuthorizationRequest.Builder(
			ResponseType.CODE,
			clientID)
			.prompt(Prompt.Type.LOGIN)
			.build();
		
		assertEquals(ResponseType.CODE, request.getResponseType());
		assertEquals(clientID, request.getClientID());
		assertEquals(new Prompt(Prompt.Type.LOGIN), request.getPrompt());
		assertEquals(3, request.toParameters().size());
		
		// Two prompt values
		request = new AuthorizationRequest.Builder(
			ResponseType.CODE,
			clientID)
			.prompt(Prompt.Type.LOGIN, Prompt.Type.CONSENT)
			.build();
		
		assertEquals(ResponseType.CODE, request.getResponseType());
		assertEquals(clientID, request.getClientID());
		assertEquals(new Prompt(Prompt.Type.LOGIN, Prompt.Type.CONSENT), request.getPrompt());
		assertEquals(3, request.toParameters().size());
		
		// Empty prompt
		request = new AuthorizationRequest.Builder(
			ResponseType.CODE,
			clientID)
			.prompt(new Prompt.Type[0])
			.build();
		
		assertEquals(ResponseType.CODE, request.getResponseType());
		assertEquals(clientID, request.getClientID());
		assertTrue(request.getPrompt().isEmpty());
		assertEquals(3, request.toParameters().size());
		
		// Null prompt
		request = new AuthorizationRequest.Builder(
			ResponseType.CODE,
			clientID)
			.prompt((Prompt.Type) null)
			.build();
		
		assertEquals(ResponseType.CODE, request.getResponseType());
		assertEquals(clientID, request.getClientID());
		assertNull(request.getPrompt());
		assertEquals(2, request.toParameters().size());
	}
	
	
	// OIDC Federation 1.0
	static TrustChain createSampleTrustChain() throws JOSEException {
		
		EntityStatementClaimsSet leafClaims = TrustChainTest.createOPSelfStatementClaimsSet(TrustChainTest.ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, TrustChainTest.OP_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutLeaf = TrustChainTest.createOPStatementClaimsSet(new Issuer(TrustChainTest.ANCHOR_ENTITY_ID.getValue()), TrustChainTest.ANCHOR_ENTITY_ID);
		EntityStatement anchorStmtAboutLeaf = EntityStatement.sign(anchorClaimsAboutLeaf, TrustChainTest.ANCHOR_RSA_JWK);
		
		List<EntityStatement> superiorStatements = Collections.singletonList(anchorStmtAboutLeaf);
		return new TrustChain(leafStmt, superiorStatements);
	}
	
	
	public void testBuilder_trustChain() throws Exception {
		
		TrustChain trustChain = createSampleTrustChain();
		
		AuthorizationRequest request = new AuthorizationRequest.Builder(ResponseType.CODE, new ClientID("123"))
			.endpointURI(URI.create("https://c2id.com/login"))
			.trustChain(trustChain)
			.build();
		
		assertEquals(ResponseType.CODE, request.getResponseType());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals(trustChain.toSerializedJWTs(), request.getTrustChain().toSerializedJWTs());
		
		Map<String, List<String>> params = request.toParameters();
		
		assertEquals(Collections.singletonList(ResponseType.CODE.toString()), params.get("response_type"));
		assertEquals(Collections.singletonList(new ClientID("123").getValue()), params.get("client_id"));
		
		JSONArray trustChainArray = new JSONArray();
		trustChainArray.addAll(trustChain.toSerializedJWTs());
		assertEquals(Collections.singletonList(trustChainArray.toJSONString()), params.get("trust_chain"));
		
		assertEquals(3, params.size());
		
		request = AuthorizationRequest.parse(request.toURI());
		
		assertEquals(ResponseType.CODE, request.getResponseType());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals(trustChain.toSerializedJWTs(), request.getTrustChain().toSerializedJWTs());
		
		assertEquals(3, request.toParameters().size());
	}
	
	
	public void testParse_trustChainParseException() {
		
		AuthorizationRequest request = new AuthorizationRequest.Builder(ResponseType.CODE, new ClientID("123"))
			.endpointURI(URI.create("https://c2id.com/login"))
			.build();
		
		Map<String, List<String>> params = request.toParameters();
		
		params.put("trust_chain", Collections.singletonList("[\"abc\"]"));
		
		try {
			AuthorizationRequest.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JWT in trust chain: Invalid serialized unsecured/JWS/JWE object: Missing part delimiters", e.getMessage());
		}
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
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Illegal redirect_uri parameter", e.getErrorObject().getDescription());
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testParseExceptionInvalidRedirectionURI_2()
		throws Exception {

		URI requestURI = new URI("https://server.example.com/authorize?client_id=1c97efd4-f030-481b-b7f3-ec4b31c80e0c&redirect_uri=/%09/example.com&response_type=code&prompt=login&scope=openid%20profile&code_challenge=iXlrYp9McDDeIk9aofZLhBiijK-rqhvLZweb3HM_EL4&code_challenge_method=S256&response_mode=form_post&nonce=638417822591109740.NTRlMWRjMDctMTNlOS00MzcwLWJmZjQtYWIwMDVlZmI3YmYyYTZhMDRiNGEtOWUzMS00NDhiLWE0NzUtMWE4NzYxY2UwMWRi&state=CfDJ8Kmwd5vY0CdJhsRp3a9AbJOkGVa8w7aa2mfTmL6oYD4LhR3hMah8OF4S0LqHXTXLgdVDjCqxzFaSTnbbqi3eo0EeI9jF7z3mooH_ysw3YduMy96caH05GCDX1Qp55WSm6Q5bbkS3JNRwcIi4N1cherGtI2IkIDRYfYd6NMx0fxY9rSD38tgl2-gzD-jaNeF5Sdj1-XwY60CU4pJGvOghWeq6VxKCC78NL3GCti8YWh3QlZXXcK3Q2tqlosBqWmDJmoGWE_JNTwHkGAE7wvplOFAD8CWbo79_XJUVNixqxz1KZmFFzN_avEqKqGzyv__gFjY3MdXQGif5TcxH9lNupYdlQQyPcyh0HdqwYOwQEqZqKwEP7zpGwnZvPp-SzTBXTTf4W3Su75u82eyHHl1qFHUEELWAZXVV1Fv6tCTlrqwGtxiqCqRNk8-dZxRXqr3pB50asXURcB_OrWCQzRkOtrOISYomIuGFjUIUzJNfk_5f5xrL9LVwoK7VTSGcm62CsSknzMm6_h9W7ega7ZKe3H2BqnFW6uqQB7f3LsrNwSmh2fweLo4kOdpDBtegNSNy1lg_ej6pz1jwwArSjdYYtefYRHny8pwcnGenyxUwt410SEE4KYsVhXELItInhSKuQBmIZ0y-hMZtoKpnw9_8h5PEuxqTjyS3HvIzIjLvcOr8ZuETLupLMTNgGzT2ubKzmfEVOuWOaBxdjAaHgRedAwAL8HVINQcZ7nsnnjVRDZDREtTLxU2-T0LDt-SEInWNwHw-mLC5NrUM5kdnSPwPhr-XfhoQ0GiwaWDa14U1yE2uIpPFX7b4M8LEWE6xavcRFIrGzGJeFRwYNnMai5iNHkPsls4P34hAIfp0su7dJbGbYKqNz7lGq7vON_i-JO_efqsJvYDW2SYoIRrwpUJRVQJFqp-tpx263R0x5zfQcCWl2aUnYq2VUua5jrWHTv73997GcJy6RvgsGxv99-S8a9oLVnWGkEJOTyVIuE3Z6oRB");

		try {
			AuthorizationRequest.parse(requestURI);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Illegal redirect_uri parameter", e.getErrorObject().getDescription());
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
			Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("api_1")).build()),
			Collections.singletonList(URI.create("https://rs1.com")),
			true,
			null,
			null,
			new Prompt(Prompt.Type.LOGIN, Prompt.Type.CONSENT),
			new JWKThumbprintConfirmation(new Base64URL("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")),
			createSampleTrustChain(),
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
		assertEquals(in.getAuthorizationDetails(), out.getAuthorizationDetails());
		assertEquals(in.includeGrantedScopes(), out.includeGrantedScopes());
		assertEquals(in.getPrompt(), out.getPrompt());
		assertEquals(in.getDPoPJWKThumbprintConfirmation(), out.getDPoPJWKThumbprintConfirmation());
		assertEquals(in.getTrustChain(), out.getTrustChain());
		assertEquals(in.getCustomParameters(), out.getCustomParameters());
		assertEquals(in.getEndpointURI(), out.getEndpointURI());
		
		assertEquals(in.toParameters(), out.toParameters());
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


	public void testRAR() throws ParseException {

		ResponseType responseType = ResponseType.CODE;
		ClientID clientID = new ClientID("123");
		List<AuthorizationDetail> authorizationDetails = Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("api_1")).build());

		AuthorizationRequest request = new AuthorizationRequest.Builder(responseType, clientID)
			.authorizationDetails(authorizationDetails)
			.build();

		Map<String, List<String>> parameters = request.toParameters();

		assertEquals(Collections.singletonList(responseType.toString()), parameters.get("response_type"));
		assertEquals(Collections.singletonList(clientID.getValue()), parameters.get("client_id"));
		assertEquals(Collections.singletonList(AuthorizationDetail.toJSONString(authorizationDetails)), parameters.get("authorization_details"));
		assertEquals(3, parameters.size());

		request = AuthorizationRequest.parse(parameters);

		assertEquals(responseType, request.getResponseType());
		assertEquals(clientID, request.getClientID());
		assertEquals(authorizationDetails, request.getAuthorizationDetails());
		assertEquals(3, request.toParameters().size());
	}


	public void testRAR_parseException_missingType() {

		ResponseType responseType = ResponseType.CODE;
		ClientID clientID = new ClientID("123");

		AuthorizationRequest request = new AuthorizationRequest.Builder(responseType, clientID)
			.build();

		Map<String, List<String>> parameters = request.toParameters();
		parameters.put("authorization_details", Collections.singletonList("[{},{}]"));

		try {
			AuthorizationRequest.parse(parameters);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid authorization details: Invalid authorization detail at position 0: Illegal or missing type", e.getMessage());
		}
	}


	public void testRAR_parseException_invalidJSON() {

		ResponseType responseType = ResponseType.CODE;
		ClientID clientID = new ClientID("123");

		AuthorizationRequest request = new AuthorizationRequest.Builder(responseType, clientID)
			.build();

		Map<String, List<String>> parameters = request.toParameters();
		parameters.put("authorization_details", Collections.singletonList("xxx"));

		try {
			AuthorizationRequest.parse(parameters);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid authorization details: Invalid JSON", e.getMessage());
		}
	}


	public void _testRAR_docExample() {

		// For PKCE
		CodeVerifier codeVerifier = new CodeVerifier();

		// Compose the authorisation detail
		AuthorizationDetail authzDetail = new AuthorizationDetail.Builder(new AuthorizationType("message_api_v1"))
			.locations(Collections.singletonList(new Location(URI.create("https://api.example.com/messages"))))
			.actions(Arrays.asList(new Action("read"), new Action("get"), new Action("search")))
			.build();

		// Compose the OAuth 2.0 authorisation request
		AuthorizationRequest request = new AuthorizationRequest.Builder(ResponseType.CODE, new ClientID("123"))
			.endpointURI(URI.create("https://demo.c2id.com/login"))
			.authorizationDetails(Collections.singletonList(authzDetail))
			.redirectionURI(URI.create("https://client.example.com/cb"))
			.codeChallenge(codeVerifier, CodeChallengeMethod.S256)
			.state(new State())
			.build();

		// Print the request
		System.out.println(request.toURI());
	}
	
	
	public void testBuilderResourceWithQueryComponent() {
		
		URI resource = URI.create("https://api.example.com?query=abc");
		
		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
			.resource(resource)
			.build();
		
		assertEquals(Collections.singletonList(resource), request.getResources());
	}
	
	
	public void testBuilderWithOneResource() {
		
		URI resource = URI.create("https://api.example.com");
		
		AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
			.resource(resource)
			.build();
		
		assertEquals(Collections.singletonList(resource), request.getResources());
		
		request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
			.resource(resource)
			.resource(null)
			.build();
		
		assertNull(request.getResources());
	}
	
	
	public void testBuilderWithResource_rejectNonAbsoluteURI() {
		
		try {
			new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
				.resources(URI.create("/api/v1"))
				.build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Resource URI must be absolute and without a fragment: /api/v1", e.getMessage());
		}
	}
	
	
	public void testBuilderWithResource_rejectURIWithFragment() {
		
		try {
			new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
				.resources(URI.create("https://rs1.com/api/v1#fragment"))
				.build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Resource URI must be absolute and without a fragment: https://rs1.com/api/v1#fragment", e.getMessage());
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
	
	
	public void testParseResourceIndicatorsWithQueryComponent()
		throws ParseException {
		
		AuthorizationRequest request = AuthorizationRequest.parse(
			URI.create(
				"https://authorization-server.example.com" +
				"/as/authorization.oauth2?response_type=token" +
				"&client_id=s6BhdRkqt3&state=laeb" +
				"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb" +
				"&resource=https%3A%2F%2Frs.example.com%2Fapi%2Fv1?query=abc"));
		
		assertEquals(new ClientID("s6BhdRkqt3"), request.getClientID());
		assertEquals(new State("laeb"), request.getState());
		assertEquals(new ResponseType("token"), request.getResponseType());
		assertEquals(URI.create("https://client.example.com/cb"), request.getRedirectionURI());
		assertEquals(Collections.singletonList(URI.create("https://rs.example.com/api/v1?query=abc")), request.getResources());
	}
	
	
	public void testParse_rejectResourceURINotAbsolute() {
		
		try {
			AuthorizationRequest.parse(URI.create("https://authorization-server.example.com" +
				"/as/authorization.oauth2?response_type=token" +
				"&client_id=s6BhdRkqt3&state=laeb" +
				"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb" +
				"&resource=%2Fapi%2Fv1"));
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_TARGET, e.getErrorObject());
			assertEquals("Illegal resource parameter: Must be an absolute URI and with no query or fragment", e.getErrorObject().getDescription());
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
			assertEquals(OAuth2Error.INVALID_TARGET, e.getErrorObject());
			assertEquals("Illegal resource parameter: Must be an absolute URI and with no query or fragment", e.getErrorObject().getDescription());
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
	
	
	public void testJAR_trustChain() throws JOSEException, java.text.ParseException {
		
		TrustChain trustChain = createSampleTrustChain();
		
		AuthorizationRequest request = new AuthorizationRequest.Builder(ResponseType.CODE, new ClientID("123"))
			.trustChain(trustChain)
			.build();
		
		JWTClaimsSet jwtClaimsSet = request.toJWTClaimsSet();
		
		assertEquals(request.getResponseType().toString(), jwtClaimsSet.getStringClaim("response_type"));
		assertEquals(request.getClientID().toString(), jwtClaimsSet.getStringClaim("client_id"));
		assertEquals(request.getTrustChain().toSerializedJWTs(), jwtClaimsSet.getStringListClaim("trust_chain"));
		assertEquals(3, jwtClaimsSet.getClaims().size());
		
		Audience aud = new Audience("https://c2id.com/login");
		JWTClaimsSet federationJWTClaimsSet = new JWTClaimsSet.Builder(jwtClaimsSet)
			.audience(aud.getValue())
			.issuer(request.getClientID().getValue())
			.jwtID(new JWTID().getValue())
			.expirationTime(new Date(1000L))
			.build();
		
		SignedJWT jar = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), federationJWTClaimsSet);
		jar.sign(new RSASSASigner(new RSAKeyGenerator(2048).keyID("1").generate()));
		
		request = new AuthorizationRequest.Builder(jar, request.getClientID())
			.endpointURI(URI.create("https://c2id.com/login"))
			.build();
		
		Map<String, List<String>> params = request.toParameters();
		assertEquals(Collections.singletonList(jar.serialize()), params.get("request"));
		assertEquals(Collections.singletonList(request.getClientID().getValue()), params.get("client_id"));
		assertEquals(2, params.size());
	}
	
	
	public void testBuilder_nullRequestObject_clientID() {
		
		try {
			new AuthorizationRequest.Builder((JWT)null, new ClientID("123"));
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testBuilder_requestObject_nullClientID() throws java.text.ParseException {
		
		try {
			new AuthorizationRequest.Builder(PlainJWT.parse("eyJhbGciOiJub25lIn0.eyJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6IjEyMyJ9."), null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testBuilder_nullRequestURI_clientID() {
		
		try {
			new AuthorizationRequest.Builder((URI)null, new ClientID("123"));
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testBuilder_requestURI_nullClientID() {
		
		try {
			new AuthorizationRequest.Builder(URI.create("urn:requests:ahy4ohgo"), null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
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
	public void testParse_parameterWithTwoDifferentValues_clientID()
		throws URISyntaxException {
		
		URI uri = new URI("https://c2id.com/authz/");
		
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);
		
		ClientID clientID = new ClientID("123");

		AuthorizationRequest req = new AuthorizationRequest(uri, rts, clientID);
		
		Map<String,List<String>> params = req.toParameters();
		params.put("client_id", Arrays.asList("injected", clientID.getValue()));
		
		try {
			AuthorizationRequest.parse(uri, params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Parameter(s) present more than once: [client_id]", e.getErrorObject().getDescription());
		}
	}
	
	
	// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/394/ignore-duplicates-in-http-request-check
	public void testParse_duplicatedParameter_clientID()
		throws URISyntaxException, ParseException {
		
		URI uri = new URI("https://c2id.com/authz/");
		
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);
		
		ClientID clientID = new ClientID("456");

		AuthorizationRequest req = new AuthorizationRequest(uri, rts, clientID);
		
		Map<String,List<String>> params = req.toParameters();
		params.put("client_id", Arrays.asList(clientID.getValue(), clientID.getValue()));
		
		AuthorizationRequest parsed = AuthorizationRequest.parse(uri, params);
		
		assertEquals(parsed.toParameters(), req.toParameters());
	}
	
	
	public void testCopyConstructorWithOIDCParameters() throws URISyntaxException, LangTagException {
		
		AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
			ResponseType.CODE,
			new Scope("openid"),
			new ClientID("123"),
			new URI("https://example.com/cb"))
			.nonce(new Nonce())
			.display(Display.POPUP)
			.maxAge(3600)
			.uiLocales(Arrays.asList(LangTag.parse("en"), LangTag.parse("bg")))
			.claimsLocales(Arrays.asList(LangTag.parse("en"), LangTag.parse("bg")))
			.idTokenHint(new PlainJWT(new JWTClaimsSet.Builder().subject("alice").build()))
			.loginHint("alice@wonderland.net")
			.acrValues(Collections.singletonList(new ACR("0")))
			.claims(new OIDCClaimsRequest()
				.withUserInfoClaimsRequest(new ClaimsSetRequest().add("email"))
			)
			.purpose("Transaction")
			.build();
		
		AuthorizationRequest copy = new AuthorizationRequest.Builder(authRequest)
			.build();
		
		assertEquals(authRequest.toParameters(), copy.toParameters());
	}


	public void testIllegalRedirectURI_constructor_fragment() {

		try {
			new AuthorizationRequest.Builder(ResponseType.CODE, new ClientID("123"))
				.redirectionURI(URI.create("https://example.com/cb#fragment"))
				.build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("The redirect_uri must not contain fragment", e.getMessage());
		}
	}


	public void testIllegalRedirectURI_parse_fragment() {

		AuthorizationRequest request = new AuthorizationRequest.Builder(ResponseType.CODE, new ClientID("123"))
			.build();

		Map<String, List<String>> parameters = request.toParameters();
		parameters.put("redirect_uri", Collections.singletonList("https://example.com/cb#fragment"));

		try {
			AuthorizationRequest.parse(parameters);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid request: Illegal redirect_uri parameter", e.getErrorObject().getDescription());
		}
	}


	public void testIllegalRedirectURI_constructor_prohibitedScheme() {

		for (String scheme: RedirectURIValidator.PROHIBITED_REDIRECT_URI_SCHEMES) {
			try {
				new AuthorizationRequest.Builder(ResponseType.CODE, new ClientID("123"))
					.redirectionURI(URI.create(scheme  + "://example.com"))
					.build();
				fail();
			} catch (IllegalStateException e) {
				assertEquals("The URI scheme " + scheme + " is prohibited", e.getMessage());
			}
		}
	}


	public void testIllegalRedirectURI_parse_prohibitedScheme() {

		AuthorizationRequest request = new AuthorizationRequest.Builder(ResponseType.CODE, new ClientID("123"))
			.build();

		for (String scheme: RedirectURIValidator.PROHIBITED_REDIRECT_URI_SCHEMES) {

			Map<String, List<String>> parameters = request.toParameters();
			parameters.put("redirect_uri", Collections.singletonList(scheme  + "://example.com"));

			try {
				AuthorizationRequest.parse(parameters);
				fail();
			} catch (ParseException e) {
				assertEquals("Invalid request: Illegal redirect_uri parameter", e.getErrorObject().getDescription());
			}
		}
	}


	public void testIllegalRedirectURI_constructor_prohibitedQueryParam() {

		for (String queryParam: RedirectURIValidator.PROHIBITED_REDIRECT_URI_QUERY_PARAMETER_NAMES) {
			try {
				new AuthorizationRequest.Builder(ResponseType.CODE, new ClientID("123"))
					.redirectionURI(URI.create("https://example.com/cb?" + queryParam  + "=123"))
					.build();
				fail();
			} catch (IllegalStateException e) {
				assertEquals("The query parameter " + queryParam + " is prohibited", e.getMessage());
			}
		}
	}


	public void testIllegalRedirectURI_parse_prohibitedQueryParam() {

		AuthorizationRequest request = new AuthorizationRequest.Builder(ResponseType.CODE, new ClientID("123"))
			.build();

		for (String queryParam: RedirectURIValidator.PROHIBITED_REDIRECT_URI_QUERY_PARAMETER_NAMES) {

			Map<String, List<String>> parameters = request.toParameters();
			parameters.put("redirect_uri", Collections.singletonList("https://example.com/cb?" + queryParam  + "=123"));

			try {
				AuthorizationRequest.parse(parameters);
				fail();
			} catch (ParseException e) {
				assertEquals("Illegal redirect_uri parameter", e.getMessage());
				assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
				assertEquals("Invalid request: Illegal redirect_uri parameter", e.getErrorObject().getDescription());
			}
		}
	}


	public void testToHTTPRequest_POST_thenParse() throws ParseException {

		AuthorizationRequest request = new AuthorizationRequest(
			URI.create("https://c2id.com/login"),
			ResponseType.CODE,
			new ClientID());

		HTTPRequest httpRequest = request.toHTTPRequest(HTTPRequest.Method.POST);
		assertEquals(request.getEndpointURI(), httpRequest.getURI());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_URLENCODED, httpRequest.getEntityContentType());
		assertEquals(request.toParameters(), httpRequest.getBodyAsFormParameters());

		assertEquals(request.toURI(), AuthorizationRequest.parse(httpRequest).toURI());
	}


	public void testToHTTPRequest_GET_thenParse() throws ParseException {

		AuthorizationRequest request = new AuthorizationRequest(
			URI.create("https://c2id.com/login"),
			ResponseType.CODE,
			new ClientID());

		HTTPRequest httpRequest = request.toHTTPRequest(HTTPRequest.Method.GET);
		assertEquals(request.getEndpointURI(), URIUtils.getBaseURI(httpRequest.getURI()));
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertNull(httpRequest.getEntityContentType());
		assertNull(httpRequest.getBody());
		assertEquals(request.toParameters(), httpRequest.getQueryStringParameters());

		assertEquals(request.toURI(), AuthorizationRequest.parse(httpRequest).toURI());
	}


	public void testToHTTPRequest_unexpectedMethod() {

		AuthorizationRequest request = new AuthorizationRequest(
			URI.create("https://c2id.com/login"),
			ResponseType.CODE,
			new ClientID());

		try {
			request.toHTTPRequest(HTTPRequest.Method.PUT);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("HTTP GET or POST expected", e.getMessage());
		}
	}


	public void testParseHTTPRequest_unexpectedMethod() {

		AuthorizationRequest request = new AuthorizationRequest(
			URI.create("https://c2id.com/login"),
			ResponseType.CODE,
			new ClientID());

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.PUT, request.getEndpointURI());
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody(URLUtils.serializeParameters(request.toParameters()));

		try {
			AuthorizationRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("HTTP GET or POST expected", e.getMessage());
		}
	}
}
