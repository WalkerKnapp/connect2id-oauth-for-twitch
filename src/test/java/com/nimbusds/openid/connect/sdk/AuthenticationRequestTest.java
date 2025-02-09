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
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.langtag.LangTagUtils;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail;
import com.nimbusds.oauth2.sdk.rar.AuthorizationType;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.assurance.IdentityTrustFramework;
import com.nimbusds.openid.connect.sdk.assurance.request.MinimalVerificationSpec;
import com.nimbusds.openid.connect.sdk.assurance.request.VerifiedClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementClaimsSet;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChainTest;
import junit.framework.TestCase;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.apache.commons.lang.RandomStringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.*;


public class AuthenticationRequestTest extends TestCase {


	private final static String EXAMPLE_JWT_STRING = 
		"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
     		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
     		"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";


	public void testRegisteredParameters() {

		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("response_type"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("response_mode"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("client_id"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("redirect_uri"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("scope"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("state"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("code_challenge"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("code_challenge_method"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("authorization_details"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("resource"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("include_granted_scopes"));

		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("nonce"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("display"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("prompt"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("dpop_jkt"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("trust_chain"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("max_age"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("ui_locales"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("claims_locales"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("id_token_hint"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("login_hint"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("acr_values"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("claims"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("purpose"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("request_uri"));
		assertTrue(AuthenticationRequest.getRegisteredParameterNames().contains("request"));

		assertEquals(26, AuthenticationRequest.getRegisteredParameterNames().size());
	}

	
	public void testMinimalConstructor()
		throws Exception {

		URI uri = new URI("https://c2id.com/login/");
		
		ResponseType rts = ResponseType.CODE;

		Scope scope = new Scope();
		scope.add(OIDCScopeValue.OPENID);
		scope.add(OIDCScopeValue.EMAIL);
		scope.add(OIDCScopeValue.PROFILE);

		ClientID clientID = new ClientID("123456789");

		URI redirectURI = new URI("http://www.deezer.com/en/");

		State state = new State("abc");
		Nonce nonce = new Nonce("xyz");

		AuthenticationRequest request =
			new AuthenticationRequest(uri, rts, scope, clientID, redirectURI, state, nonce);

		assertEquals(uri, request.getEndpointURI());
		
		ResponseType rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.QUERY, request.impliedResponseMode());

		Scope scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());
		
		assertEquals(new ClientID("123456789"), request.getClientID());
		
		assertEquals(new URI("http://www.deezer.com/en/"), request.getRedirectionURI());
		
		assertEquals(new State("abc"), request.getState());
		assertEquals(new Nonce("xyz"), request.getNonce());

		assertNull(request.getResponseMode());
		assertNull(request.getDisplay());
		assertNull(request.getPrompt());
		assertNull(request.getDPoPJWKThumbprintConfirmation());
		assertNull(request.getTrustChain());
		assertEquals(-1, request.getMaxAge());
		assertNull(request.getUILocales());
		assertNull(request.getIDTokenHint());
		assertNull(request.getLoginHint());
		assertNull(request.getACRValues());
		assertNull(request.getClaims());
		assertNull(request.getOIDCClaims());
		assertNull(request.getClaimsLocales());
		assertNull(request.getRequestObject());
		assertNull(request.getRequestURI());
		assertNull(request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());
		assertNull(request.getAuthorizationDetails());
		assertNull(request.getResources());
		assertFalse(request.includeGrantedScopes());
		assertTrue(request.getCustomParameters().isEmpty());

		// Check the resulting query string
		String queryString = request.toQueryString();

		request = AuthenticationRequest.parse(uri, queryString);
		
		assertEquals(uri, request.getEndpointURI());

		rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.QUERY, request.impliedResponseMode());

		scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());
		
		assertEquals(new ClientID("123456789"), request.getClientID());
		
		assertEquals(new URI("http://www.deezer.com/en/"), request.getRedirectionURI());
		
		assertEquals(new State("abc"), request.getState());
		assertEquals(new Nonce("xyz"), request.getNonce());

		assertNull(request.getResponseMode());
		assertNull(request.getDisplay());
		assertNull(request.getPrompt());
		assertNull(request.getDPoPJWKThumbprintConfirmation());
		assertNull(request.getTrustChain());
		assertEquals(-1, request.getMaxAge());
		assertNull(request.getUILocales());
		assertNull(request.getIDTokenHint());
		assertNull(request.getLoginHint());
		assertNull(request.getACRValues());
		assertNull(request.getClaims());
		assertNull(request.getOIDCClaims());
		assertNull(request.getClaimsLocales());
		assertNull(request.getRequestObject());
		assertNull(request.getRequestURI());
		assertNull(request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());
		assertNull(request.getAuthorizationDetails());
		assertNull(request.getResources());
		assertFalse(request.includeGrantedScopes());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testAltParse()
		throws Exception {

		URI uri = new URI("https://c2id.com/login/");

		ResponseType rts = ResponseType.CODE;

		Scope scope = new Scope();
		scope.add(OIDCScopeValue.OPENID);
		scope.add(OIDCScopeValue.EMAIL);
		scope.add(OIDCScopeValue.PROFILE);

		ClientID clientID = new ClientID("123456789");

		URI redirectURI = new URI("http://www.deezer.com/en/");

		State state = new State("abc");
		Nonce nonce = new Nonce("xyz");

		AuthenticationRequest request =
			new AuthenticationRequest(uri, rts, scope, clientID, redirectURI, state, nonce);

		// Check the resulting query string
		String queryString = request.toQueryString();

		request = AuthenticationRequest.parse(queryString);

		assertNull(request.getEndpointURI());

		ResponseType rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.QUERY, request.impliedResponseMode());

		Scope scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());
		
		assertEquals(new ClientID("123456789"), request.getClientID());
		
		assertEquals(new URI("http://www.deezer.com/en/"), request.getRedirectionURI());
		
		assertEquals(new State("abc"), request.getState());
		assertEquals(new Nonce("xyz"), request.getNonce());

		assertEquals(-1, request.getMaxAge());

		assertNull(request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());

		assertNull(request.getAuthorizationDetails());

		assertNull(request.getResources());
		
		assertFalse(request.includeGrantedScopes());

		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testExtendedConstructor_withCustomParams()
		throws Exception {

		URI uri = new URI("https://c2id.com/login/");

		ResponseType rts = ResponseType.CODE;

		ResponseMode rm = ResponseMode.FORM_POST;

		Scope scope = new Scope();
		scope.add(OIDCScopeValue.OPENID);
		scope.add(OIDCScopeValue.EMAIL);
		scope.add(OIDCScopeValue.PROFILE);

		ClientID clientID = new ClientID("123456789");

		URI redirectURI = new URI("http://www.deezer.com/en/");

		State state = new State("abc");
		Nonce nonce = new Nonce("xyz");

		// Extended parameters
		Display display = Display.POPUP;

		Prompt prompt = new Prompt();
		prompt.add(Prompt.Type.LOGIN);
		prompt.add(Prompt.Type.CONSENT);
		
		JWKThumbprintConfirmation dpopJKT = new JWKThumbprintConfirmation(new Base64URL("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"));
		
		TrustChain trustChain = createSampleTrustChain();

		int maxAge = 3600;

		List<LangTag> uiLocales = new LinkedList<>();
		uiLocales.add(LangTag.parse("en-US"));
		uiLocales.add(LangTag.parse("en-GB"));

		List<LangTag> claimsLocales = new LinkedList<>();
		claimsLocales.add(LangTag.parse("de-DE"));
		claimsLocales.add(LangTag.parse("de-AT"));

		JWT idTokenHint = JWTParser.parse(EXAMPLE_JWT_STRING);

		String loginHint = "alice123";

		List<ACR> acrValues = new LinkedList<>();
		acrValues.add(new ACR("1"));
		acrValues.add(new ACR("2"));

		OIDCClaimsRequest claims = new OIDCClaimsRequest()
			.withUserInfoClaimsRequest(new ClaimsSetRequest().add("given_name").add("family_name"));
		
		String purpose = "Some identity assurance purpose";

		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.S256;
		CodeChallenge codeChallenge = CodeChallenge.compute(codeChallengeMethod, codeVerifier);

		List<AuthorizationDetail> authorizationDetails = Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("example_api")).build());

		List<URI> resources = Collections.singletonList(URI.create("https://rs1.com"));

		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("x", Collections.singletonList("100"));
		customParams.put("y", Collections.singletonList("200"));
		customParams.put("z", Collections.singletonList("300"));

		AuthenticationRequest request = new AuthenticationRequest(
			uri, rts, rm, scope, clientID, redirectURI, state, nonce,
			display, prompt, dpopJKT, trustChain, maxAge, uiLocales, claimsLocales,
			idTokenHint, loginHint, acrValues, claims, purpose, null, null,
			codeChallenge, codeChallengeMethod,
			authorizationDetails,
			resources,
			true,
			customParams);

		assertEquals(uri, request.getEndpointURI());

		ResponseType rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		Scope scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());
		
		assertEquals(new ClientID("123456789"), request.getClientID());
		
		assertEquals(new URI("http://www.deezer.com/en/"), request.getRedirectionURI());
		
		assertEquals(new State("abc"), request.getState());
		assertEquals(new Nonce("xyz"), request.getNonce());

		// Check extended parameters

		assertEquals(rm, request.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, request.impliedResponseMode());

		assertEquals("Display checK", Display.POPUP, request.getDisplay());

		Prompt promptOut = request.getPrompt();
		assertTrue("Prompt login", promptOut.contains(Prompt.Type.LOGIN));
		assertTrue("Prompt consent", promptOut.contains(Prompt.Type.CONSENT));
		assertEquals("Prompt size", 2, promptOut.size());
		
		assertEquals(dpopJKT, request.getDPoPJWKThumbprintConfirmation());
		
		assertEquals(trustChain, request.getTrustChain());

		assertEquals(3600, request.getMaxAge());

		uiLocales = request.getUILocales();
		assertEquals("UI locale en-US", uiLocales.get(0), LangTag.parse("en-US"));
		assertEquals("UI locale en-GB", uiLocales.get(1), LangTag.parse("en-GB"));
		assertEquals("UI locales size", 2, uiLocales.size());

		claimsLocales = request.getClaimsLocales();
		assertEquals("Claims locale de-DE", claimsLocales.get(0), LangTag.parse("de-DE"));
		assertEquals("Claims locale de-AT", claimsLocales.get(1), LangTag.parse("de-AT"));
		assertEquals("Claims locales size", 2, claimsLocales.size());

		assertEquals(EXAMPLE_JWT_STRING, request.getIDTokenHint().getParsedString());

		assertEquals(loginHint, request.getLoginHint());

		List<ACR> acrValuesOut = request.getACRValues();
		assertEquals("1", acrValuesOut.get(0).toString());
		assertEquals("2", acrValuesOut.get(1).toString());
		assertEquals(2, acrValuesOut.size());

		OIDCClaimsRequest claimsOut = request.getOIDCClaims();

		assertEquals(claims, claimsOut);
		
		assertEquals(purpose, request.getPurpose());

		assertEquals(codeChallenge, request.getCodeChallenge());
		assertEquals(codeChallengeMethod, request.getCodeChallengeMethod());

		assertEquals(authorizationDetails, request.getAuthorizationDetails());

		assertEquals(resources, request.getResources());

		assertEquals(Collections.singletonList("100"), request.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameter("y"));
		assertEquals(Collections.singletonList("300"), request.getCustomParameter("z"));
		assertEquals(3, request.getCustomParameters().size());

		// Check the resulting query string
		String queryString = request.toQueryString();

		request = AuthenticationRequest.parse(uri, queryString);

		assertEquals(uri, request.getEndpointURI());

		rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());
		
		assertEquals(new ClientID("123456789"), request.getClientID());
		
		assertEquals(new URI("http://www.deezer.com/en/"), request.getRedirectionURI());
		
		assertEquals(new State("abc"), request.getState());
		assertEquals(new Nonce("xyz"), request.getNonce());

		// Check extended parameters

		assertEquals(rm, request.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, request.impliedResponseMode());

		assertEquals("Display checK", Display.POPUP, request.getDisplay());

		promptOut = request.getPrompt();
		assertTrue("Prompt login", promptOut.contains(Prompt.Type.LOGIN));
		assertTrue("Prompt consent", promptOut.contains(Prompt.Type.CONSENT));
		assertEquals("Prompt size", 2, promptOut.size());
		
		assertEquals(dpopJKT, request.getDPoPJWKThumbprintConfirmation());
		
		assertEquals(trustChain.toSerializedJWTs(), request.getTrustChain().toSerializedJWTs());

		assertEquals(3600, request.getMaxAge());

		uiLocales = request.getUILocales();
		assertEquals("UI locale en-US", uiLocales.get(0), LangTag.parse("en-US"));
		assertEquals("UI locale en-GB", uiLocales.get(1), LangTag.parse("en-GB"));
		assertEquals("UI locales size", 2, uiLocales.size());

		claimsLocales = request.getClaimsLocales();
		assertEquals("Claims locale de-DE", claimsLocales.get(0), LangTag.parse("de-DE"));
		assertEquals("Claims locale de-AT", claimsLocales.get(1), LangTag.parse("de-AT"));
		assertEquals("Claims locales size", 2, claimsLocales.size());

		assertEquals(EXAMPLE_JWT_STRING, request.getIDTokenHint().getParsedString());

		assertEquals(loginHint, request.getLoginHint());

		acrValuesOut = request.getACRValues();
		assertEquals("1", acrValuesOut.get(0).toString());
		assertEquals("2", acrValuesOut.get(1).toString());
		assertEquals(2, acrValuesOut.size());

		claimsOut = request.getOIDCClaims();
		assertEquals(claims.toJSONObject(), claimsOut.toJSONObject());
		
		assertEquals(purpose, request.getPurpose());

		assertEquals(codeChallenge, request.getCodeChallenge());
		assertEquals(codeChallengeMethod, request.getCodeChallengeMethod());

		assertEquals(authorizationDetails, request.getAuthorizationDetails());

		assertEquals(resources, request.getResources());
		
		assertTrue(request.includeGrantedScopes());

		assertEquals(Collections.singletonList("100"), request.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameter("y"));
		assertEquals(Collections.singletonList("300"), request.getCustomParameter("z"));
		assertEquals(3, request.getCustomParameters().size());
	}


	public void testDeprecatedExtendedConstructor_withCustomParams()
		throws Exception {

		URI uri = new URI("https://c2id.com/login/");

		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		ResponseMode rm = ResponseMode.FORM_POST;

		Scope scope = new Scope();
		scope.add(OIDCScopeValue.OPENID);
		scope.add(OIDCScopeValue.EMAIL);
		scope.add(OIDCScopeValue.PROFILE);

		ClientID clientID = new ClientID("123456789");

		URI redirectURI = new URI("http://www.deezer.com/en/");

		State state = new State("abc");
		Nonce nonce = new Nonce("xyz");

		// Extended parameters
		Display display = Display.POPUP;

		Prompt prompt = new Prompt();
		prompt.add(Prompt.Type.LOGIN);
		prompt.add(Prompt.Type.CONSENT);

		int maxAge = 3600;

		List<LangTag> uiLocales = new LinkedList<>();
		uiLocales.add(LangTag.parse("en-US"));
		uiLocales.add(LangTag.parse("en-GB"));

		List<LangTag> claimsLocales = new LinkedList<>();
		claimsLocales.add(LangTag.parse("de-DE"));
		claimsLocales.add(LangTag.parse("de-AT"));

		JWT idTokenHint = JWTParser.parse(EXAMPLE_JWT_STRING);

		String loginHint = "alice123";

		List<ACR> acrValues = new LinkedList<>();
		acrValues.add(new ACR("1"));
		acrValues.add(new ACR("2"));

		ClaimsRequest claims = new ClaimsRequest();
		claims.addUserInfoClaim("given_name");
		claims.addUserInfoClaim("family_name");
		
		String purpose = "Some identity assurance purpose";

		CodeVerifier codeVerifier = new CodeVerifier();
		CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.S256;
		CodeChallenge codeChallenge = CodeChallenge.compute(codeChallengeMethod, codeVerifier);
		
		List<URI> resources = Collections.singletonList(URI.create("https://rs1.com"));

		Map<String,List<String>> customParams = new HashMap<>();
		customParams.put("x", Collections.singletonList("100"));
		customParams.put("y", Collections.singletonList("200"));
		customParams.put("z", Collections.singletonList("300"));

		AuthenticationRequest request = new AuthenticationRequest(
			uri, rts, rm, scope, clientID, redirectURI, state, nonce,
			display, prompt, maxAge, uiLocales, claimsLocales,
			idTokenHint, loginHint, acrValues, claims, purpose, null, null,
			codeChallenge, codeChallengeMethod,
			resources,
			true,
			customParams);

		assertEquals(uri, request.getEndpointURI());

		ResponseType rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		Scope scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());
		
		assertEquals(new ClientID("123456789"), request.getClientID());
		
		assertEquals(new URI("http://www.deezer.com/en/"), request.getRedirectionURI());
		
		assertEquals(new State("abc"), request.getState());
		assertEquals(new Nonce("xyz"), request.getNonce());

		// Check extended parameters

		assertEquals(rm, request.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, request.impliedResponseMode());

		assertEquals("Display checK", Display.POPUP, request.getDisplay());

		Prompt promptOut = request.getPrompt();
		assertTrue("Prompt login", promptOut.contains(Prompt.Type.LOGIN));
		assertTrue("Prompt consent", promptOut.contains(Prompt.Type.CONSENT));
		assertEquals("Prompt size", 2, promptOut.size());

		assertEquals(3600, request.getMaxAge());

		uiLocales = request.getUILocales();
		assertEquals("UI locale en-US", uiLocales.get(0), LangTag.parse("en-US"));
		assertEquals("UI locale en-GB", uiLocales.get(1), LangTag.parse("en-GB"));
		assertEquals("UI locales size", 2, uiLocales.size());

		claimsLocales = request.getClaimsLocales();
		assertEquals("Claims locale de-DE", claimsLocales.get(0), LangTag.parse("de-DE"));
		assertEquals("Claims locale de-AT", claimsLocales.get(1), LangTag.parse("de-AT"));
		assertEquals("Claims locales size", 2, claimsLocales.size());

		assertEquals(EXAMPLE_JWT_STRING, request.getIDTokenHint().getParsedString());

		assertEquals(loginHint, request.getLoginHint());

		List<ACR> acrValuesOut = request.getACRValues();
		assertEquals("1", acrValuesOut.get(0).toString());
		assertEquals("2", acrValuesOut.get(1).toString());
		assertEquals(2, acrValuesOut.size());

		ClaimsRequest claimsOut = request.getClaims();

		assertEquals(2, claimsOut.getUserInfoClaims().size());
		
		assertEquals(purpose, request.getPurpose());

		assertEquals(codeChallenge, request.getCodeChallenge());
		assertEquals(codeChallengeMethod, request.getCodeChallengeMethod());
		
		assertEquals(resources, request.getResources());

		assertEquals(Collections.singletonList("100"), request.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameter("y"));
		assertEquals(Collections.singletonList("300"), request.getCustomParameter("z"));
		assertEquals(3, request.getCustomParameters().size());

		// Check the resulting query string
		String queryString = request.toQueryString();

		request = AuthenticationRequest.parse(uri, queryString);

		assertEquals(uri, request.getEndpointURI());

		rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());
		
		assertEquals(new ClientID("123456789"), request.getClientID());
		
		assertEquals(new URI("http://www.deezer.com/en/"), request.getRedirectionURI());
		
		assertEquals(new State("abc"), request.getState());
		assertEquals(new Nonce("xyz"), request.getNonce());

		// Check extended parameters

		assertEquals(rm, request.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, request.impliedResponseMode());

		assertEquals("Display checK", Display.POPUP, request.getDisplay());

		promptOut = request.getPrompt();
		assertTrue("Prompt login", promptOut.contains(Prompt.Type.LOGIN));
		assertTrue("Prompt consent", promptOut.contains(Prompt.Type.CONSENT));
		assertEquals("Prompt size", 2, promptOut.size());

		assertEquals(3600, request.getMaxAge());

		uiLocales = request.getUILocales();
		assertEquals("UI locale en-US", uiLocales.get(0), LangTag.parse("en-US"));
		assertEquals("UI locale en-GB", uiLocales.get(1), LangTag.parse("en-GB"));
		assertEquals("UI locales size", 2, uiLocales.size());

		claimsLocales = request.getClaimsLocales();
		assertEquals("Claims locale de-DE", claimsLocales.get(0), LangTag.parse("de-DE"));
		assertEquals("Claims locale de-AT", claimsLocales.get(1), LangTag.parse("de-AT"));
		assertEquals("Claims locales size", 2, claimsLocales.size());

		assertEquals(EXAMPLE_JWT_STRING, request.getIDTokenHint().getParsedString());

		assertEquals(loginHint, request.getLoginHint());

		acrValuesOut = request.getACRValues();
		assertEquals("1", acrValuesOut.get(0).toString());
		assertEquals("2", acrValuesOut.get(1).toString());
		assertEquals(2, acrValuesOut.size());

		claimsOut = request.getClaims();

		assertEquals(2, claimsOut.getUserInfoClaims().size());
		
		assertEquals(purpose, request.getPurpose());

		assertEquals(codeChallenge, request.getCodeChallenge());
		assertEquals(codeChallengeMethod, request.getCodeChallengeMethod());
		
		assertEquals(resources, request.getResources());
		
		assertTrue(request.includeGrantedScopes());

		assertEquals(Collections.singletonList("100"), request.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameter("y"));
		assertEquals(Collections.singletonList("300"), request.getCustomParameter("z"));
		assertEquals(3, request.getCustomParameters().size());
	}


	public void testRequestObjectConstructor()
		throws Exception {

		URI uri = new URI("https://c2id.com/login");
		
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		Scope scope = new Scope();
		scope.add(OIDCScopeValue.OPENID);
		scope.add(OIDCScopeValue.EMAIL);
		scope.add(OIDCScopeValue.PROFILE);

		ClientID clientID = new ClientID("123456789");

		URI redirectURI = new URI("http://www.deezer.com/en/");

		State state = new State("abc");
		Nonce nonce = new Nonce("xyz");

		// Extended parameters
		Display display = Display.POPUP;

		Prompt prompt = new Prompt();
		prompt.add(Prompt.Type.LOGIN);
		prompt.add(Prompt.Type.CONSENT);

		int maxAge = 3600;

		List<LangTag> uiLocales = new LinkedList<>();
		uiLocales.add(LangTag.parse("en-US"));
		uiLocales.add(LangTag.parse("en-GB"));

		List<LangTag> claimsLocales = new LinkedList<>();
		claimsLocales.add(LangTag.parse("en-US"));
		claimsLocales.add(LangTag.parse("en-GB"));

		JWT idTokenHint = JWTParser.parse(EXAMPLE_JWT_STRING);

		String loginHint = "alice123";

		List<ACR> acrValues = new LinkedList<>();
		acrValues.add(new ACR("1"));
		acrValues.add(new ACR("2"));

		ClaimsRequest claims = new ClaimsRequest();
		claims.addUserInfoClaim("given_name");
		claims.addUserInfoClaim("family_name");

		JWT requestObject = JWTParser.parse(EXAMPLE_JWT_STRING);

		AuthenticationRequest request = new AuthenticationRequest(
			uri, rts, null, scope, clientID, redirectURI, state, nonce,
			display, prompt, maxAge, uiLocales, claimsLocales,
			idTokenHint, loginHint, acrValues, claims, null, requestObject, null,
			null, null, null, false, null);

		assertEquals(uri, request.getEndpointURI());
		
		ResponseType rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		Scope scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());
		
		assertEquals(new ClientID("123456789"), request.getClientID());
		
		assertEquals(new URI("http://www.deezer.com/en/"), request.getRedirectionURI());
		
		assertEquals(new State("abc"), request.getState());
		assertEquals(new Nonce("xyz"), request.getNonce());

		// Check extended parameters

		assertNull(request.getResponseMode());

		assertEquals("Display checK", Display.POPUP, request.getDisplay());

		Prompt promptOut = request.getPrompt();
		assertTrue("Prompt login", promptOut.contains(Prompt.Type.LOGIN));
		assertTrue("Prompt consent", promptOut.contains(Prompt.Type.CONSENT));
		assertEquals("Prompt size", 2, promptOut.size());

		assertEquals(3600, request.getMaxAge());

		uiLocales = request.getUILocales();
		assertEquals("UI locale en-US", uiLocales.get(0), LangTag.parse("en-US"));
		assertEquals("UI locale en-GB", uiLocales.get(1), LangTag.parse("en-GB"));
		assertEquals("UI locales size", 2, uiLocales.size());

		claimsLocales = request.getClaimsLocales();
		assertEquals("Claims locale en-US", claimsLocales.get(0), LangTag.parse("en-US"));
		assertEquals("Claims locale en-US", claimsLocales.get(1), LangTag.parse("en-GB"));
		assertEquals("Claims locales size", 2, claimsLocales.size());

		assertEquals(EXAMPLE_JWT_STRING, request.getIDTokenHint().getParsedString());

		assertEquals(loginHint, request.getLoginHint());

		List<ACR> acrValuesOut = request.getACRValues();
		assertEquals("1", acrValuesOut.get(0).toString());
		assertEquals("2", acrValuesOut.get(1).toString());
		assertEquals(2, acrValuesOut.size());

		ClaimsRequest claimsOut = request.getClaims();

//		System.out.println("OIDC login request claims: " + claimsOut.toJSONObject().toString());

		assertEquals(2, claimsOut.getUserInfoClaims().size());

		assertEquals(EXAMPLE_JWT_STRING, request.getRequestObject().getParsedString());


		// Check the resulting query string
		String queryString = request.toQueryString();

//		System.out.println("OIDC login query string: " + queryString);


		request = AuthenticationRequest.parse(uri, queryString);
		
		assertEquals(uri, request.getEndpointURI());

		rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());
		
		assertEquals(new ClientID("123456789"), request.getClientID());
		
		assertEquals(new URI("http://www.deezer.com/en/"), request.getRedirectionURI());
		
		assertEquals(new State("abc"), request.getState());
		assertEquals(new Nonce("xyz"), request.getNonce());

		// Check extended parameters

		assertNull(request.getResponseMode());

		assertEquals("Display checK", Display.POPUP, request.getDisplay());

		promptOut = request.getPrompt();
		assertTrue("Prompt login", promptOut.contains(Prompt.Type.LOGIN));
		assertTrue("Prompt consent", promptOut.contains(Prompt.Type.CONSENT));
		assertEquals("Prompt size", 2, promptOut.size());

		assertEquals(3600, request.getMaxAge());

		uiLocales = request.getUILocales();
		assertEquals("UI locale en-US", uiLocales.get(0), LangTag.parse("en-US"));
		assertEquals("UI locale en-GB", uiLocales.get(1), LangTag.parse("en-GB"));
		assertEquals("UI locales size", 2, uiLocales.size());

		claimsLocales = request.getClaimsLocales();
		assertEquals("Claims locale en-US", claimsLocales.get(0), LangTag.parse("en-US"));
		assertEquals("Claims locale en-US", claimsLocales.get(1), LangTag.parse("en-GB"));
		assertEquals("Claims locales size", 2, claimsLocales.size());

		assertEquals(EXAMPLE_JWT_STRING, request.getIDTokenHint().getParsedString());

		assertEquals(loginHint, request.getLoginHint());

		acrValuesOut = request.getACRValues();
		assertEquals("1", acrValuesOut.get(0).toString());
		assertEquals("2", acrValuesOut.get(1).toString());
		assertEquals(2, acrValuesOut.size());

		claimsOut = request.getClaims();

//		System.out.println("OIDC login request claims: " + claimsOut.toJSONObject().toString());

		assertEquals(2, claimsOut.getUserInfoClaims().size());

		assertEquals(EXAMPLE_JWT_STRING, request.getRequestObject().getParsedString());
	}


	public void testRequestURIConstructor()
		throws Exception {

		URI uri = new URI("https://c2id.com/login/");
		
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);

		Scope scope = new Scope();
		scope.add(OIDCScopeValue.OPENID);
		scope.add(OIDCScopeValue.EMAIL);
		scope.add(OIDCScopeValue.PROFILE);

		ClientID clientID = new ClientID("123456789");

		URI redirectURI = new URI("http://www.deezer.com/en/");

		State state = new State("abc");
		Nonce nonce = new Nonce("xyz");

		// Extended parameters
		Display display = Display.POPUP;

		Prompt prompt = new Prompt();
		prompt.add(Prompt.Type.LOGIN);
		prompt.add(Prompt.Type.CONSENT);

		int maxAge = 3600;

		List<LangTag> uiLocales = new LinkedList<>();
		uiLocales.add(LangTag.parse("en-US"));
		uiLocales.add(LangTag.parse("en-GB"));

		List<LangTag> claimsLocales = new LinkedList<>();
		claimsLocales.add(LangTag.parse("en-US"));
		claimsLocales.add(LangTag.parse("en-GB"));

		JWT idTokenHint = JWTParser.parse(EXAMPLE_JWT_STRING);

		String loginHint = "alice123";

		List<ACR> acrValues = new LinkedList<>();
		acrValues.add(new ACR("1"));
		acrValues.add(new ACR("2"));

		ClaimsRequest claims = new ClaimsRequest();
		claims.addUserInfoClaim("given_name");
		claims.addUserInfoClaim("family_name");

		URI requestURI = new URI("http://example.com/request-object.jwt#1234");

		AuthenticationRequest request = new AuthenticationRequest(
			uri, rts, null, scope, clientID, redirectURI, state, nonce,
			display, prompt, maxAge, uiLocales, claimsLocales,
			idTokenHint, loginHint, acrValues, claims, null, null, requestURI,
			null, null, null, false, null);

		assertEquals(uri, request.getEndpointURI());
		
		ResponseType rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		Scope scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());
		
		assertEquals(new ClientID("123456789"), request.getClientID());
		
		assertEquals(new URI("http://www.deezer.com/en/"), request.getRedirectionURI());
		
		assertEquals(new State("abc"), request.getState());
		assertEquals(new Nonce("xyz"), request.getNonce());

		// Check extended parameters

		assertNull(request.getResponseMode());

		assertEquals("Display checK", Display.POPUP, request.getDisplay());

		Prompt promptOut = request.getPrompt();
		assertTrue("Prompt login", promptOut.contains(Prompt.Type.LOGIN));
		assertTrue("Prompt consent", promptOut.contains(Prompt.Type.CONSENT));
		assertEquals("Prompt size", 2, promptOut.size());

		assertEquals(3600, request.getMaxAge());

		uiLocales = request.getUILocales();
		assertEquals("UI locale en-US", uiLocales.get(0), LangTag.parse("en-US"));
		assertEquals("UI locale en-GB", uiLocales.get(1), LangTag.parse("en-GB"));
		assertEquals("UI locales size", 2, uiLocales.size());

		claimsLocales = request.getClaimsLocales();
		assertEquals("Claims locale en-US", claimsLocales.get(0), LangTag.parse("en-US"));
		assertEquals("Claims locale en-US", claimsLocales.get(1), LangTag.parse("en-GB"));
		assertEquals("Claims locales size", 2, claimsLocales.size());

		assertEquals(EXAMPLE_JWT_STRING, request.getIDTokenHint().getParsedString());

		assertEquals(loginHint, request.getLoginHint());

		List<ACR> acrValuesOut = request.getACRValues();
		assertEquals("1", acrValuesOut.get(0).toString());
		assertEquals("2", acrValuesOut.get(1).toString());
		assertEquals(2, acrValuesOut.size());

		ClaimsRequest claimsOut = request.getClaims();

//		System.out.println("OIDC login request claims: " + claimsOut.toJSONObject().toString());

		assertEquals(2, claimsOut.getUserInfoClaims().size());

		assertEquals(requestURI, request.getRequestURI());


		// Check the resulting query string
		String queryString = request.toQueryString();

//		System.out.println("OIDC login query string: " + queryString);


		request = AuthenticationRequest.parse(uri, queryString);
		
		assertEquals(uri, request.getEndpointURI());

		rtsOut = request.getResponseType();
		assertTrue(rtsOut.contains(ResponseType.Value.CODE));
		assertEquals(1, rtsOut.size());

		scopeOut = request.getScope();
		assertTrue(scopeOut.contains(OIDCScopeValue.OPENID));
		assertTrue(scopeOut.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopeOut.contains(OIDCScopeValue.PROFILE));
		assertEquals(3, scopeOut.size());
		
		assertEquals(new ClientID("123456789"), request.getClientID());
		
		assertEquals(new URI("http://www.deezer.com/en/"), request.getRedirectionURI());
		
		assertEquals(new State("abc"), request.getState());
		assertEquals(new Nonce("xyz"), request.getNonce());

		// Check extended parameters

		assertNull(request.getResponseMode());

		assertEquals("Display checK", Display.POPUP, request.getDisplay());

		promptOut = request.getPrompt();
		assertTrue("Prompt login", promptOut.contains(Prompt.Type.LOGIN));
		assertTrue("Prompt consent", promptOut.contains(Prompt.Type.CONSENT));
		assertEquals("Prompt size", 2, promptOut.size());

		assertEquals(3600, request.getMaxAge());

		uiLocales = request.getUILocales();
		assertEquals("UI locale en-US", uiLocales.get(0), LangTag.parse("en-US"));
		assertEquals("UI locale en-GB", uiLocales.get(1), LangTag.parse("en-GB"));
		assertEquals("UI locales size", 2, uiLocales.size());

		claimsLocales = request.getClaimsLocales();
		assertEquals("Claims locale en-US", claimsLocales.get(0), LangTag.parse("en-US"));
		assertEquals("Claims locale en-US", claimsLocales.get(1), LangTag.parse("en-GB"));
		assertEquals("Claims locales size", 2, claimsLocales.size());

		assertEquals(EXAMPLE_JWT_STRING, request.getIDTokenHint().getParsedString());

		assertEquals(loginHint, request.getLoginHint());

		acrValuesOut = request.getACRValues();
		assertEquals("1", acrValuesOut.get(0).toString());
		assertEquals("2", acrValuesOut.get(1).toString());
		assertEquals(2, acrValuesOut.size());

		claimsOut = request.getClaims();

//		System.out.println("OIDC login request claims: " + claimsOut.toJSONObject().toString());

		assertEquals(2, claimsOut.getUserInfoClaims().size());

		assertEquals(requestURI, request.getRequestURI());
	}


	public void testBuilderMinimal()
		throws Exception {

		AuthenticationRequest request = new AuthenticationRequest.Builder(
			ResponseType.CODE,
			new Scope("openid", "email"),
			new ClientID("123"),
			new URI("https://client.com/cb")).build();
		
		assertEquals(new ResponseType("code"), request.getResponseType());
		assertEquals(new Scope("openid", "email"), request.getScope());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals(new URI("https://client.com/cb"), request.getRedirectionURI());
		assertNull(request.getState());
		assertNull(request.getNonce());
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.QUERY, request.impliedResponseMode());
		assertNull(request.getDisplay());
		assertNull(request.getPrompt());
		assertNull(request.getDPoPJWKThumbprintConfirmation());
		assertNull(request.getTrustChain());
		assertEquals(-1, request.getMaxAge());
		assertNull(request.getUILocales());
		assertNull(request.getClaimsLocales());
		assertNull(request.getIDTokenHint());
		assertNull(request.getLoginHint());
		assertNull(request.getACRValues());
		assertNull(request.getClaims());
		assertNull(request.getRequestObject());
		assertNull(request.getRequestURI());
		assertNull(request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());
		assertNull(request.getAuthorizationDetails());
		assertNull(request.getResources());
		assertFalse(request.includeGrantedScopes());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testBuilderFull()
		throws Exception {

		List<ACR> acrValues = new LinkedList<>();
		acrValues.add(new ACR("1"));
		acrValues.add(new ACR("2"));

		ClaimsRequest claims = new ClaimsRequest();
		claims.addUserInfoClaim("given_name");
		claims.addUserInfoClaim("family_name");
		
		String purpose = "Some Identity Assurance purpose";

		CodeVerifier codeVerifier = new CodeVerifier();
		
		TrustChain trustChain = createSampleTrustChain();
		
		AuthenticationRequest request = new AuthenticationRequest.Builder(
			ResponseType.CODE_IDTOKEN,
			new Scope("openid", "email"),
			new ClientID("123"),
			new URI("https://client.com/cb"))
			.state(new State("abc"))
			.nonce(new Nonce("def"))
			.display(Display.POPUP)
			.prompt(new Prompt(Prompt.Type.NONE))
			.dPoPJWKThumbprintConfirmation(new JWKThumbprintConfirmation(new Base64URL("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")))
			.trustChain(trustChain)
			.maxAge(3600)
			.uiLocales(Arrays.asList(LangTag.parse("en-GB"), LangTag.parse("en-US")))
			.claimsLocales(Arrays.asList(LangTag.parse("bg-BG"), LangTag.parse("fr-FR")))
			.idTokenHint(JWTParser.parse(EXAMPLE_JWT_STRING))
			.loginHint("alice@wonderland.net")
			.acrValues(acrValues)
			.claims(claims)
			.purpose(purpose)
			.responseMode(ResponseMode.FORM_POST)
			.codeChallenge(codeVerifier, CodeChallengeMethod.S256)
			.authorizationDetails(Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("example_api")).build()))
			.resources(URI.create("https://rs1.com"))
			.includeGrantedScopes(true)
			.customParameter("x", "100")
			.customParameter("y", "200")
			.customParameter("z", "300")
			.endpointURI(new URI("https://c2id.com/login"))
			.build();
		
		assertEquals(ResponseType.CODE_IDTOKEN, request.getResponseType());
		assertEquals(ResponseMode.FORM_POST, request.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, request.impliedResponseMode());
		assertEquals(new Scope("openid", "email"), request.getScope());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals(new URI("https://client.com/cb"), request.getRedirectionURI());
		assertEquals(new State("abc"), request.getState());
		assertEquals(new Nonce("def"), request.getNonce());
		assertEquals(Display.POPUP, request.getDisplay());
		assertEquals(new Prompt(Prompt.Type.NONE), request.getPrompt());
		assertEquals(new JWKThumbprintConfirmation(new Base64URL("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")), request.getDPoPJWKThumbprintConfirmation());
		assertEquals(trustChain, request.getTrustChain());
		assertEquals(3600, request.getMaxAge());
		assertEquals(Arrays.asList(LangTag.parse("en-GB"), LangTag.parse("en-US")), request.getUILocales());
		assertEquals(Arrays.asList(LangTag.parse("bg-BG"), LangTag.parse("fr-FR")), request.getClaimsLocales());
		assertEquals(EXAMPLE_JWT_STRING, request.getIDTokenHint().getParsedString());
		assertEquals("alice@wonderland.net", request.getLoginHint());
		assertEquals(acrValues, request.getACRValues());
		assertEquals(claims.toJSONObject(), request.getClaims().toJSONObject());
		assertEquals(claims.toJSONObject(), request.getOIDCClaims().toJSONObject());
		assertEquals(purpose, request.getPurpose());
		assertEquals(CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier), request.getCodeChallenge());
		assertEquals(CodeChallengeMethod.S256, request.getCodeChallengeMethod());
		assertEquals(Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("example_api")).build()), request.getAuthorizationDetails());
		assertEquals(Collections.singletonList(URI.create("https://rs1.com")), request.getResources());
		assertTrue(request.includeGrantedScopes());
		assertEquals(Collections.singletonList("100"), request.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameter("y"));
		assertEquals(Collections.singletonList("300"), request.getCustomParameter("z"));
		assertEquals(3, request.getCustomParameters().size());
		assertEquals(new URI("https://c2id.com/login"), request.getEndpointURI());
	}


	public void testBuilderWithWithRequestObject()
		throws Exception {

		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code", "id_token"),
			new Scope("openid", "email"),
			new ClientID("123"),
			new URI("https://client.com/cb")).
			nonce(new Nonce("xyz")).
			requestObject(JWTParser.parse(EXAMPLE_JWT_STRING)).
			build();
		
		assertEquals(new ResponseType("code", "id_token"), request.getResponseType());
		assertEquals(ResponseMode.FRAGMENT, request.impliedResponseMode());
		assertEquals(new Scope("openid", "email"), request.getScope());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals(new URI("https://client.com/cb"), request.getRedirectionURI());
		assertEquals(new Nonce("xyz"), request.getNonce());
		assertEquals(EXAMPLE_JWT_STRING, request.getRequestObject().getParsedString());
		assertEquals(-1, request.getMaxAge());
	}


	public void testBuilderWithRequestURI()
		throws Exception {

		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code", "id_token"),
			new Scope("openid", "email"),
			new ClientID("123"),
			new URI("https://client.com/cb")).
			requestURI(new URI("https://client.com/request#123")).
			nonce(new Nonce("xyz")).
			build();
		
		assertEquals(new ResponseType("code", "id_token"), request.getResponseType());
		assertEquals(ResponseMode.FRAGMENT, request.impliedResponseMode());
		assertEquals(new Scope("openid", "email"), request.getScope());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals(new URI("https://client.com/cb"), request.getRedirectionURI());
		assertEquals(new Nonce("xyz"), request.getNonce());
		assertEquals(new URI("https://client.com/request#123"), request.getRequestURI());
		assertEquals(-1, request.getMaxAge());
	}
	
	
	public void testBuilderPromptTypesVarArg() {
		
		Scope scope = new Scope(OIDCScopeValue.OPENID);
		ClientID clientID = new ClientID("123");
		URI redirectURI = URI.create("https://rp.example.com/cb");
		
		// One prompt value
		AuthenticationRequest request = new AuthenticationRequest.Builder(
			ResponseType.CODE,
			scope,
			clientID,
			redirectURI)
			.prompt(Prompt.Type.LOGIN)
			.build();
		
		assertEquals(ResponseType.CODE, request.getResponseType());
		assertEquals(scope, request.getScope());
		assertEquals(clientID, request.getClientID());
		assertEquals(redirectURI, request.getRedirectionURI());
		assertEquals(new Prompt(Prompt.Type.LOGIN), request.getPrompt());
		assertEquals(5, request.toParameters().size());
		
		// Two prompt values
		request = new AuthenticationRequest.Builder(
			ResponseType.CODE,
			scope,
			clientID,
			redirectURI)
			.prompt(Prompt.Type.LOGIN, Prompt.Type.CONSENT)
			.build();
		
		assertEquals(ResponseType.CODE, request.getResponseType());
		assertEquals(scope, request.getScope());
		assertEquals(clientID, request.getClientID());
		assertEquals(redirectURI, request.getRedirectionURI());
		assertEquals(new Prompt(Prompt.Type.LOGIN, Prompt.Type.CONSENT), request.getPrompt());
		assertEquals(5, request.toParameters().size());
		
		// Empty prompt
		request = new AuthenticationRequest.Builder(
			ResponseType.CODE,
			scope,
			clientID,
			redirectURI)
			.prompt(new Prompt.Type[0])
			.build();
		
		assertEquals(ResponseType.CODE, request.getResponseType());
		assertEquals(scope, request.getScope());
		assertEquals(clientID, request.getClientID());
		assertEquals(redirectURI, request.getRedirectionURI());
		assertTrue(request.getPrompt().isEmpty());
		assertEquals(5, request.toParameters().size());
		
		// Null prompt
		request = new AuthenticationRequest.Builder(
			ResponseType.CODE,
			scope,
			clientID,
			redirectURI)
			.prompt((Prompt.Type) null)
			.build();
		
		assertEquals(ResponseType.CODE, request.getResponseType());
		assertEquals(scope, request.getScope());
		assertEquals(clientID, request.getClientID());
		assertEquals(redirectURI, request.getRedirectionURI());
		assertNull(request.getPrompt());
		assertEquals(4, request.toParameters().size());
	}


	public void testParseInvalidResponseType() {

		AuthenticationRequest request = new AuthenticationRequest.Builder(
			ResponseType.CODE,
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.build();

		Map<String, List<String>> params = request.toParameters();

		// Illegal response_type
		params.put("response_type", Collections.singletonList("'...\"id_token\"???...'"));

                try {
                        AuthenticationRequest.parse(params);
			fail();
                } catch (ParseException e) {
                        assertEquals("Unsupported response_type parameter: Unsupported OpenID Connect response type value", e.getMessage());
                }
        }
	
	
	// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/345/token-and-authz-request-must-fail-with-400
	public void testParse_repeatedParameter_clientID()
		throws URISyntaxException {
		
		URI uri = new URI("https://c2id.com/authz/");
		
		ResponseType rts = new ResponseType();
		rts.add(ResponseType.Value.CODE);
		
		Scope scope = new Scope(OIDCScopeValue.OPENID);
		
		ClientID clientID = new ClientID("123456");
		
		URI redirectURI = new URI("https://example.com/cb");
		
		State state = new State();
		
		AuthenticationRequest req = new AuthenticationRequest(uri, rts, scope, clientID, redirectURI, state, null);
		
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


	public void testParseMissingRedirectionURI() {

		String query = "response_type=id_token%20token" +
			"&client_id=s6BhdRkqt3" +
			"&scope=openid%20profile" +
			"&state=af0ifjsldkj" +
			"&nonce=n-0S6_WzA2Mj";

		try {
			AuthenticationRequest.parse(query);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing redirect_uri parameter", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing redirect_uri parameter", e.getErrorObject().getDescription());
			assertEquals(ResponseMode.FRAGMENT, e.getResponseMode());
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testParseMissingScope() {

		String query = "response_type=id_token%20token" +
			"&client_id=s6BhdRkqt3" +
			"&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
			"&state=af0ifjsldkj";

		try {
			AuthenticationRequest.parse(query);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing scope parameter", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing scope parameter", e.getErrorObject().getDescription());
			assertEquals(ResponseMode.FRAGMENT, e.getResponseMode());
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testParseMissingScopeOpenIDValue() {

		String query = "response_type=code" +
			"&client_id=s6BhdRkqt3" +
			"&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
			"&scope=profile" +
			"&state=af0ifjsldkj";

		try {
			AuthenticationRequest.parse(query);
			fail();
		} catch (ParseException e) {
			assertEquals("The scope must include an openid value", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: The scope must include an openid value", e.getErrorObject().getDescription());
			assertEquals(ResponseMode.QUERY, e.getResponseMode());
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testParseInvalidDisplay() {

		String query = "response_type=code" +
			"&client_id=s6BhdRkqt3" +
			"&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
			"&scope=openid%20profile" +
			"&state=af0ifjsldkj" +
			"&display=mobile";

		try {
			AuthenticationRequest.parse(query);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid display parameter: Unknown display type", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Invalid display parameter: Unknown display type", e.getErrorObject().getDescription());
			assertEquals(ResponseMode.QUERY, e.getResponseMode());
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testParseInvalidMaxAge() {

		String query =
			"response_type=code" +
			"&client_id=s6BhdRkqt3" +
			"&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
			"&scope=openid%20profile" +
			"&state=af0ifjsldkj" +
			"&max_age=zero";

		try {
			AuthenticationRequest.parse(query);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid max_age parameter", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Invalid max_age parameter", e.getErrorObject().getDescription());
			assertEquals(ResponseMode.QUERY, e.getResponseMode());
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testParseInvalidIDTokenHint() {

		String query = "response_type=code" +
			"&client_id=s6BhdRkqt3" +
			"&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
			"&scope=openid%20profile" +
			"&state=af0ifjsldkj" +
			"&id_token_hint=ey...";

		try {
			AuthenticationRequest.parse(query);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid id_token_hint parameter: Invalid unsecured/JWS/JWE header: Invalid JSON object", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Invalid id_token_hint parameter: Invalid unsecured/JWS/JWE header: Invalid JSON object", e.getErrorObject().getDescription());			assertEquals(ResponseMode.QUERY, e.getResponseMode());
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testParseFromURI()
		throws Exception {

		URI uri = new URI("https://c2id.com/login?" +
			"response_type=id_token%20token" +
			"&client_id=s6BhdRkqt3" +
			"&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
			"&scope=openid%20profile" +
			"&state=af0ifjsldkj" +
			"&nonce=n-0S6_WzA2Mj");

		AuthenticationRequest request = AuthenticationRequest.parse(uri);

		assertEquals(new URI("https://c2id.com/login"), request.getEndpointURI());
		assertEquals(new ResponseType("id_token", "token"), request.getResponseType());
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.FRAGMENT, request.impliedResponseMode());
		assertEquals(new ClientID("s6BhdRkqt3"), request.getClientID());
		assertEquals(new URI("https://client.example.org/cb"), request.getRedirectionURI());
		assertEquals(new Scope("openid", "profile"), request.getScope());
		assertEquals(new State("af0ifjsldkj"), request.getState());
		assertEquals(new Nonce("n-0S6_WzA2Mj"), request.getNonce());
		assertEquals(-1, request.getMaxAge());
	}


	public void testParseRequestURIWithRedirectURI()
		throws Exception {

		// See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issue/113/authenticationrequest-fails-to-parse

		// Example from http://openid.net/specs/openid-connect-core-1_0.html#UseRequestUri
		String query = "response_type=code%20id_token" +
			"&client_id=s6BhdRkqt3" +
			"&request_uri=https%3A%2F%2Fclient.example.org%2Frequest.jwt" +
			"%23GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM" +
			"&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj" +
			"&scope=openid";

		AuthenticationRequest request = AuthenticationRequest.parse(query);
		
		assertEquals(request.getResponseType(), new ResponseType("code", "id_token"));
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.FRAGMENT, request.impliedResponseMode());
		assertEquals(request.getClientID(), new ClientID("s6BhdRkqt3"));
		assertEquals(request.getRequestURI(), new URI("https://client.example.org/request.jwt#GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM"));
		assertEquals(request.getState(), new State("af0ifjsldkj"));
		assertEquals(request.getNonce(), new Nonce("n-0S6_WzA2Mj"));
		assertEquals(request.getScope(), Scope.parse("openid"));
		assertEquals(-1, request.getMaxAge());
	}
	
	
	public void testParseRequestURI_missingClientID() {
		
		try {
			AuthenticationRequest.parse(URI.create("https://c2id.com/login?request_uri=https%3A%2F%2Fexample.org%2Frequest.jwt"));
			fail();
		} catch (ParseException e) {
			assertEquals("Missing client_id parameter", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		}
	}
	
	
	public void testParseRequestObject_missingClientID() {
		
		try {
			AuthenticationRequest.parse(URI.create("https://c2id.com/login?request=eyJhbGciOiJub25lIn0.eyJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6IjEyMyJ9."));
			fail();
		} catch (ParseException e) {
			assertEquals("Missing client_id parameter", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
		}
	}


	public void testBuilderWithRedirectURIInRequestURI()
		throws Exception {

		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code", "id_token"),
			new Scope("openid"),
			new ClientID("s6BhdRkqt3"),
			null) // redirect_uri
			.state(new State("af0ifjsldkj"))
			.nonce(new Nonce("n-0S6_WzA2Mj"))
			.requestURI(new URI("https://client.example.org/request.jwt#GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM"))
			.build();
		
		assertEquals(request.getResponseType(), new ResponseType("code", "id_token"));
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.FRAGMENT, request.impliedResponseMode());
		assertEquals(request.getClientID(), new ClientID("s6BhdRkqt3"));
		assertEquals(request.getRequestURI(), new URI("https://client.example.org/request.jwt#GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM"));
		assertEquals(request.getState(), new State("af0ifjsldkj"));
		assertEquals(request.getNonce(), new Nonce("n-0S6_WzA2Mj"));
		assertEquals(request.getScope(), Scope.parse("openid"));
	}


	public void testNonceRequirement()
		throws Exception {

		// See https://bitbucket.org/openid/connect/issues/972/nonce-requirement-in-hybrid-auth-request
		
		// Spec discussion about nonce in hybrid flow https://bitbucket.org/openid/connect/issues/972/nonce-requirement-in-hybrid-auth-request
		
		// response_type=code
		AuthenticationRequest ar = new AuthenticationRequest.Builder(
			ResponseType.parse("code"),
			new Scope("openid"),
			new ClientID("s6BhdRkqt3"),
			URI.create("https://example.com/cb")) // redirect_uri
			.state(new State("af0ifjsldkj"))
			.endpointURI(new URI("https://c2id.com/login"))
			.build();
		
		AuthenticationRequest.parse(ar.toURI());
		
		// response_type=code+token
		ar = new AuthenticationRequest.Builder(
			ResponseType.parse("code token"),
			new Scope("openid"),
			new ClientID("s6BhdRkqt3"),
			URI.create("https://example.com/cb")) // redirect_uri
			.state(new State("af0ifjsldkj"))
			.endpointURI(new URI("https://c2id.com/login"))
			.build();
		
		AuthenticationRequest.parse(ar.toURI());
		
		// response_type=id_token+token
		try {
			new AuthenticationRequest.Builder(
				ResponseType.parse("id_token token"),
				new Scope("openid"),
				new ClientID("s6BhdRkqt3"),
				URI.create("https://example.com/cb")) // redirect_uri
				.state(new State("af0ifjsldkj"))
				.build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Nonce required for response_type=id_token token", e.getMessage());
		}
		
		try {
			AuthenticationRequest.parse(new URI(
				"https://c2id.com/login?" +
					"response_type=id_token%20token" +
					"&client_id=s6BhdRkqt3" +
					"&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
					"&scope=openid%20profile" +
					"&state=af0ifjsldkj"));
			fail();
		} catch (ParseException e) {
			assertEquals("Missing nonce parameter: Required for response_type=id_token token", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing nonce parameter: Required for response_type=id_token token", e.getErrorObject().getDescription());
			assertEquals(new ClientID("s6BhdRkqt3"), e.getClientID());
			assertEquals(new URI("https://client.example.org/cb"), e.getRedirectionURI());
			assertEquals(ResponseMode.FRAGMENT, e.getResponseMode());
			assertEquals(new State("af0ifjsldkj"), e.getState());
		}

		// response_type=id_token
		try {
			new AuthenticationRequest.Builder(
				ResponseType.parse("id_token"),
				new Scope("openid"),
				new ClientID("s6BhdRkqt3"),
				URI.create("https://example.com/cb")) // redirect_uri
				.state(new State("af0ifjsldkj"))
				.build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Nonce required for response_type=id_token", e.getMessage());
		}
		
		try {
			AuthenticationRequest.parse(new URI(
				"https://c2id.com/login?" +
					"response_type=id_token" +
					"&client_id=s6BhdRkqt3" +
					"&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
					"&scope=openid%20profile" +
					"&state=af0ifjsldkj"));
			fail();
		} catch (ParseException e) {
			assertEquals("Missing nonce parameter: Required for response_type=id_token", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing nonce parameter: Required for response_type=id_token", e.getErrorObject().getDescription());
			assertEquals(new ClientID("s6BhdRkqt3"), e.getClientID());
			assertEquals(new URI("https://client.example.org/cb"), e.getRedirectionURI());
			assertEquals(ResponseMode.FRAGMENT, e.getResponseMode());
			assertEquals(new State("af0ifjsldkj"), e.getState());
		}

		// response_type=code+id_token
		try {
			new AuthenticationRequest.Builder(
				ResponseType.parse("code id_token"),
				new Scope("openid"),
				new ClientID("s6BhdRkqt3"),
				URI.create("https://example.com/cb")) // redirect_uri
				.state(new State("af0ifjsldkj"))
				.build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Nonce required for response_type=code id_token", e.getMessage());
		}
		
		try {
			AuthenticationRequest.parse(new URI(
				"https://c2id.com/login?" +
					"response_type=code%20id_token" +
					"&client_id=s6BhdRkqt3" +
					"&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
					"&scope=openid%20profile" +
					"&state=af0ifjsldkj"));
			fail();
		} catch (ParseException e) {
			assertEquals("Missing nonce parameter: Required for response_type=code id_token", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing nonce parameter: Required for response_type=code id_token", e.getErrorObject().getDescription());
			assertEquals(new ClientID("s6BhdRkqt3"), e.getClientID());
			assertEquals(new URI("https://client.example.org/cb"), e.getRedirectionURI());
			assertEquals(ResponseMode.FRAGMENT, e.getResponseMode());
			assertEquals(new State("af0ifjsldkj"), e.getState());
		}

		// response_type=code+id_token+token
		try {
			new AuthenticationRequest.Builder(
				ResponseType.parse("code id_token token"),
				new Scope("openid"),
				new ClientID("s6BhdRkqt3"),
				URI.create("https://example.com/cb")) // redirect_uri
				.state(new State("af0ifjsldkj"))
				.build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Nonce required for response_type=code id_token token", e.getMessage());
		}
		
		try {
			AuthenticationRequest.parse(new URI(
				"https://c2id.com/login?" +
					"response_type=code%20id_token%20token" +
					"&client_id=s6BhdRkqt3" +
					"&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
					"&scope=openid%20profile" +
					"&state=af0ifjsldkj"));
			fail();
		} catch (ParseException e) {
			assertEquals("Missing nonce parameter: Required for response_type=code id_token token", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing nonce parameter: Required for response_type=code id_token token", e.getErrorObject().getDescription());
			assertEquals(new ClientID("s6BhdRkqt3"), e.getClientID());
			assertEquals(new URI("https://client.example.org/cb"), e.getRedirectionURI());
			assertEquals(ResponseMode.FRAGMENT, e.getResponseMode());
			assertEquals(new State("af0ifjsldkj"), e.getState());
		}
	}


	// See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/147/authorizationrequestparse-final-uri-uri
	public void testParseWithEncodedEqualsChar()
		throws Exception {

		URI redirectURI = URI.create("https://client.com/in?app=123");

		String encodedRedirectURI = URLEncoder.encode(redirectURI.toString(), "UTF-8");

		URI requestURI = URI.create("https://server.example.com/authorize?" +
			"response_type=id_token%20token" +
			"&client_id=s6BhdRkqt3" +
			"&scope=openid%20profile" +
			"&state=af0ifjsldkj" +
			"&nonce=n-0S6_WzA2Mj" +
			"&redirect_uri=" + encodedRedirectURI);

		AuthenticationRequest request = AuthenticationRequest.parse(requestURI);

		assertEquals(ResponseType.parse("id_token token"), request.getResponseType());
		assertEquals(new ClientID("s6BhdRkqt3"), request.getClientID());
		assertEquals(new State("af0ifjsldkj"), request.getState());
		assertEquals(new Nonce("n-0S6_WzA2Mj"), request.getNonce());
		assertEquals(-1, request.getMaxAge());
		assertEquals(redirectURI, request.getRedirectionURI());
	}


	public void testParsePKCEExample()
		throws Exception {

		URI redirectURI = URI.create("https://client.com/cb");

		String encodedRedirectURI = URLEncoder.encode(redirectURI.toString(), "UTF-8");

		URI requestURI = URI.create("https://server.example.com/authorize?" +
			"response_type=id_token%20token" +
			"&client_id=s6BhdRkqt3" +
			"&scope=openid%20profile" +
			"&state=af0ifjsldkj" +
			"&nonce=n-0S6_WzA2Mj" +
			"&redirect_uri=" + encodedRedirectURI +
			"&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" +
			"&code_challenge_method=S256");

		AuthenticationRequest request = AuthenticationRequest.parse(requestURI);

		assertEquals(ResponseType.parse("id_token token"), request.getResponseType());
		assertEquals(new ClientID("s6BhdRkqt3"), request.getClientID());
		assertEquals(new State("af0ifjsldkj"), request.getState());
		assertEquals(new Nonce("n-0S6_WzA2Mj"), request.getNonce());
		assertEquals(-1, request.getMaxAge());
		assertEquals(redirectURI, request.getRedirectionURI());
		assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", request.getCodeChallenge().getValue());
		assertEquals(CodeChallengeMethod.S256, request.getCodeChallengeMethod());
	}
	
	
	public void testParsePromptCreate() throws ParseException {
		
		AuthorizationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code"), new Scope("openid"), new ClientID("123"), URI.create("https://example.com/cb"))
			.prompt(new Prompt("create"))
			.endpointURI(URI.create("https://login.c2id.com"))
			.build();
		
		assertEquals(new Prompt(Prompt.Type.CREATE), request.getPrompt());
		
		request = AuthorizationRequest.parse(request.toURI());
		
		assertEquals(new Prompt(Prompt.Type.CREATE), request.getPrompt());
	}
	
	
	public void testParseUnknownPrompt() {
		
		AuthorizationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code"), new Scope("openid"), new ClientID("123"), URI.create("https://example.com/cb"))
			.build();
		
		Map<String,List<String>> params = request.toParameters();
		params.put("prompt", Collections.singletonList("prompt-xxx"));
		
		try {
			AuthenticationRequest.parse(params);
		} catch (ParseException e) {
			assertEquals("Invalid prompt parameter: Unknown prompt type: prompt-xxx", e.getMessage());
		}
	}


	public void testParseWithCustomParams()
		throws Exception {

		String q = "https://example.com:9091/oidc-login?client_id=am6bae3a&response_type=id_token+token&redirect_uri=https%3A%2F%2Fexample.com%3A9090%2Fexample%2FimplicitFlow&scope=openid&nonce=CvJam5c9fpY&claims=%7B%22id_token%22%3A%7B%22given_name%22%3Anull%2C%22family_name%22%3Anull%7D%7D&language=zh&context=MS-GLOBAL01&response_mode=json";

		AuthenticationRequest r = AuthenticationRequest.parse(URI.create(q));

		assertEquals(new ClientID("am6bae3a"), r.getClientID());
		assertEquals(new ResponseType("token", "id_token"), r.getResponseType());
		assertEquals(new ResponseMode("json"), r.getResponseMode());
		assertEquals(new Scope("openid"), r.getScope());
		assertEquals(new Nonce("CvJam5c9fpY"), r.getNonce());
		assertEquals(-1, r.getMaxAge());
		assertTrue(r.getClaims().getIDTokenClaimNames(false).contains("family_name"));
		assertTrue(r.getClaims().getIDTokenClaimNames(false).contains("given_name"));
		assertEquals(2, r.getClaims().getIDTokenClaimNames(false).size());
		assertEquals(URI.create("https://example.com:9090/example/implicitFlow"), r.getRedirectionURI());
		assertEquals(Collections.singletonList("MS-GLOBAL01"), r.getCustomParameter("context")); // custom
		assertEquals(Collections.singletonList("zh"), r.getCustomParameter("language")); // custom
	}


	public void testParseIllegalClaimsCase() {

		AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
			ResponseType.CODE,
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://rp.example.com/cb"))
			.state(new State())
			.build();

		Map<String, List<String>> authRequestParams = authRequest.toParameters();

		String queryString = URLUtils.serializeParameters(authRequestParams) + "&claims=id_token%22";

		try {
			AuthenticationRequest.parse(queryString);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid claims parameter: Invalid JSON", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Invalid claims parameter: Invalid JSON", e.getErrorObject().getDescription());
		}
	}
	
	
	public void testSignedAuthRequest()
		throws Exception {
		
		JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
			.claim("response_type", "code")
			.claim("scope", "openid email")
			.claim("code_challenge_method", "S256")
			.build();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("1").build(),
			jwtClaims);
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair rsaKeyPair = keyPairGenerator.generateKeyPair();
		
		jwt.sign(new RSASSASigner(rsaKeyPair.getPrivate()));
		
		String jwtString = jwt.serialize();
		
		CodeVerifier pkceVerifier = new CodeVerifier();
		
		URI authRequest = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("myapp://openid-connect-callback"))
			.state(new State())
			.codeChallenge(pkceVerifier, CodeChallengeMethod.S256)
			.requestObject(jwt)
			.endpointURI(URI.create("https://openid.c2id.com"))
			.build()
			.toURI();
		
//		System.out.println(authRequest);
		
		Base64URL fragment = Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(jwtString.getBytes(Charset.forName("UTF-8"))));
		
		URI requestURI = URI.create("https://myapp.io/request.jwt+" + fragment);
		
		authRequest = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("myapp://openid-connect-callback"))
			.state(new State())
			.codeChallenge(pkceVerifier, CodeChallengeMethod.S256)
			.requestURI(requestURI)
			.endpointURI(URI.create("https://openid.c2id.com"))
			.build()
			.toURI();
		
//		System.out.println(authRequest);
	}
	
	
	public void testBuilder_PKCE_null() {
		
		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.codeChallenge((CodeVerifier) null, null)
			.build();
		
		assertEquals(new ResponseType("code"), request.getResponseType());
		assertEquals(new ClientID("123"), request.getClientID());
		assertNull(request.getEndpointURI());
		assertEquals(URI.create("https://example.com/cb"), request.getRedirectionURI());
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.QUERY, request.impliedResponseMode());
		assertEquals(new Scope("openid"), request.getScope());
		assertNull(request.getState());
		assertNull(request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());
		assertTrue(request.getCustomParameters().isEmpty());
	}
	
	
	public void testBuilder_PKCE_null_deprecated() {
		
		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.codeChallenge((CodeChallenge) null, null)
			.build();
		
		assertEquals(new ResponseType("code"), request.getResponseType());
		assertEquals(new ClientID("123"), request.getClientID());
		assertNull(request.getEndpointURI());
		assertEquals(URI.create("https://example.com/cb"), request.getRedirectionURI());
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.QUERY, request.impliedResponseMode());
		assertEquals(new Scope("openid"), request.getScope());
		assertNull(request.getState());
		assertNull(request.getCodeChallenge());
		assertNull(request.getCodeChallengeMethod());
		assertTrue(request.getCustomParameters().isEmpty());
	}
	
	
	public void testBuilder_PKCE_plain_default() {
		
		CodeVerifier pkceVerifier = new CodeVerifier();
		
		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.codeChallenge(pkceVerifier, null)
			.build();
		
		assertEquals(new ResponseType("code"), request.getResponseType());
		assertEquals(new ClientID("123"), request.getClientID());
		assertNull(request.getEndpointURI());
		assertEquals(URI.create("https://example.com/cb"), request.getRedirectionURI());
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.QUERY, request.impliedResponseMode());
		assertEquals(new Scope("openid"), request.getScope());
		assertNull(request.getState());
		assertEquals(CodeChallenge.compute(CodeChallengeMethod.PLAIN, pkceVerifier), request.getCodeChallenge());
		assertEquals(CodeChallengeMethod.PLAIN, request.getCodeChallengeMethod());
		assertTrue(request.getCustomParameters().isEmpty());
	}
	
	
	public void testBuilder_PKCE_plain() {
		
		CodeVerifier pkceVerifier = new CodeVerifier();
		
		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.codeChallenge(pkceVerifier, CodeChallengeMethod.PLAIN)
			.build();
		
		assertEquals(new ResponseType("code"), request.getResponseType());
		assertEquals(new ClientID("123"), request.getClientID());
		assertNull(request.getEndpointURI());
		assertEquals(URI.create("https://example.com/cb"), request.getRedirectionURI());
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.QUERY, request.impliedResponseMode());
		assertEquals(new Scope("openid"), request.getScope());
		assertNull(request.getState());
		assertEquals(CodeChallenge.compute(CodeChallengeMethod.PLAIN, pkceVerifier), request.getCodeChallenge());
		assertEquals(CodeChallengeMethod.PLAIN, request.getCodeChallengeMethod());
		assertTrue(request.getCustomParameters().isEmpty());
	}
	
	
	public void testBuilder_PKCE_S256() {
		
		CodeVerifier pkceVerifier = new CodeVerifier();
		
		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.codeChallenge(pkceVerifier, CodeChallengeMethod.S256)
			.build();
		
		assertEquals(new ResponseType("code"), request.getResponseType());
		assertEquals(new ClientID("123"), request.getClientID());
		assertNull(request.getEndpointURI());
		assertEquals(URI.create("https://example.com/cb"), request.getRedirectionURI());
		assertNull(request.getResponseMode());
		assertEquals(ResponseMode.QUERY, request.impliedResponseMode());
		assertEquals(new Scope("openid"), request.getScope());
		assertNull(request.getState());
		assertEquals(CodeChallenge.compute(CodeChallengeMethod.S256, pkceVerifier), request.getCodeChallenge());
		assertEquals(CodeChallengeMethod.S256, request.getCodeChallengeMethod());
		assertTrue(request.getCustomParameters().isEmpty());
	}
	
	
	public void testBuilderWithOneResource() {
		
		URI resource = URI.create("https://api.example.com");
		
		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.resource(resource)
			.build();
		
		assertEquals(Collections.singletonList(resource), request.getResources());
		
		request = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.resource(resource)
			.resource(null)
			.build();
		
		assertNull(request.getResources());
	}
	
	
	public void testResponseTypeCodeTokenMustNotRequireNonce() {
		
		new AuthenticationRequest.Builder(
			new ResponseType("code", "token"),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.build();
		
	}
	
	
	public void testCopyConstructorBuilder_requestObject()
		throws Exception {
		
		ClaimsRequest claims = new ClaimsRequest();
		claims.addIDTokenClaim("name");
		
		AuthenticationRequest in = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			new Scope("openid"),
			new ClientID("123"),
			new URI("https://example.com/cb"))
			.state(new State())
			.nonce(new Nonce())
			.display(Display.POPUP)
			.prompt(new Prompt(Prompt.Type.NONE))
			.dPoPJWKThumbprintConfirmation(new JWKThumbprintConfirmation(new Base64URL("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")))
			.trustChain(createSampleTrustChain())
			.maxAge(900)
			.uiLocales(LangTagUtils.parseLangTagList("en", "de"))
			.claimsLocales(LangTagUtils.parseLangTagList("fr", "bg"))
			.idTokenHint(JWTParser.parse(EXAMPLE_JWT_STRING))
			.loginHint("alice@wonderland.net")
			.acrValues(Arrays.asList(new ACR("0"), new ACR("1")))
			.claims(claims)
			.requestObject(JWTParser.parse(EXAMPLE_JWT_STRING))
			.responseMode(ResponseMode.FORM_POST)
			.codeChallenge(new CodeVerifier(), CodeChallengeMethod.S256)
			.authorizationDetails(Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("example_api")).build()))
			.customParameter("apples", "10")
			.endpointURI(new URI("https://c2id.com/login"))
			.build();
		
		AuthenticationRequest out = new AuthenticationRequest.Builder(in).build();
		
		assertEquals(in.getResponseType(), out.getResponseType());
		assertEquals(in.getScope(), out.getScope());
		assertEquals(in.getClientID(), out.getClientID());
		assertEquals(in.getRedirectionURI(), out.getRedirectionURI());
		assertEquals(in.getState(), out.getState());
		assertEquals(in.getNonce(), out.getNonce());
		assertEquals(in.getDisplay(), out.getDisplay());
		assertEquals(in.getPrompt(), out.getPrompt());
		assertEquals(in.getDPoPJWKThumbprintConfirmation(), out.getDPoPJWKThumbprintConfirmation());
		assertEquals(in.getTrustChain(), out.getTrustChain());
		assertEquals(in.getMaxAge(), out.getMaxAge());
		assertEquals(in.getUILocales(), out.getUILocales());
		assertEquals(in.getClaimsLocales(), out.getClaimsLocales());
		assertEquals(in.getIDTokenHint(), out.getIDTokenHint());
		assertEquals(in.getLoginHint(), out.getLoginHint());
		assertEquals(in.getACRValues(), out.getACRValues());
		assertEquals(in.getClaims().toJSONObject(), out.getClaims().toJSONObject());
		assertEquals(in.getOIDCClaims().toJSONObject(), out.getOIDCClaims().toJSONObject());
		assertEquals(in.getRequestObject(), out.getRequestObject());
		assertEquals(in.getRequestURI(), out.getRequestURI());
		assertEquals(in.getResponseMode(), out.getResponseMode());
		assertEquals(in.getCodeChallenge(), out.getCodeChallenge());
		assertEquals(in.getCodeChallengeMethod(), out.getCodeChallengeMethod());
		assertEquals(in.getAuthorizationDetails(), out.getAuthorizationDetails());
		assertEquals(in.getCustomParameters(), out.getCustomParameters());
		assertEquals(in.getEndpointURI(), out.getEndpointURI());
	}
	
	
	public void testCopyConstructorBuilder_requestURI()
		throws Exception {
		
		ClaimsRequest claims = new ClaimsRequest();
		claims.addIDTokenClaim("name");
		
		AuthenticationRequest in = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			new Scope("openid"),
			new ClientID("123"),
			new URI("https://example.com/cb"))
			.state(new State())
			.nonce(new Nonce())
			.display(Display.POPUP)
			.prompt(new Prompt(Prompt.Type.NONE))
			.dPoPJWKThumbprintConfirmation(new JWKThumbprintConfirmation(new Base64URL("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")))
			.trustChain(createSampleTrustChain())
			.maxAge(900)
			.uiLocales(LangTagUtils.parseLangTagList("en", "de"))
			.claimsLocales(LangTagUtils.parseLangTagList("fr", "bg"))
			.idTokenHint(JWTParser.parse(EXAMPLE_JWT_STRING))
			.loginHint("alice@wonderland.net")
			.acrValues(Arrays.asList(new ACR("0"), new ACR("1")))
			.claims(claims)
			.requestURI(new URI("https://example.com/request.jwt"))
			.responseMode(ResponseMode.FORM_POST)
			.codeChallenge(new CodeVerifier(), CodeChallengeMethod.S256)
			.authorizationDetails(Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("example_api")).build()))
			.customParameter("apples", "10")
			.endpointURI(new URI("https://c2id.com/login"))
			.build();
		
		AuthenticationRequest out = new AuthenticationRequest.Builder(in).build();
		
		assertEquals(in.getResponseType(), out.getResponseType());
		assertEquals(in.getScope(), out.getScope());
		assertEquals(in.getClientID(), out.getClientID());
		assertEquals(in.getRedirectionURI(), out.getRedirectionURI());
		assertEquals(in.getState(), out.getState());
		assertEquals(in.getNonce(), out.getNonce());
		assertEquals(in.getDisplay(), out.getDisplay());
		assertEquals(in.getPrompt(), out.getPrompt());
		assertEquals(in.getDPoPJWKThumbprintConfirmation(), out.getDPoPJWKThumbprintConfirmation());
		assertEquals(in.getTrustChain(), out.getTrustChain());
		assertEquals(in.getMaxAge(), out.getMaxAge());
		assertEquals(in.getUILocales(), out.getUILocales());
		assertEquals(in.getClaimsLocales(), out.getClaimsLocales());
		assertEquals(in.getIDTokenHint(), out.getIDTokenHint());
		assertEquals(in.getLoginHint(), out.getLoginHint());
		assertEquals(in.getACRValues(), out.getACRValues());
		assertEquals(in.getClaims().toJSONObject(), out.getClaims().toJSONObject());
		assertEquals(in.getOIDCClaims().toJSONObject(), out.getOIDCClaims().toJSONObject());
		assertEquals(in.getRequestObject(), out.getRequestObject());
		assertEquals(in.getRequestURI(), out.getRequestURI());
		assertEquals(in.getResponseMode(), out.getResponseMode());
		assertEquals(in.getCodeChallenge(), out.getCodeChallenge());
		assertEquals(in.getCodeChallengeMethod(), out.getCodeChallengeMethod());
		assertEquals(in.getAuthorizationDetails(), out.getAuthorizationDetails());
		assertEquals(in.getCustomParameters(), out.getCustomParameters());
		assertEquals(in.getEndpointURI(), out.getEndpointURI());
	}
	
	
	public void testQueryParamsInEndpoint()
		throws Exception {
		
		URI endpoint = new URI("https://c2id.com/login?foo=bar");
		
		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.endpointURI(endpoint)
			.build();
		
		// query parameters belonging to the authz endpoint not included here
		Map<String,List<String>> requestParameters = request.toParameters();
		assertEquals(Collections.singletonList("code"), requestParameters.get("response_type"));
		assertEquals(Collections.singletonList("123"), requestParameters.get("client_id"));
		assertEquals(Collections.singletonList("openid"), requestParameters.get("scope"));
		assertEquals(Collections.singletonList("https://example.com/cb"), requestParameters.get("redirect_uri"));
		assertEquals(4, requestParameters.size());
		
		Map<String,List<String>> queryParams = URLUtils.parseParameters(request.toQueryString());
		assertEquals(Collections.singletonList("bar"), queryParams.get("foo"));
		assertEquals(Collections.singletonList("code"), queryParams.get("response_type"));
		assertEquals(Collections.singletonList("123"), queryParams.get("client_id"));
		assertEquals(Collections.singletonList("openid"), queryParams.get("scope"));
		assertEquals(Collections.singletonList("https://example.com/cb"), queryParams.get("redirect_uri"));
		assertEquals(5, queryParams.size());
		
		URI redirectToAS = request.toURI();
		
		Map<String,List<String>> finalParameters = URLUtils.parseParameters(redirectToAS.getQuery());
		assertEquals(Collections.singletonList("bar"), finalParameters.get("foo"));
		assertEquals(Collections.singletonList("code"), finalParameters.get("response_type"));
		assertEquals(Collections.singletonList("123"), finalParameters.get("client_id"));
		assertEquals(Collections.singletonList("openid"), finalParameters.get("scope"));
		assertEquals(Collections.singletonList("https://example.com/cb"), finalParameters.get("redirect_uri"));
		assertEquals(5, finalParameters.size());
	}
	
	
	public void testToJWTClaimsSet() throws java.text.ParseException {
		
		AuthenticationRequest ar = new AuthenticationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.state(new State())
			.build();
		
		JWTClaimsSet jwtClaimsSet = ar.toJWTClaimsSet();
		
		assertEquals(ar.getResponseType().toString(), jwtClaimsSet.getStringClaim("response_type"));
		assertEquals(ar.getClientID().toString(), jwtClaimsSet.getStringClaim("client_id"));
		assertEquals(ar.getScope().toString(), jwtClaimsSet.getStringClaim("scope"));
		assertEquals(ar.getRedirectionURI().toString(), jwtClaimsSet.getStringClaim("redirect_uri"));
		assertEquals(ar.getState().toString(), jwtClaimsSet.getStringClaim("state"));
		
		assertEquals(5, jwtClaimsSet.getClaims().size());
	}
	
	
	public void testToJWTClaimsSet_withMaxAge() throws java.text.ParseException {
		
		AuthenticationRequest ar = new AuthenticationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.state(new State())
			.maxAge(3600)
			.build();
		
		JWTClaimsSet jwtClaimsSet = ar.toJWTClaimsSet();
		
		assertEquals(ar.getResponseType().toString(), jwtClaimsSet.getStringClaim("response_type"));
		assertEquals(ar.getClientID().toString(), jwtClaimsSet.getStringClaim("client_id"));
		assertEquals(ar.getScope().toString(), jwtClaimsSet.getStringClaim("scope"));
		assertEquals(ar.getRedirectionURI().toString(), jwtClaimsSet.getStringClaim("redirect_uri"));
		assertEquals(ar.getState().toString(), jwtClaimsSet.getStringClaim("state"));
		assertEquals(ar.getMaxAge(), jwtClaimsSet.getIntegerClaim("max_age").intValue());
		
		assertEquals(6, jwtClaimsSet.getClaims().size());
	}
	
	
	public void testToJWTClaimsSet_withMaxAge_withMultipleResourceParams() throws java.text.ParseException {
		
		AuthenticationRequest ar = new AuthenticationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.state(new State())
			.maxAge(3600)
			.resources(URI.create("https://one.rs.com"), URI.create("https://two.rs.com"))
			.build();
		
		JWTClaimsSet jwtClaimsSet = ar.toJWTClaimsSet();
		
		assertEquals(ar.getResponseType().toString(), jwtClaimsSet.getStringClaim("response_type"));
		assertEquals(ar.getClientID().toString(), jwtClaimsSet.getStringClaim("client_id"));
		assertEquals(ar.getScope().toString(), jwtClaimsSet.getStringClaim("scope"));
		assertEquals(ar.getRedirectionURI().toString(), jwtClaimsSet.getStringClaim("redirect_uri"));
		assertEquals(ar.getState().toString(), jwtClaimsSet.getStringClaim("state"));
		assertEquals(ar.getMaxAge(), jwtClaimsSet.getIntegerClaim("max_age").intValue());
		assertEquals(ar.getResources().get(0).toString(), jwtClaimsSet.getStringListClaim("resource").get(0));
		assertEquals(ar.getResources().get(1).toString(), jwtClaimsSet.getStringListClaim("resource").get(1));
		assertEquals(ar.getResources().size(), jwtClaimsSet.getStringListClaim("resource").size());
		
		assertEquals(7, jwtClaimsSet.getClaims().size());
	}
	
	
	public void testBuilder_requestURI_minimal() throws ParseException {
		
		URI endpointURI = URI.create("https://c2id.com/login");
		URI requestURI = URI.create("urn:requests:ahy4ohgo");
		ClientID clientID = new ClientID("123");
		
		AuthenticationRequest ar = new AuthenticationRequest.Builder(requestURI, clientID)
			.endpointURI(endpointURI)
			.build();
		
		assertEquals(endpointURI, ar.getEndpointURI());
		assertEquals(requestURI, ar.getRequestURI());
		assertEquals(clientID, ar.getClientID());
		
		assertTrue(ar.specifiesRequestObject());
		
		assertEquals(Collections.singletonList(requestURI.toString()), ar.toParameters().get("request_uri"));
		assertEquals(Collections.singletonList(clientID.getValue()), ar.toParameters().get("client_id"));
		assertEquals(2, ar.toParameters().size());
		
		ar = AuthenticationRequest.parse(ar.toURI());
		
		assertEquals(endpointURI, ar.getEndpointURI());
		assertEquals(requestURI, ar.getRequestURI());
		assertEquals(clientID, ar.getClientID());
	}
	
	
	public void testBuilder_requestURI_coreTopLevelParams() {
		
		URI requestURI = URI.create("urn:requests:ahy4ohgo");
		ResponseType rt = new ResponseType("code");
		Scope scope = new Scope("openid");
		ClientID clientID = new ClientID("123");
		URI redirectURI = URI.create("https://example.com/cb");
		
		AuthenticationRequest ar = new AuthenticationRequest.Builder(requestURI, clientID)
			.responseType(rt)
			.scope(scope)
			.redirectionURI(redirectURI)
			.build();
		
		assertEquals(requestURI, ar.getRequestURI());
		assertTrue(ar.specifiesRequestObject());
		
		assertEquals(rt, ar.getResponseType());
		assertEquals(scope, ar.getScope());
		assertEquals(clientID, ar.getClientID());
		assertEquals(redirectURI, ar.getRedirectionURI());
		
		try {
			new AuthenticationRequest.Builder(requestURI, clientID).responseType(null);
			fail("Core response_type when set not null");
		} catch (IllegalArgumentException e) {
			assertEquals("The response type must not be null", e.getMessage());
		}
		
		try {
			new AuthenticationRequest.Builder(requestURI, clientID).scope(null);
			fail("Core scope when set not null");
		} catch (IllegalArgumentException e) {
			assertEquals("The scope must not be null", e.getMessage());
		}
		
		try {
			new AuthenticationRequest.Builder(requestURI, clientID).scope(new Scope("email"));
			fail("Core scope when set must contain openid");
		} catch (IllegalArgumentException e) {
			assertEquals("The scope must include an openid value", e.getMessage());
		}
		
		try {
			new AuthenticationRequest.Builder(requestURI, clientID).redirectionURI(null);
			fail("Core redirection URI when set not null");
		} catch (IllegalArgumentException e) {
			assertEquals("The redirection URI must not be null", e.getMessage());
		}
	}
	
	
	public void testBuilder_requestObject_minimal() throws ParseException {
		
		URI endpointURI = URI.create("https://c2id.com/login");
		ResponseType rt = new ResponseType("code");
		Scope scope = new Scope("openid");
		ClientID clientID = new ClientID("123");
		URI redirectURI = URI.create("https://example.com/cb");
		
		AuthenticationRequest ar = new AuthenticationRequest.Builder(rt, scope, clientID, redirectURI)
			.endpointURI(endpointURI)
			.build();
		
		JWT requestObject = new PlainJWT(ar.toJWTClaimsSet());
		
		ar = new AuthenticationRequest.Builder(requestObject, clientID)
			.endpointURI(endpointURI)
			.build();
		
		assertEquals(endpointURI, ar.getEndpointURI());
		assertEquals(requestObject, ar.getRequestObject());
		assertEquals(clientID, ar.getClientID());
		
		assertEquals(Collections.singletonList(requestObject.serialize()), ar.toParameters().get("request"));
		assertEquals(Collections.singletonList(clientID.getValue()), ar.toParameters().get("client_id"));
		
		ar = AuthenticationRequest.parse(ar.toURI());
		
		assertEquals(endpointURI, ar.getEndpointURI());
		assertEquals(requestObject.serialize(), ar.getRequestObject().serialize());
		assertEquals(clientID, ar.getClientID());
	}
	
	
	public void testRequestObject_hybridFlow_formPost() throws Exception {
		
		Issuer op = new Issuer("https://c2id.com");
		ClientID clientID = new ClientID("kgt26u4ulfdxm");
		ResponseType rt = new ResponseType("id_token", "token");
		Scope scope = new Scope("openid");
		URI redirectURI = URI.create("https://example.com/cb");
		ResponseMode rm = ResponseMode.FORM_POST;
		State state = new State();
		Nonce nonce = new Nonce();
		
		AuthenticationRequest securedRequest = new AuthenticationRequest.Builder(rt, scope, clientID, redirectURI)
			.responseMode(rm)
			.state(state)
			.nonce(nonce)
			.build();
		
		Date exp = new Date((new Date().getTime() / 1000 * 1000) + 60_000L);
		JWTClaimsSet jarClaims = new JWTClaimsSet.Builder(securedRequest.toJWTClaimsSet())
			.expirationTime(exp)
			.audience(op.getValue())
			.build();
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.algorithm(JWSAlgorithm.RS256)
			.keyID("IzTEeEuALnxGiWD_5caM1GHX0Cs")
			.generate();
		SignedJWT jar = new SignedJWT(new JWSHeader.Builder((JWSAlgorithm) rsaJWK.getAlgorithm()).keyID(rsaJWK.getKeyID()).build(), jarClaims);
		jar.sign(new RSASSASigner(rsaJWK));
		
		AuthenticationRequest jarRequest = new AuthenticationRequest.Builder(jar, clientID).build();
		
		Map<String,List<String>> params = jarRequest.toParameters();
		
		// Selected top level params
		params.put("scope", Collections.singletonList(scope.toString()));
		params.put("response_type", Collections.singletonList(rt.toString()));
		params.put("client_id", Collections.singletonList(clientID.getValue()));
		
		AuthenticationRequest ar = AuthenticationRequest.parse(params);
		
		assertEquals(jar.serialize(), ar.getRequestObject().serialize());
		assertEquals(clientID, ar.getClientID());
		assertEquals(scope, ar.getScope());
		assertEquals(rt, ar.getResponseType());
		assertEquals(4, ar.toParameters().size());
	}
	
	
	public void testBuilder_nullResponseType() {
		
		try {
			new AuthenticationRequest.Builder(null, new Scope("openid"), new ClientID("123"), URI.create("https://example.com/cb"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The response type must not be null", e.getMessage());
		}
	}
	
	
	public void testBuilder_nullScope() {
		
		try {
			new AuthenticationRequest.Builder(new ResponseType("code"), null, new ClientID("123"), URI.create("https://example.com/cb"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The scope must not be null", e.getMessage());
		}
	}
	
	
	public void testBuilder_missingOpenIDScopeValue() {
		
		try {
			new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("email"), new ClientID("123"), URI.create("https://example.com/cb"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The scope must include an \"openid\" value", e.getMessage());
		}
	}
	
	
	public void testBuilder_nullClientID() {
		
		try {
			new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"), null, URI.create("https://example.com/cb"));
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}


	public void testRAR() throws ParseException {

		ResponseType responseType = ResponseType.CODE;
		ClientID clientID = new ClientID("123");
		Scope scope = new Scope("openid");
		URI redirectURI = URI.create("https://example.com/cb");
		List<AuthorizationDetail> authorizationDetails = Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("api_1")).build());

		AuthenticationRequest request = new AuthenticationRequest.Builder(responseType, scope, clientID, redirectURI)
			.authorizationDetails(authorizationDetails)
			.build();

		Map<String, List<String>> parameters = request.toParameters();

		assertEquals(Collections.singletonList(responseType.toString()), parameters.get("response_type"));
		assertEquals(Collections.singletonList(scope.toString()), parameters.get("scope"));
		assertEquals(Collections.singletonList(clientID.getValue()), parameters.get("client_id"));
		assertEquals(Collections.singletonList(redirectURI.toString()), parameters.get("redirect_uri"));
		assertEquals(Collections.singletonList(AuthorizationDetail.toJSONString(authorizationDetails)), parameters.get("authorization_details"));
		assertEquals(5, parameters.size());

		request = AuthenticationRequest.parse(parameters);

		assertEquals(responseType, request.getResponseType());
		assertEquals(scope, request.getScope());
		assertEquals(clientID, request.getClientID());
		assertEquals(redirectURI, request.getRedirectionURI());
		assertEquals(authorizationDetails, request.getAuthorizationDetails());
		assertEquals(5, request.toParameters().size());
	}


	public void testRAR_parseException_missingType() {

		ResponseType responseType = ResponseType.CODE;
		ClientID clientID = new ClientID("123");
		Scope scope = new Scope("openid");
		URI redirectURI = URI.create("https://example.com/cb");

		AuthenticationRequest request = new AuthenticationRequest.Builder(responseType, scope, clientID, redirectURI)
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
		Scope scope = new Scope("openid");
		URI redirectURI = URI.create("https://example.com/cb");

		AuthenticationRequest request = new AuthenticationRequest.Builder(responseType, scope, clientID, redirectURI)
			.build();

		Map<String, List<String>> parameters = request.toParameters();
		parameters.put("authorization_details", Collections.singletonList("xxx"));

		try {
			AuthenticationRequest.parse(parameters);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid authorization details: Invalid JSON", e.getMessage());
		}
	}
	
	
	// dpop
	public void testDPoP() throws ParseException {
		
		JWKThumbprintConfirmation dpopJKT = new JWKThumbprintConfirmation(new Base64URL("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"));
		
		AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.endpointURI(URI.create("https://c2id.com/login"))
			.dPoPJWKThumbprintConfirmation(dpopJKT)
			.build();
		
		assertEquals(dpopJKT, authRequest.getDPoPJWKThumbprintConfirmation());
		
		Map<String, List<String>> params = authRequest.toParameters();
		
		assertEquals(Collections.singletonList("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"), params.get("dpop_jkt"));
		
		authRequest = AuthenticationRequest.parse(params);
		
		assertEquals(dpopJKT, authRequest.getDPoPJWKThumbprintConfirmation());
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
		
		ResponseType responseType = ResponseType.CODE;
		Scope scope = new Scope("openid");
		ClientID clientID = new ClientID("123");
		URI redirectURI = URI.create("https://example.com/cb");
		TrustChain trustChain = createSampleTrustChain();
		
		AuthenticationRequest request = new AuthenticationRequest.Builder(responseType, scope, clientID, redirectURI)
			.endpointURI(URI.create("https://c2id.com/login"))
			.trustChain(trustChain)
			.build();
		
		assertEquals(responseType, request.getResponseType());
		assertEquals(scope, request.getScope());
		assertEquals(clientID, request.getClientID());
		assertEquals(redirectURI, request.getRedirectionURI());
		assertEquals(trustChain.toSerializedJWTs(), request.getTrustChain().toSerializedJWTs());
		
		Map<String, List<String>> params = request.toParameters();
		
		assertEquals(Collections.singletonList(responseType.toString()), params.get("response_type"));
		assertEquals(Collections.singletonList(scope.toString()), params.get("scope"));
		assertEquals(Collections.singletonList(clientID.getValue()), params.get("client_id"));
		assertEquals(Collections.singletonList(redirectURI.toString()), params.get("redirect_uri"));
		
		JSONArray trustChainArray = new JSONArray();
		trustChainArray.addAll(trustChain.toSerializedJWTs());
		assertEquals(Collections.singletonList(trustChainArray.toJSONString()), params.get("trust_chain"));
		
		assertEquals(5, params.size());
		
		request = AuthenticationRequest.parse(request.toURI());
		
		assertEquals(responseType, request.getResponseType());
		assertEquals(scope, request.getScope());
		assertEquals(clientID, request.getClientID());
		assertEquals(redirectURI, request.getRedirectionURI());
		assertEquals(trustChain.toSerializedJWTs(), request.getTrustChain().toSerializedJWTs());
		
		assertEquals(5, request.toParameters().size());
	}
	
	
	public void testParse_trustChainParseException() throws JOSEException {
		
		ResponseType responseType = ResponseType.CODE;
		Scope scope = new Scope("openid");
		ClientID clientID = new ClientID("123");
		URI redirectURI = URI.create("https://example.com/cb");
		TrustChain trustChain = createSampleTrustChain();
		
		AuthenticationRequest request = new AuthenticationRequest.Builder(responseType, scope, clientID, redirectURI)
			.endpointURI(URI.create("https://c2id.com/login"))
			.trustChain(trustChain)
			.build();
		
		Map<String, List<String>> params = request.toParameters();
		
		params.put("trust_chain", Collections.singletonList("[\"abc\"]"));
		
		try {
			AuthenticationRequest.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JWT in trust chain: Invalid serialized unsecured/JWS/JWE object: Missing part delimiters", e.getMessage());
		}
	}
	
	
	// purpose
	public void testPurposeParameter() throws LangTagException, ParseException {
		
		CodeVerifier pkceVerifier = new CodeVerifier();
		
		AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.endpointURI(URI.create("https://c2id.com/login"))
			.codeChallenge(pkceVerifier, CodeChallengeMethod.S256)
			.uiLocales(Collections.singletonList(new LangTag("en")))
			.purpose("Account holder identification")
			.build();
		
		assertEquals("Account holder identification", authRequest.getPurpose());
		
		Map<String,List<String>> params = authRequest.toParameters();
		assertEquals(Collections.singletonList("Account holder identification"), params.get("purpose"));
		
		URI request = authRequest.toURI();
		
		authRequest = AuthenticationRequest.parse(request);
		
		assertEquals("Account holder identification", authRequest.getPurpose());
	}
	
	
	public void testPurposeLimitConstants() {
		
		assertEquals(3, AuthenticationRequest.PURPOSE_MIN_LENGTH);
		assertEquals(300, AuthenticationRequest.PURPOSE_MAX_LENGTH);
	}
	
	
	public void testPurposeMinLength() throws ParseException {
		
		AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.endpointURI(URI.create("https://c2id.com/login"))
			.purpose("abc")
			.build();
		
		assertEquals("abc", authRequest.getPurpose());
		
		authRequest = AuthenticationRequest.parse(authRequest.toURI());
		
		assertEquals("abc", authRequest.getPurpose());
	}
	
	
	public void testPurposeMaxLength() throws ParseException {
		
		String purpose = RandomStringUtils.random(300);
		assertEquals(300, purpose.length());
		
		AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.endpointURI(URI.create("https://c2id.com/login"))
			.purpose(purpose)
			.build();
		
		assertEquals(purpose, authRequest.getPurpose());
		
		authRequest = AuthenticationRequest.parse(authRequest.toURI());
		
		assertEquals(purpose, authRequest.getPurpose());
	}
	
	
	public void testPurposeTooShort() {
		
		try {
			new AuthenticationRequest.Builder(
				new ResponseType(ResponseType.Value.CODE),
				new Scope("openid"),
				new ClientID("123"),
				URI.create("https://example.com/cb"))
				.endpointURI(URI.create("https://c2id.com/login"))
				.purpose("ab")
				.build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("The purpose must not be shorter than 3 characters", e.getMessage());
		}
	}
	
	
	public void testPurposeTooLong() {
		
		String purpose = RandomStringUtils.random(301);
		assertEquals(301, purpose.length());
		
		try {
			new AuthenticationRequest.Builder(
				new ResponseType(ResponseType.Value.CODE),
				new Scope("openid"),
				new ClientID("123"),
				URI.create("https://example.com/cb"))
				.endpointURI(URI.create("https://c2id.com/login"))
				.purpose(purpose)
				.build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("The purpose must not be longer than 300 characters", e.getMessage());
		}
	}
	
	
	public void testPurposeParseTooShort() {
		
		AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.endpointURI(URI.create("https://c2id.com/login"))
			.state(new State())
			.build();
		
		Map<String,List<String>> params = authRequest.toParameters();
		
		params.put("purpose", Collections.singletonList("ab"));
		
		try {
			AuthenticationRequest.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid purpose parameter: Must not be shorter than 3 and longer than 300 characters", e.getMessage());
			assertEquals(authRequest.getState(), e.getState());
			assertEquals(authRequest.getClientID(), e.getClientID());
			assertEquals(authRequest.getRedirectionURI(), e.getRedirectionURI());
			assertEquals("invalid_request", e.getErrorObject().getCode());
			assertEquals("Invalid request: Invalid purpose parameter: Must not be shorter than 3 and longer than 300 characters", e.getErrorObject().getDescription());
		}
		
		params.put("purpose", Collections.singletonList(RandomStringUtils.random(301)));
		
		try {
			AuthenticationRequest.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid purpose parameter: Must not be shorter than 3 and longer than 300 characters", e.getMessage());
			assertEquals(authRequest.getState(), e.getState());
			assertEquals(authRequest.getClientID(), e.getClientID());
			assertEquals(authRequest.getRedirectionURI(), e.getRedirectionURI());
			assertEquals("invalid_request", e.getErrorObject().getCode());
			assertEquals("Invalid request: Invalid purpose parameter: Must not be shorter than 3 and longer than 300 characters", e.getErrorObject().getDescription());
		}
	}
	
	
	public void testIdentityAssurance_basicExample()
		throws Exception {
		
		OIDCClaimsRequest claimsRequest = new OIDCClaimsRequest()
			.withUserInfoVerifiedClaimsRequest(
				new VerifiedClaimsSetRequest()
				.add("given_name")
				.add("family_name")
				.add("address")
			);
		
		CodeVerifier pkceVerifier = new CodeVerifier();
		
		AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new Scope(OIDCScopeValue.OPENID),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.state(new State("7a4b68ab-5315-4e25-a10f-0fbfaa36d6c7"))
			.codeChallenge(pkceVerifier, CodeChallengeMethod.S256)
			.claims(claimsRequest)
			.uiLocales(Collections.singletonList(new LangTag("en")))
			.purpose("Account holder identification")
			.endpointURI(URI.create("https://c2id.com/authz"))
			.build();
		
		authRequest = AuthenticationRequest.parse(authRequest.toURI());
		
		assertEquals(claimsRequest.toJSONObject(), authRequest.getOIDCClaims().toJSONObject());
		assertEquals(claimsRequest.toJSONObject(), authRequest.getClaims().toJSONObject());
		
		assertEquals(Collections.singletonList(new LangTag("en")), authRequest.getUILocales());
		assertEquals("Account holder identification", authRequest.getPurpose());
		assertEquals(claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getClaimNames(false), authRequest.getOIDCClaims().getUserInfoVerifiedClaimsRequestList().get(0).getClaimNames(false));
		assertEquals(claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getVerificationJSONObject(), authRequest.getOIDCClaims().getUserInfoVerifiedClaimsRequestList().get(0).getVerificationJSONObject());
	}
	
	
	public void testIdentityAssurance_basicExample_deprecatedAPI()
		throws Exception {
		
		JSONObject verification = new JSONObject();
		verification.put("trust_framework", null);
		
		OIDCClaimsRequest claimsRequest = new OIDCClaimsRequest()
			.withUserInfoVerifiedClaimsRequest(
				new com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSetRequest()
				.add("given_name")
				.add("family_name")
				.add("address")
				.withVerificationJSONObject(verification)
			);
		
		CodeVerifier pkceVerifier = new CodeVerifier();
		
		AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new Scope(OIDCScopeValue.OPENID),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.state(new State("7a4b68ab-5315-4e25-a10f-0fbfaa36d6c7"))
			.codeChallenge(pkceVerifier, CodeChallengeMethod.S256)
			.claims(claimsRequest)
			.uiLocales(Collections.singletonList(new LangTag("en")))
			.purpose("Account holder identification")
			.endpointURI(URI.create("https://c2id.com/authz"))
			.build();
		
		authRequest = AuthenticationRequest.parse(authRequest.toURI());
		
		assertEquals(claimsRequest.toJSONObject(), authRequest.getOIDCClaims().toJSONObject());
		assertEquals(claimsRequest.toJSONObject(), authRequest.getClaims().toJSONObject());
		
		assertEquals(Collections.singletonList(new LangTag("en")), authRequest.getUILocales());
		assertEquals("Account holder identification", authRequest.getPurpose());
		assertEquals(claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getClaimNames(false), authRequest.getOIDCClaims().getUserInfoVerifiedClaimsRequestList().get(0).getClaimNames(false));
		assertEquals(claimsRequest.getUserInfoVerifiedClaimsRequestList().get(0).getVerificationJSONObject(), authRequest.getOIDCClaims().getUserInfoVerifiedClaimsRequestList().get(0).getVerificationJSONObject());
	}
	
	
	public void testIdentityAssurance_verificationElement()
		throws Exception {
		
		OIDCClaimsRequest claimsRequest = new OIDCClaimsRequest()
			.withUserInfoClaimsRequest(new ClaimsSetRequest()
				.add("family_name")
			)
			.withUserInfoVerifiedClaimsRequest(
				new VerifiedClaimsSetRequest()
					.withVerification(new MinimalVerificationSpec(IdentityTrustFramework.DE_AML))
					.add("given_name")
			);
		
		AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new Scope("openid"),
			new ClientID("123"),
			new URI("https://client.com/callback"))
			.state(new State())
			.claims(claimsRequest)
			.build();
		
		AuthenticationRequest parsed = AuthenticationRequest.parse(authRequest.toParameters());
		
		assertEquals(claimsRequest.toJSONObject(), parsed.getOIDCClaims().toJSONObject());
	}
	
	
	public void testIdentityAssurance_basicExample_deprecated()
		throws Exception {
		
		JSONObject verification = new JSONObject();
		verification.put("trust_framework", null);
		
		ClaimsRequest claimsRequest = new ClaimsRequest();
		claimsRequest.setUserInfoClaimsVerificationJSONObject(verification);
		claimsRequest.addVerifiedUserInfoClaim(new ClaimsRequest.Entry("given_name"));
		claimsRequest.addVerifiedUserInfoClaim(new ClaimsRequest.Entry("family_name"));
		claimsRequest.addVerifiedUserInfoClaim(new ClaimsRequest.Entry("address"));
		
		CodeVerifier pkceVerifier = new CodeVerifier();
		
		AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new Scope(OIDCScopeValue.OPENID),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.state(new State("7a4b68ab-5315-4e25-a10f-0fbfaa36d6c7"))
			.codeChallenge(pkceVerifier, CodeChallengeMethod.S256)
			.claims(claimsRequest)
			.uiLocales(Collections.singletonList(new LangTag("en")))
			.purpose("Account holder identification")
			.endpointURI(URI.create("https://c2id.com/authz"))
			.build();
		
//		System.out.println(authRequest.toURI());
		
		authRequest = AuthenticationRequest.parse(authRequest.toURI());
		
		assertEquals(claimsRequest.toJSONObject(), authRequest.getClaims().toJSONObject());
		
		assertEquals(Collections.singletonList(new LangTag("en")), authRequest.getUILocales());
		assertEquals("Account holder identification", authRequest.getPurpose());
		assertEquals(claimsRequest.getVerifiedUserInfoClaimNames(false), authRequest.getClaims().getVerifiedUserInfoClaimNames(false));
		assertEquals(claimsRequest.getUserInfoClaimsVerificationJSONObject(), authRequest.getClaims().getUserInfoClaimsVerificationJSONObject());
	}
	
	
	public void testIdentityAssurance_verificationElement_deprecated()
		throws Exception {
		
		ClaimsRequest claimsRequest = new ClaimsRequest();
		claimsRequest.addUserInfoClaim("family_name");
		claimsRequest.addVerifiedUserInfoClaim(new ClaimsRequest.Entry("given_name"));
		JSONObject verification = new JSONObject();
		JSONObject tfSpec = new JSONObject();
		tfSpec.put("value", IdentityTrustFramework.DE_AML.getValue());
		verification.put("trust_framework", tfSpec);
		claimsRequest.setUserInfoClaimsVerificationJSONObject(verification);
		
		AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new Scope("openid"),
			new ClientID("123"),
			new URI("https://client.com/callback"))
			.state(new State())
			.claims(claimsRequest)
			.build();
		
		AuthenticationRequest parsed = AuthenticationRequest.parse(authRequest.toParameters());
		
		assertEquals(claimsRequest.toJSONObject(), parsed.getClaims().toJSONObject());
	}
	
	
	public void testIdentityAssurance_invalidRequestOnEmptyClaimsObject()
		throws Exception {
		
		AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new Scope("openid"),
			new ClientID("123"),
			new URI("https://client.com/callback"))
			.state(new State())
			.build();
		
		String claimsJSON = "{"+
			"\"userinfo\":{" +
			"\"verified_claims\":{" +
			"\"verification\":{" +
			"\"trust_framework\":null" +
			"}," +
			"\"claims\":{}" +
			"}" +
			"}" +
			"}";
		
		Map<String,List<String>> params = authRequest.toParameters();
		params.put("claims", Collections.singletonList(claimsJSON));
		
		try {
			AuthenticationRequest.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid claims parameter: Invalid verified claims request: Empty verified claims object", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST, e.getErrorObject());
			assertEquals("Invalid request: Invalid claims parameter: Invalid verified claims request: Empty verified claims object", e.getErrorObject().getDescription());
		}
	}
	
	
	public void testFAPIExample()
		throws Exception {
		
		// Create the client RSA public / private key pair and store it securely.
		// The same key can be used to create the self-signed client certificate
		// for mTLS client authentication at the token endpoint and receiving
		// client certificate bound tokens
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.keyUse(KeyUse.SIGNATURE)
			.algorithm(JWSAlgorithm.PS256)
			.keyIDFromThumbprint(true)
			.generate();
		
		// The required OpenID provider parameters
		URI authorizationEndpoint = new URI("https://c2id.com/login");
		
		// Required client parameters from the OpenID relying party registration
		ClientID clientID = new ClientID("123");
		URI redirectURI = new URI("https://example.com/cb");
		JWSAlgorithm requestObjectJWSAlg = JWSAlgorithm.PS256;
		
		// Construct the OpenID authentication request whose parameters
		// are going to be signed
		
		// Generate unique state to pair the callback to this request
		State state = new State();
		
		// Generate unique nonce for the ID token
		Nonce nonce = new Nonce();
		
		AuthenticationRequest securedRequest = new AuthenticationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN),
			new Scope("openid", "https://scopes.c2id.com/account"),
			clientID,
			redirectURI)
			.nonce(nonce)
			.state(state)
			.acrValues(Collections.singletonList(new ACR("https://trust-frameworks.c2id.com/high")))
			.build();
		
		// Convert params to JWT and sign with the client RSA key
		JWTClaimsSet jwtClaimsSet = securedRequest.toJWTClaimsSet();
//		System.out.println(jwtClaimsSet.toJSONObject());
		
		SignedJWT requestJWT = new SignedJWT(
			new JWSHeader.Builder(
				requestObjectJWSAlg)
				.keyID(rsaJWK.getKeyID())
			.build(),
			jwtClaimsSet);
		
		JWSSigner jwsSigner = new RSASSASigner(rsaJWK);
		// May need an alternative JCA provider for JWS PS256 if the
		// RSA algorithm isn't supported by the default JCA provider
		jwsSigner.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		requestJWT.sign(jwsSigner);
		
		// Construct the final OpenID authentication request which
		// includes the signed parameters in a JWT; some top-level
		// query parameters are repeated to ensure the request still
		// parses an OpenID authentication request
		AuthenticationRequest finalRequest = new AuthenticationRequest.Builder(
			securedRequest.getResponseType(),
			new Scope("openid"),
			securedRequest.getClientID(),
			securedRequest.getRedirectionURI())
			.requestObject(requestJWT)
			.endpointURI(authorizationEndpoint)
			.build();
		
		// Output as URI to send the end-user to the OpenID provider
//		System.out.println(finalRequest.toURI());
	}
	
	
	public void testFederation_requestObject()
		throws Exception {
		
		// The OpenID provider authorisation endpoint
		URI endpoint = new URI("https://op.umu.se/authorize");

		// The client_id must be set to the entity ID of the relying party (RP)
		ClientID clientID = new ClientID("https://wiki.ligo.org");

		// Key pair belonging to the RP entity
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.keyUse(KeyUse.SIGNATURE)
			.algorithm(JWSAlgorithm.RS256)
			.keyIDFromThumbprint(true)
			.generate();

		// Build the OpenID authentication request
		AuthenticationRequest request = new AuthenticationRequest.Builder(
			new ResponseType("code"),
			new Scope("openid", "profile", "email"),
			clientID,
			new URI("https://wiki.ligo.org/openid/callback"))
			.state(new State("em9Yah2eevathieh"))
			.nonce(new Nonce("the5Sha1Aeraete1"))
			.endpointURI(endpoint)
			.build();
		
		// Convert the OpenID authentication request to a JWT claims set
		// and append the required 'iss', 'aud', 'sub', 'jti' and 'exp'
		// claims
		Date now = new Date();
		Date exp = DateUtils.fromSecondsSinceEpoch(DateUtils.toSecondsSinceEpoch(now) + 60);
		JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder(request.toJWTClaimsSet())
			.issuer(clientID.getValue())
			.audience(endpoint.toString())
			// .subject(clientID.getValue()) prohibited: https://tools.ietf.org/html/draft-ietf-oauth-jwsreq-29#section-10.8
			.jwtID(new JWTID().getValue())
			.expirationTime(exp)
			.build();
		
		// Sign the request object JWT with the RP entity private key
		SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(
			(JWSAlgorithm)rsaJWK.getAlgorithm())
			.keyID(rsaJWK.getKeyID())
			.build(),
			jwtClaimsSet);
		jwt.sign(new RSASSASigner(rsaJWK));
		
		// Compose the final OpenID authentication request with the
		// request object JWT the minimal other required top-level
		// parameters
		request = new AuthenticationRequest.Builder(jwt, clientID)
			.responseType(request.getResponseType())
			.scope(request.getScope())
			.endpointURI(endpoint)
			.build();
		
//		System.out.println(request.toURI());
	}


	public void testToHTTPRequest_POST_thenParse() throws ParseException {

		AuthenticationRequest request = new AuthenticationRequest(
			URI.create("https://c2id.com/login"),
			ResponseType.CODE,
			new Scope("openid"),
			new ClientID(),
			URI.create("https://example.com/cb"),
			new State(),
			new Nonce());

		HTTPRequest httpRequest = request.toHTTPRequest(HTTPRequest.Method.POST);
		assertEquals(request.getEndpointURI(), httpRequest.getURI());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_URLENCODED, httpRequest.getEntityContentType());
		assertEquals(request.toParameters(), httpRequest.getBodyAsFormParameters());

		assertEquals(request.toURI(), AuthenticationRequest.parse(httpRequest).toURI());
	}


	public void testToHTTPRequest_GET_thenParse() throws ParseException {

		AuthenticationRequest request = new AuthenticationRequest(
			URI.create("https://c2id.com/login"),
			ResponseType.CODE,
			new Scope("openid"),
			new ClientID(),
			URI.create("https://example.com/cb"),
			new State(),
			new Nonce());

		HTTPRequest httpRequest = request.toHTTPRequest(HTTPRequest.Method.GET);
		assertEquals(request.getEndpointURI(), URIUtils.getBaseURI(httpRequest.getURI()));
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertNull(httpRequest.getEntityContentType());
		assertNull(httpRequest.getBody());
		assertEquals(request.toParameters(), httpRequest.getQueryStringParameters());

		assertEquals(request.toURI(), AuthenticationRequest.parse(httpRequest).toURI());
	}


	public void testToHTTPRequest_unexpectedMethod() {

		AuthenticationRequest request = new AuthenticationRequest(
			URI.create("https://c2id.com/login"),
			ResponseType.CODE,
			new Scope("openid"),
			new ClientID(),
			URI.create("https://example.com/cb"),
			new State(),
			new Nonce());

		try {
			request.toHTTPRequest(HTTPRequest.Method.PUT);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("HTTP GET or POST expected", e.getMessage());
		}
	}


	public void testParseHTTPRequest_unexpectedMethod() {

		AuthenticationRequest request = new AuthenticationRequest(
			URI.create("https://c2id.com/login"),
			ResponseType.CODE,
			new Scope("openid"),
			new ClientID(),
			URI.create("https://example.com/cb"),
			new State(),
			new Nonce());

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.PUT, request.getEndpointURI());
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody(URLUtils.serializeParameters(request.toParameters()));

		try {
			AuthenticationRequest.parse(httpRequest).toURI();
			fail();
		} catch (ParseException e) {
			assertEquals("HTTP GET or POST expected", e.getMessage());
		}
	}
}