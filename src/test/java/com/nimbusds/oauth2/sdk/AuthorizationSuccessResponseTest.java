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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.jarm.JARMUtils;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import junit.framework.TestCase;

import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;


public class AuthorizationSuccessResponseTest extends TestCase {
	
	
	private static final URI ABS_REDIRECT_URI = URI.create("https://client.example.org/cb");


	private static final AuthorizationCode CODE = new AuthorizationCode("SplxlOBeZQQYbYS6WxSbIA");


	private static final AccessToken TOKEN = new BearerAccessToken("2YotnFZFEjr1zCsicMWpAA", 3600, null, null);


	private static final State STATE = new State();
	
	
	private static final Issuer ISSUER = new Issuer("https://login.c2id.com");
	
	
	private static final ClientID CLIENT_ID = new ClientID("123");
	
	
	public void testCodeFlow()
		throws Exception {
	
		AuthorizationSuccessResponse resp = new AuthorizationSuccessResponse(ABS_REDIRECT_URI, CODE, null, STATE, null);

		assertTrue(resp.indicatesSuccess());
		assertEquals(ABS_REDIRECT_URI, resp.getRedirectionURI());
		assertEquals(CODE, resp.getAuthorizationCode());
		assertEquals(STATE, resp.getState());
		assertNull(resp.getIssuer());
		assertNull(resp.getAccessToken());
		assertNull(resp.getResponseMode());

		ResponseType responseType = resp.impliedResponseType();
		assertEquals(new ResponseType("code"), responseType);

		assertEquals(ResponseMode.QUERY, resp.impliedResponseMode());

		Map<String,List<String>> params = resp.toParameters();
		assertEquals(CODE, new AuthorizationCode(MultivaluedMapUtils.getFirstValue(params, "code")));
		assertEquals(STATE, new State(MultivaluedMapUtils.getFirstValue(params,"state")));
		assertEquals(2, params.size());

		URI uri = resp.toURI();

		HTTPResponse httpResponse = resp.toHTTPResponse();
		assertEquals(302, httpResponse.getStatusCode());
		assertEquals(uri.toString(), httpResponse.getLocation().toString());

		resp = AuthorizationSuccessResponse.parse(httpResponse);

		assertTrue(resp.indicatesSuccess());
		assertEquals(ABS_REDIRECT_URI, resp.getRedirectionURI());
		assertEquals(CODE, resp.getAuthorizationCode());
		assertEquals(STATE, resp.getState());
		assertNull(resp.getIssuer());
		assertNull(resp.getAccessToken());
		assertNull(resp.getResponseMode());

		assertEquals(ResponseMode.QUERY, resp.impliedResponseMode());
	}
	
	
	public void testCodeFlowWithIssuer()
		throws Exception {
	
		AuthorizationSuccessResponse resp = new AuthorizationSuccessResponse(ABS_REDIRECT_URI, CODE, null, STATE, ISSUER, null);

		assertTrue(resp.indicatesSuccess());
		assertEquals(ABS_REDIRECT_URI, resp.getRedirectionURI());
		assertEquals(CODE, resp.getAuthorizationCode());
		assertEquals(STATE, resp.getState());
		assertEquals(ISSUER, resp.getIssuer());
		assertNull(resp.getAccessToken());
		assertNull(resp.getResponseMode());

		ResponseType responseType = resp.impliedResponseType();
		assertEquals(new ResponseType("code"), responseType);

		assertEquals(ResponseMode.QUERY, resp.impliedResponseMode());

		Map<String,List<String>> params = resp.toParameters();
		assertEquals(CODE, new AuthorizationCode(MultivaluedMapUtils.getFirstValue(params, "code")));
		assertEquals(STATE, new State(MultivaluedMapUtils.getFirstValue(params,"state")));
		assertEquals(ISSUER, new Issuer(MultivaluedMapUtils.getFirstValue(params,"iss")));
		assertEquals(3, params.size());

		URI uri = resp.toURI();

		HTTPResponse httpResponse = resp.toHTTPResponse();
		assertEquals(302, httpResponse.getStatusCode());
		assertEquals(uri.toString(), httpResponse.getLocation().toString());

		resp = AuthorizationSuccessResponse.parse(httpResponse);

		assertTrue(resp.indicatesSuccess());
		assertEquals(ABS_REDIRECT_URI, resp.getRedirectionURI());
		assertEquals(CODE, resp.getAuthorizationCode());
		assertEquals(STATE, resp.getState());
		assertEquals(ISSUER, resp.getIssuer());
		assertNull(resp.getAccessToken());
		assertNull(resp.getResponseMode());

		assertEquals(ResponseMode.QUERY, resp.impliedResponseMode());
	}


	public void testImplicitFlow()
		throws Exception {
	
		AuthorizationSuccessResponse resp = new AuthorizationSuccessResponse(ABS_REDIRECT_URI, null, TOKEN, STATE, null);

		assertTrue(resp.indicatesSuccess());
		assertEquals(ABS_REDIRECT_URI, resp.getRedirectionURI());
		assertEquals(TOKEN, resp.getAccessToken());
		assertEquals(3600, resp.getAccessToken().getLifetime());
		assertEquals(STATE, resp.getState());
		assertNull(resp.getAuthorizationCode());
		assertNull(resp.getResponseMode());

		ResponseType responseType = resp.impliedResponseType();
		assertEquals(new ResponseType("token"), responseType);

		assertEquals(ResponseMode.FRAGMENT, resp.impliedResponseMode());

		Map<String,List<String>> params = resp.toParameters();
		assertEquals(TOKEN.getValue(), MultivaluedMapUtils.getFirstValue(params,"access_token"));
		assertEquals(STATE, new State(MultivaluedMapUtils.getFirstValue(params, "state")));
		assertEquals(TOKEN.getType(), new AccessTokenType(MultivaluedMapUtils.getFirstValue(params,"token_type")));
		assertEquals("3600", MultivaluedMapUtils.getFirstValue(params, "expires_in"));
		assertEquals(4, params.size());

		URI uri = resp.toURI();

		HTTPResponse httpResponse = resp.toHTTPResponse();
		assertEquals(302, httpResponse.getStatusCode());
		assertEquals(uri, httpResponse.getLocation());

		resp = AuthorizationSuccessResponse.parse(httpResponse);

		assertTrue(resp.indicatesSuccess());
		assertEquals(ABS_REDIRECT_URI, resp.getRedirectionURI());
		assertEquals(TOKEN, resp.getAccessToken());
		assertEquals(3600, resp.getAccessToken().getLifetime());
		assertEquals(STATE, resp.getState());
		assertNull(resp.getAuthorizationCode());
		assertNull(resp.getResponseMode());

		assertEquals(ResponseMode.FRAGMENT, resp.impliedResponseMode());
	}


	public void testResponseModeFormPost()
		throws Exception {

		AuthorizationSuccessResponse resp = new AuthorizationSuccessResponse(
			ABS_REDIRECT_URI,
			null,
			TOKEN,
			STATE,
			ResponseMode.FORM_POST);

		ResponseType responseType = resp.impliedResponseType();
		assertEquals(new ResponseType("token"), responseType);

		assertEquals(ResponseMode.FORM_POST, resp.getResponseMode());
		assertEquals(ResponseMode.FORM_POST, resp.impliedResponseMode());

		try {
			resp.toURI();
			fail();
		} catch (SerializeException e) {
			// ok
		}

		HTTPRequest httpRequest = resp.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		assertTrue(httpRequest.getURL().toString().startsWith(ABS_REDIRECT_URI.toString()));

		assertEquals(Collections.singletonList("Bearer"), httpRequest.getQueryStringParameters().get("token_type"));
		assertEquals(Collections.singletonList(TOKEN.getLifetime() + ""), httpRequest.getQueryStringParameters().get("expires_in"));
		assertEquals(Collections.singletonList(TOKEN.getValue()), httpRequest.getQueryStringParameters().get("access_token"));
		assertEquals(Collections.singletonList(STATE.getValue()), httpRequest.getQueryStringParameters().get("state"));
		assertEquals(4, httpRequest.getQueryStringParameters().size());
	}

	
	// JARM with form_post.jwt
	public void testResponseModeJWTFormPost()
		throws Exception {
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.keyID("1")
			.generate();
		
		AuthorizationSuccessResponse origResponse = new AuthorizationSuccessResponse(
			ABS_REDIRECT_URI,
			null,
			TOKEN,
			STATE,
			null
		);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
			ISSUER,
			CLIENT_ID,
			DateUtils.fromSecondsSinceEpoch(DateUtils.toSecondsSinceEpoch(new Date()) + 60),
			origResponse
		);
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader(JWSAlgorithm.RS256),
			jwtClaimsSet
		);
		jwt.sign(new RSASSASigner(rsaJWK));

		AuthorizationSuccessResponse resp = new AuthorizationSuccessResponse(
			ABS_REDIRECT_URI,
			jwt,
			ResponseMode.FORM_POST_JWT);

		assertEquals(ResponseMode.FORM_POST_JWT, resp.getResponseMode());
		assertEquals(ResponseMode.FORM_POST_JWT, resp.impliedResponseMode());
		
		try {
			resp.toURI();
			fail();
		} catch (SerializeException e) {
			// ok
		}

		HTTPRequest httpRequest = resp.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		assertTrue(httpRequest.getURL().toString().startsWith(ABS_REDIRECT_URI.toString()));

		assertEquals(Collections.singletonList(jwt.serialize()), httpRequest.getQueryStringParameters().get("response"));
		assertEquals(1, httpRequest.getQueryStringParameters().size());
	}


	public void testOverrideQueryResponseMode() {

		AuthorizationSuccessResponse resp = new AuthorizationSuccessResponse(
			ABS_REDIRECT_URI,
			CODE,
			null,
			STATE,
			ResponseMode.FRAGMENT);

		ResponseType responseType = resp.impliedResponseType();
		assertEquals(new ResponseType("code"), responseType);

		assertEquals(ResponseMode.FRAGMENT, resp.getResponseMode());
		assertEquals(ResponseMode.FRAGMENT, resp.impliedResponseMode());

		try {
			resp.toHTTPRequest();
			fail();
		} catch (SerializeException e) {
			// ok
		}

		URI uri = resp.toURI();
		assertNull(uri.getQuery());
		Map<String,List<String>> params = URLUtils.parseParameters(uri.getRawFragment());
		assertEquals(CODE.getValue(), MultivaluedMapUtils.getFirstValue(params, "code"));
		assertEquals(STATE.getValue(), MultivaluedMapUtils.getFirstValue(params, "state"));
		assertEquals(2, params.size());
	}


	public void testOverrideFragmentResponseMode() {

		AuthorizationSuccessResponse resp = new AuthorizationSuccessResponse(
			ABS_REDIRECT_URI,
			null,
			TOKEN,
			STATE,
			ResponseMode.QUERY);

		ResponseType responseType = resp.impliedResponseType();
		assertEquals(new ResponseType("token"), responseType);

		assertEquals(ResponseMode.QUERY, resp.getResponseMode());
		assertEquals(ResponseMode.QUERY, resp.impliedResponseMode());

		try {
			resp.toHTTPRequest();
			fail();
		} catch (SerializeException e) {
			// ok
		}

		URI uri = resp.toURI();
		assertNull(uri.getRawFragment());
		Map<String,List<String>> params = URLUtils.parseParameters(uri.getQuery());
		assertEquals("Bearer", MultivaluedMapUtils.getFirstValue(params, "token_type"));
		assertEquals(TOKEN.getValue(), MultivaluedMapUtils.getFirstValue(params, "access_token"));
		assertEquals(TOKEN.getLifetime() + "", MultivaluedMapUtils.getFirstValue(params, "expires_in"));
		assertEquals(STATE.getValue(), MultivaluedMapUtils.getFirstValue(params, "state"));
		assertEquals(4, params.size());
	}


	public void testParseCodeResponse()
		throws Exception {
		
		String RESPONSE_CODE = "https://client.example.org/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz";
		URI redirectionURI = new URI(RESPONSE_CODE);

		AuthorizationSuccessResponse response = AuthorizationSuccessResponse.parse(redirectionURI);
		assertTrue(response.indicatesSuccess());
		assertEquals("https://client.example.org/cb", response.getRedirectionURI().toString());
		assertEquals("SplxlOBeZQQYbYS6WxSbIA", response.getAuthorizationCode().getValue());
		assertEquals("xyz", response.getState().getValue());
		assertNull(response.getAccessToken());
	}


	public void testParseTokenResponse()
		throws Exception {
		
		String responseToken = "https://client.example.org/cb#" +
			"&access_token=2YotnFZFEjr1zCsicMWpAA" +
			"&token_type=Bearer" +
			"&expires_in=3600" +
			"&state=xyz";
		URI redirectionURI = new URI(responseToken);

		AuthorizationSuccessResponse response = AuthorizationSuccessResponse.parse(redirectionURI);
		assertTrue(response.indicatesSuccess());
		assertEquals("https://client.example.org/cb", response.getRedirectionURI().toString());
		assertNull(response.getAuthorizationCode());
		assertEquals("xyz", response.getState().getValue());
		BearerAccessToken accessToken = (BearerAccessToken)response.getAccessToken();
		assertEquals("2YotnFZFEjr1zCsicMWpAA", accessToken.getValue());
		assertEquals(3600L, accessToken.getLifetime());
	}
	
	
	public void testParseWithIssuer_example()
		throws Exception {
		
		String responseWithIssuer = "https://client.example/cb?" +
			"code=x1848ZT64p4IirMPT0R-X3141MFPTuBX-VFL_cvaplMH58" +
			"&state=ZWVlNDBlYzA1NjdkMDNhYjg3ZjUxZjAyNGQzMTM2NzI" +
			"&iss=https://honest.as.example";
		URI redirectionURI = new URI(responseWithIssuer);
		
		AuthorizationSuccessResponse response = AuthorizationSuccessResponse.parse(redirectionURI);
		assertTrue(response.indicatesSuccess());
		assertEquals("https://client.example/cb", response.getRedirectionURI().toString());
		assertEquals(new AuthorizationCode("x1848ZT64p4IirMPT0R-X3141MFPTuBX-VFL_cvaplMH58"), response.getAuthorizationCode());
		assertEquals(new State("ZWVlNDBlYzA1NjdkMDNhYjg3ZjUxZjAyNGQzMTM2NzI"), response.getState());
		assertEquals(new Issuer("https://honest.as.example"), response.getIssuer());
	}
	
	
	// See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/140
	public void testRedirectionURIWithQueryString() {

		URI redirectURI = URI.create("https://example.com/myservice/?action=oidccallback");
		assertEquals("action=oidccallback", redirectURI.getQuery());

		AuthorizationCode code = new AuthorizationCode();
		State state = new State();

		AuthorizationSuccessResponse response = new AuthorizationSuccessResponse(redirectURI, code, null, state, ResponseMode.QUERY);

		Map<String,List<String>> params = response.toParameters();
		assertEquals(code.getValue(), MultivaluedMapUtils.getFirstValue(params, "code"));
		assertEquals(state.getValue(), MultivaluedMapUtils.getFirstValue(params, "state"));
		assertEquals(2, params.size());

		URI uri = response.toURI();

		params = URLUtils.parseParameters(uri.getQuery());
		assertEquals("oidccallback", MultivaluedMapUtils.getFirstValue(params, "action"));
		assertEquals(code.getValue(), MultivaluedMapUtils.getFirstValue(params, "code"));
		assertEquals(state.getValue(), MultivaluedMapUtils.getFirstValue(params, "state"));
		assertEquals(3, params.size());
	}


	// See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/147/authorizationrequestparse-final-uri-uri
	public void testParseWithEncodedEqualsChar()
		throws Exception {

		URI redirectURI = URI.create("https://example.com/in");

		AuthorizationCode code = new AuthorizationCode("===code===");
		State state = new State("===state===");

		AuthorizationSuccessResponse response = new AuthorizationSuccessResponse(redirectURI, code, null, state, ResponseMode.QUERY);

		URI uri = response.toURI();

		response = AuthorizationSuccessResponse.parse(uri);

		assertEquals(code, response.getAuthorizationCode());
		assertEquals(state, response.getState());
		assertNull(response.getAccessToken());
	}
	
	
	// See https://bitbucket.org/connect2id/openid-connect-dev-client/issues/5/stripping-equal-sign-from-access_code-in
	public void testParseWithEncodedEqualsCharAlt()
		throws Exception {

		String uri = "https://demo.c2id.com/oidc-client/cb?" +
			"&state=cVIe4g4D1J3tYtZgnTL-Po9QpozQJdikDCBp7KJorIQ" +
			"&code=1nf1ljB0JkPIbhMcYMeoT9Q5oGt28ggDsUiWLvCL81YTqCZMzAbVCGLUPrDHouda4cELZRujcS7d8rUNcZVl7HxUXdDsOUtc65s2knGbxSo%3D";

		AuthorizationSuccessResponse response = AuthorizationSuccessResponse.parse(URI.create(uri));

		assertEquals("cVIe4g4D1J3tYtZgnTL-Po9QpozQJdikDCBp7KJorIQ", response.getState().getValue());
		assertEquals("1nf1ljB0JkPIbhMcYMeoT9Q5oGt28ggDsUiWLvCL81YTqCZMzAbVCGLUPrDHouda4cELZRujcS7d8rUNcZVl7HxUXdDsOUtc65s2knGbxSo=", response.getAuthorizationCode().getValue());
	}


	public void testParse_httpRequest() throws Exception {

		AuthorizationSuccessResponse response = new AuthorizationSuccessResponse(
			URI.create("https://example.com/cb"),
			new AuthorizationCode(),
			null,
			new State(),
			null,
			ResponseMode.FORM_POST
		);

		HTTPRequest httpRequest = response.toHTTPRequest();

		AuthorizationSuccessResponse parsedResponse = AuthorizationSuccessResponse.parse(httpRequest);

		assertEquals(response.getRedirectionURI(), parsedResponse.getRedirectionURI());
		assertEquals(response.getState(), parsedResponse.getState());
		assertNull(parsedResponse.getIssuer());
		assertNull(parsedResponse.getResponseMode());
	}
}
