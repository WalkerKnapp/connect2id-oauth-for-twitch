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

package com.nimbusds.oauth2.sdk.token;


import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail;
import com.nimbusds.oauth2.sdk.rar.AuthorizationType;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class BearerAccessTokenTest extends TestCase {
	
	
	public void testGenerateConstructor() {
		
		AccessToken token = new BearerAccessToken();
		
		assertNotNull(token);
		
		assertEquals(32, new Base64(token.getValue()).decode().length);
		assertEquals(0L, token.getLifetime());
		assertNull(token.getScope());
		assertNull(token.getIssuedTokenType());
		
		String header = token.toAuthorizationHeader();
		assertEquals("Bearer " + token.getValue(), header);
	}
	
	
	public void testGenerateConstructor_bytes() {

		AccessToken token = new BearerAccessToken(12);

		assertNotNull(token);

		assertEquals(12, new Base64(token.getValue()).decode().length);
		assertEquals(0L, token.getLifetime());
		assertNull(token.getScope());
		assertNull(token.getIssuedTokenType());

		String header = token.toAuthorizationHeader();
		assertTrue(header.startsWith("Bearer "));
		assertEquals(token.getValue(), header.substring("Bearer ".length()));
	}
	
	
	public void testGenerateConstructor_lifetime_scope() {
		
		Scope scope = Scope.parse("read write");

		AccessToken token = new BearerAccessToken(1500, scope);

		assertNotNull(token);

		assertEquals(32, new Base64(token.getValue()).decode().length);
		assertEquals(1500L, token.getLifetime());
		assertEquals(scope, token.getScope());
		assertNull(token.getIssuedTokenType());

		String header = token.toAuthorizationHeader();
		assertTrue(header.startsWith("Bearer "));
		assertEquals(token.getValue(), header.substring("Bearer ".length()));
	}
	
	
	public void testGenerateConstructor_bytes_lifetime_scope() {
		
		Scope scope = Scope.parse("read write");

		AccessToken token = new BearerAccessToken(12, 1500, scope);

		assertNotNull(token);

		assertEquals(12, new Base64(token.getValue()).decode().length);
		assertEquals(1500L, token.getLifetime());
		assertEquals(scope, token.getScope());
		assertNull(token.getIssuedTokenType());

		String header = token.toAuthorizationHeader();
		assertTrue(header.startsWith("Bearer "));
		assertEquals(token.getValue(), header.substring("Bearer ".length()));
	}
	
	
	public void testValueConstructor()
		throws Exception {
		
		AccessToken token = new BearerAccessToken("abc");
		
		assertEquals("abc", token.getValue());
		assertEquals(0L, token.getLifetime());
		assertNull(token.getScope());
		assertNull(token.getIssuedTokenType());
		
		assertEquals("Bearer abc", token.toAuthorizationHeader());
		
		JSONObject jsonObject = token.toJSONObject();
		
		assertEquals("abc", jsonObject.get("access_token"));
		assertEquals("Bearer", jsonObject.get("token_type"));
		assertEquals(2, jsonObject.size());
		
		token = BearerAccessToken.parse(jsonObject);
		
		assertEquals("abc", token.getValue());
		assertEquals(0L, token.getLifetime());
		assertNull(token.getScope());
		assertNull(token.getIssuedTokenType());
		
		assertTrue(token.getParameterNames().contains("access_token"));
		assertTrue(token.getParameterNames().contains("token_type"));
		assertEquals(2, token.getParameterNames().size());
	}


	public void testValueConstructor_lifetime_scope()
		throws Exception {
		
		Scope scope = Scope.parse("read write");

		AccessToken token = new BearerAccessToken("abc", 1500, scope);
		
		assertEquals("abc", token.getValue());
		assertEquals(1500L, token.getLifetime());
		assertEquals(scope, token.getScope());
		assertNull(token.getIssuedTokenType());
		
		assertEquals("Bearer abc", token.toAuthorizationHeader());

		JSONObject jsonObject = token.toJSONObject();

		assertEquals("abc", jsonObject.get("access_token"));
		assertEquals("Bearer", jsonObject.get("token_type"));
		assertEquals(1500L, jsonObject.get("expires_in"));
		assertEquals(scope, Scope.parse((String) jsonObject.get("scope")));
		assertEquals(4, jsonObject.size());

		token = BearerAccessToken.parse(jsonObject);
		
		assertEquals("abc", token.getValue());
		assertEquals(1500L, token.getLifetime());
		assertEquals(scope, token.getScope());
		assertNull(token.getIssuedTokenType());

		assertTrue(token.getParameterNames().contains("access_token"));
		assertTrue(token.getParameterNames().contains("token_type"));
		assertTrue(token.getParameterNames().contains("expires_in"));
		assertTrue(token.getParameterNames().contains("scope"));
		assertEquals(4, token.getParameterNames().size());
	}


	public void testValueConstructor_lifetime_scope_uri()
		throws Exception {
		
		Scope scope = Scope.parse("read write");

		AccessToken token = new BearerAccessToken("abc", 1500, scope, TokenTypeURI.ACCESS_TOKEN);
		
		assertEquals("abc", token.getValue());
		assertEquals(1500L, token.getLifetime());
		assertEquals(scope, token.getScope());
		assertEquals(TokenTypeURI.ACCESS_TOKEN, token.getIssuedTokenType());
		
		assertEquals("Bearer abc", token.toAuthorizationHeader());

		JSONObject jsonObject = token.toJSONObject();

		assertEquals("abc", jsonObject.get("access_token"));
		assertEquals("Bearer", jsonObject.get("token_type"));
		assertEquals(1500L, jsonObject.get("expires_in"));
		assertEquals(scope, Scope.parse((String) jsonObject.get("scope")));
		assertEquals(TokenTypeURI.ACCESS_TOKEN, TokenTypeURI.parse((String) jsonObject.get("issued_token_type")));
		assertEquals(5, jsonObject.size());

		token = BearerAccessToken.parse(jsonObject);
		
		assertEquals("abc", token.getValue());
		assertEquals(1500L, token.getLifetime());
		assertEquals(scope, token.getScope());
		assertEquals(TokenTypeURI.ACCESS_TOKEN, token.getIssuedTokenType());

		assertTrue(token.getParameterNames().contains("access_token"));
		assertTrue(token.getParameterNames().contains("token_type"));
		assertTrue(token.getParameterNames().contains("expires_in"));
		assertTrue(token.getParameterNames().contains("scope"));
		assertTrue(token.getParameterNames().contains("issued_token_type"));
		assertEquals(5, token.getParameterNames().size());
	}


	public void testValueConstructor_lifetime_scope_rar_uri()
		throws Exception {

		Scope scope = Scope.parse("read write");

		List<AuthorizationDetail> authorizationDetails = Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("example_api")).build());

		AccessToken token = new BearerAccessToken("abc", 1500, scope, authorizationDetails, TokenTypeURI.ACCESS_TOKEN);

		assertEquals("abc", token.getValue());
		assertEquals(1500L, token.getLifetime());
		assertEquals(scope, token.getScope());
		assertEquals(authorizationDetails, token.getAuthorizationDetails());
		assertEquals(TokenTypeURI.ACCESS_TOKEN, token.getIssuedTokenType());

		assertEquals("Bearer abc", token.toAuthorizationHeader());

		JSONObject jsonObject = token.toJSONObject();

		assertEquals("abc", jsonObject.get("access_token"));
		assertEquals("Bearer", jsonObject.get("token_type"));
		assertEquals(1500L, jsonObject.get("expires_in"));
		assertEquals(scope, Scope.parse((String) jsonObject.get("scope")));
		assertEquals(authorizationDetails, AuthorizationDetail.parseList((String) jsonObject.get("authorization_details")));
		assertEquals(TokenTypeURI.ACCESS_TOKEN, TokenTypeURI.parse((String) jsonObject.get("issued_token_type")));
		assertEquals(6, jsonObject.size());

		token = BearerAccessToken.parse(jsonObject);

		assertEquals("abc", token.getValue());
		assertEquals(1500L, token.getLifetime());
		assertEquals(scope, token.getScope());
		assertEquals(authorizationDetails, token.getAuthorizationDetails());
		assertEquals(TokenTypeURI.ACCESS_TOKEN, token.getIssuedTokenType());

		assertTrue(token.getParameterNames().contains("access_token"));
		assertTrue(token.getParameterNames().contains("token_type"));
		assertTrue(token.getParameterNames().contains("expires_in"));
		assertTrue(token.getParameterNames().contains("scope"));
		assertTrue(token.getParameterNames().contains("authorization_details"));
		assertTrue(token.getParameterNames().contains("issued_token_type"));
		assertEquals(6, token.getParameterNames().size());
	}
	
	
	public void testParseFromHeader()
		throws ParseException {
	
		AccessToken token = AccessToken.parse("Bearer abc");
		
		assertEquals("abc", token.getValue());
		assertEquals(0L, token.getLifetime());
		assertNull(token.getScope());

		assertTrue(token.getParameterNames().contains("access_token"));
		assertTrue(token.getParameterNames().contains("token_type"));
		assertEquals(2, token.getParameterNames().size());
	}


	public void testParseFromHeader_missing() {

		try {
			AccessToken.parse((String)null);
			fail();
		} catch (ParseException e) {
			assertEquals(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(BearerTokenError.MISSING_TOKEN.getCode(), e.getErrorObject().getCode());
		}
	}
	
	
	public void testParseFromHeader_missingName() {
	
		try {
			AccessToken.parse("abc");
			fail();
		} catch (ParseException e) {
			assertEquals(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(BearerTokenError.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
		}
	}
	
	
	public void testParseFromHeader_missingValue() {
	
		try {
			AccessToken.parse("Bearer ", AccessTokenType.BEARER);
			fail();
		} catch (ParseException e) {
			assertEquals("The token value must not be null or empty string", e.getMessage());
			assertEquals(BearerTokenError.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
		}
	
		try {
			AccessToken.parse("DPoP ", AccessTokenType.DPOP);
			fail();
		} catch (ParseException e) {
			assertEquals(DPoPTokenError.INVALID_REQUEST.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(DPoPTokenError.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
		}
	}
	
	
	public void testParseFromQueryParameters()
		throws Exception {
		
		Map<String,List<String>> params = new HashMap<>();
		params.put("access_token", Collections.singletonList("abc"));
		
		assertEquals("abc", BearerAccessToken.parse(params).getValue());
	}
	
	
	public void testParseFromQueryParameters_missing() {
		
		Map<String,List<String>> params = new HashMap<>();
		params.put("some_param", Collections.singletonList("abc"));
		
		try {
			BearerAccessToken.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing access token parameter", e.getMessage());
			assertEquals(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(BearerTokenError.MISSING_TOKEN.getCode(), e.getErrorObject().getCode());
		}
	}
	
	
	public void testParseFromQueryParameters_empty() {
		
		Map<String,List<String>> params = new HashMap<>();
		params.put("access_token", Collections.singletonList(""));
		
		try {
			BearerAccessToken.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Blank / empty access token", e.getMessage());
			assertEquals(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(BearerTokenError.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
		}
	}


	public void testParseFromHTTPRequest()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://c2id.com/reg/123"));
		httpRequest.setAuthorization("Bearer abc");

		BearerAccessToken accessToken = BearerAccessToken.parse(httpRequest);

		assertEquals("abc", accessToken.getValue());
	}


	public void testParseFromHTTPRequest_missing()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://c2id.com/reg/123"));

		try {
			BearerAccessToken.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals(401, e.getErrorObject().getHTTPStatusCode());
			assertNull(e.getErrorObject().getCode());
		}
	}


	public void testParseFromHTTPRequest_invalid()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://c2id.com/reg/123"));
		httpRequest.setAuthorization("Bearer");

		try {
			BearerAccessToken.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(BearerTokenError.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
		}
	}


	public void testParseFromJSONObject_invalidAuthorizationDetails() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("access_token", "abc");
		jsonObject.put("token_type", "Bearer");
		jsonObject.put("authorization_details", "[{},{}]");

		try {
			BearerAccessToken.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid authorization details: Invalid authorization detail at position 0: Illegal or missing type", e.getMessage());
		}
	}


	public void testParseFromJSONObject_invalidIssuedTokenType() {

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("access_token", "abc");
		jsonObject.put("token_type", "Bearer");
		jsonObject.put("issued_token_type", "invalid uri");

		try {
			BearerAccessToken.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid issued_token_type parameter: Illegal token type URI: invalid uri", e.getMessage());
		}
	}
}
