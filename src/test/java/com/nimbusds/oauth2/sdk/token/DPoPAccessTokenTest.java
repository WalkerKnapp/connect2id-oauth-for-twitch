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


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail;
import com.nimbusds.oauth2.sdk.rar.AuthorizationType;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import junit.framework.TestCase;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class DPoPAccessTokenTest extends TestCase {


	public void testValueConstructor()
		throws Exception {
		
		AccessToken token = new DPoPAccessToken("abc");
		assertEquals(AccessTokenType.DPOP, token.getType());
		assertEquals("abc", token.getValue());
		assertEquals(0L, token.getLifetime());
		assertNull(token.getScope());
		
		assertEquals("DPoP abc", token.toAuthorizationHeader());

		JSONObject jsonObject = token.toJSONObject();

		assertEquals("abc", jsonObject.get("access_token"));
		assertEquals("DPoP", jsonObject.get("token_type"));
		assertEquals(2, jsonObject.size());

		token = DPoPAccessToken.parse(jsonObject);
		assertEquals(AccessTokenType.DPOP, token.getType());
		assertEquals("abc", token.getValue());
		assertEquals(0L, token.getLifetime());
		assertNull(token.getScope());

		assertTrue(token.getParameterNames().contains("access_token"));
		assertTrue(token.getParameterNames().contains("token_type"));
		assertEquals(2, token.getParameterNames().size());
	}


	public void testValueConstructor_lifetime_scope()
		throws Exception {
		
		Scope scope = new Scope("read", "write");

		AccessToken token = new DPoPAccessToken("abc", 1500L, scope);
		assertEquals(AccessTokenType.DPOP, token.getType());
		assertEquals("abc", token.getValue());
		assertEquals(1500L, token.getLifetime());
		assertEquals(scope, token.getScope());
		assertNull(token.getIssuedTokenType());
		
		assertEquals("DPoP abc", token.toAuthorizationHeader());

		JSONObject jsonObject = token.toJSONObject();

		assertEquals("abc", jsonObject.get("access_token"));
		assertEquals("DPoP", jsonObject.get("token_type"));
		assertEquals(1500L, jsonObject.get("expires_in"));
		assertEquals(scope.toString(), jsonObject.get("scope"));
		assertEquals(4, jsonObject.size());

		token = DPoPAccessToken.parse(jsonObject);
		assertEquals(AccessTokenType.DPOP, token.getType());
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
		
		Scope scope = new Scope("read", "write");

		AccessToken token = new DPoPAccessToken("abc", 1500L, scope, TokenTypeURI.ACCESS_TOKEN);
		assertEquals(AccessTokenType.DPOP, token.getType());
		assertEquals("abc", token.getValue());
		assertEquals(1500L, token.getLifetime());
		assertEquals(scope, token.getScope());
		assertEquals(TokenTypeURI.ACCESS_TOKEN, token.getIssuedTokenType());
		
		assertEquals("DPoP abc", token.toAuthorizationHeader());

		JSONObject jsonObject = token.toJSONObject();

		assertEquals("abc", jsonObject.get("access_token"));
		assertEquals("DPoP", jsonObject.get("token_type"));
		assertEquals(1500L, jsonObject.get("expires_in"));
		assertEquals(scope.toString(), jsonObject.get("scope"));
		assertEquals(TokenTypeURI.ACCESS_TOKEN, TokenTypeURI.parse((String) jsonObject.get("issued_token_type")));
		assertEquals(5, jsonObject.size());

		token = DPoPAccessToken.parse(jsonObject);
		assertEquals(AccessTokenType.DPOP, token.getType());
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

		Scope scope = new Scope("read", "write");

		List<AuthorizationDetail> authorizationDetails = Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("example_api")).build());

		AccessToken token = new DPoPAccessToken("abc", 1500L, scope, authorizationDetails, TokenTypeURI.ACCESS_TOKEN);
		assertEquals(AccessTokenType.DPOP, token.getType());
		assertEquals("abc", token.getValue());
		assertEquals(1500L, token.getLifetime());
		assertEquals(scope, token.getScope());
		assertEquals(authorizationDetails, token.getAuthorizationDetails());
		assertEquals(TokenTypeURI.ACCESS_TOKEN, token.getIssuedTokenType());

		assertEquals("DPoP abc", token.toAuthorizationHeader());

		JSONObject jsonObject = token.toJSONObject();

		assertEquals("abc", jsonObject.get("access_token"));
		assertEquals("DPoP", jsonObject.get("token_type"));
		assertEquals(1500L, jsonObject.get("expires_in"));
		assertEquals(scope.toString(), jsonObject.get("scope"));
		assertEquals(AuthorizationDetail.toJSONArray(authorizationDetails), JSONObjectUtils.getJSONArray(jsonObject, "authorization_details"));
		assertEquals(TokenTypeURI.ACCESS_TOKEN, TokenTypeURI.parse((String) jsonObject.get("issued_token_type")));
		assertEquals(6, jsonObject.size());

		token = DPoPAccessToken.parse(jsonObject);
		assertEquals(AccessTokenType.DPOP, token.getType());
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
		throws Exception {
	
		AccessToken token = AccessToken.parse("DPoP abc", AccessTokenType.DPOP);
		assertEquals(AccessTokenType.DPOP, token.getType());
		assertEquals("abc", token.getValue());
		assertEquals(0L, token.getLifetime());
		assertNull(token.getScope());

		assertTrue(token.getParameterNames().contains("access_token"));
		assertTrue(token.getParameterNames().contains("token_type"));
		assertEquals(2, token.getParameterNames().size());
	}


	public void testParseFromHeader_missing() {

		try {
			AccessToken.parse(null, AccessTokenType.DPOP);
			fail();
		} catch (ParseException e) {
			assertEquals(DPoPTokenError.MISSING_TOKEN.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(DPoPTokenError.MISSING_TOKEN.getCode(), e.getErrorObject().getCode());
		}
	}
	
	
	public void testParseFromHeader_missingName() {
	
		try {
			AccessToken.parse("abc", AccessTokenType.DPOP);
			fail();
		} catch (ParseException e) {
			System.err.println(e.getMessage());
			assertEquals(DPoPTokenError.INVALID_REQUEST.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(DPoPTokenError.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
		}
	}
	
	
	public void testParseFromHeader_missingValue() {
	
		try {
			AccessToken.parse("DPoP ", AccessTokenType.DPOP);
			fail();
		} catch (ParseException e) {
			assertEquals("The token value must not be null or empty string", e.getMessage());
			assertEquals(DPoPTokenError.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals(DPoPTokenError.INVALID_REQUEST.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
		}
	}
	
	
	public void testParseFromQueryParameters()
		throws Exception {
		
		Map<String,List<String>> params = new HashMap<>();
		params.put("access_token", Collections.singletonList("abc"));
		
		assertEquals("abc", DPoPAccessToken.parse(params).getValue());
	}
	
	
	public void testParseFromQueryParameters_missing() {
		
		Map<String,List<String>> params = new HashMap<>();
		params.put("some_param", Collections.singletonList("abc"));
		
		try {
			DPoPAccessToken.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing access token parameter", e.getMessage());
			assertEquals(DPoPTokenError.MISSING_TOKEN.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(DPoPTokenError.MISSING_TOKEN.getCode(), e.getErrorObject().getCode());
		}
	}
	
	
	public void testParseFromQueryParameters_empty() {
		
		Map<String,List<String>> params = new HashMap<>();
		params.put("access_token", Collections.singletonList(""));
		
		try {
			DPoPAccessToken.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Blank / empty access token", e.getMessage());
			assertEquals(DPoPTokenError.INVALID_REQUEST.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(DPoPTokenError.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
		}
	}


	public void testParseFromHTTPRequest()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://c2id.com/reg/123"));
		httpRequest.setAuthorization("DPoP abc");

		DPoPAccessToken accessToken = DPoPAccessToken.parse(httpRequest);

		assertEquals("abc", accessToken.getValue());
	}


	public void testParseFromHTTPRequest_missing()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://c2id.com/reg/123"));

		try {
			DPoPAccessToken.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals(401, e.getErrorObject().getHTTPStatusCode());
			assertNull(e.getErrorObject().getCode());
		}
	}


	public void testParseFromHTTPRequest_invalid()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://c2id.com/reg/123"));
		httpRequest.setAuthorization("DPoP");

		try {
			DPoPAccessToken.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals(DPoPTokenError.INVALID_REQUEST.getHTTPStatusCode(), e.getErrorObject().getHTTPStatusCode());
			assertEquals(DPoPTokenError.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
		}
	}


	public void testParseFromJSONObject_invalidAuthorizationDetails()
		throws ParseException {

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("access_token", "abc");
		jsonObject.put("token_type", "DPoP");
		jsonObject.put("authorization_details", JSONArrayUtils.parse("[{},{}]"));

		try {
			DPoPAccessToken.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid authorization detail at position 0: Illegal or missing type", e.getMessage());
		}
	}


	public void testParseFromJSONObject_invalidIssuedTokenType() {

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("access_token", "abc");
		jsonObject.put("token_type", "DPoP");
		jsonObject.put("issued_token_type", "invalid uri");

		try {
			DPoPAccessToken.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid issued_token_type parameter: Illegal token type URI: invalid uri", e.getMessage());
		}
	}
}
