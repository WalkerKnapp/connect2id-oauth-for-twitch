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
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail;
import com.nimbusds.oauth2.sdk.rar.AuthorizationType;
import com.nimbusds.oauth2.sdk.token.*;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import java.util.*;


public class AccessTokenResponseTest extends TestCase {


	public void testConstructor()
		throws ParseException {

		Tokens tokens = new Tokens(new BearerAccessToken(), new RefreshToken());
		AccessTokenResponse response = new AccessTokenResponse(tokens);

		assertTrue(response.indicatesSuccess());
		assertEquals(tokens.getAccessToken(), response.getTokens().getAccessToken());
		assertEquals(tokens.getAccessToken(), response.getTokens().getBearerAccessToken());
		assertEquals(tokens.getRefreshToken(), response.getTokens().getRefreshToken());
		assertTrue(response.getCustomParameters().isEmpty());
		assertTrue(response.getCustomParams().isEmpty());

		HTTPResponse httpResponse = response.toHTTPResponse();
		response = AccessTokenResponse.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals(tokens.getAccessToken(), response.getTokens().getAccessToken());
		assertEquals(tokens.getAccessToken(), response.getTokens().getBearerAccessToken());
		assertEquals(tokens.getRefreshToken(), response.getTokens().getRefreshToken());
		assertTrue(response.getCustomParameters().isEmpty());
		assertTrue(response.getCustomParams().isEmpty());
	}


	public void testConstructorMinimal()
		throws ParseException {

		Tokens tokens = new Tokens(new BearerAccessToken(), null);

		AccessTokenResponse response = new AccessTokenResponse(tokens, null);

		assertTrue(response.indicatesSuccess());
		assertEquals(tokens.getAccessToken(), response.getTokens().getAccessToken());
		assertEquals(tokens.getAccessToken(), response.getTokens().getBearerAccessToken());
		assertNull(response.getTokens().getRefreshToken());
		assertTrue(response.getCustomParameters().isEmpty());
		assertTrue(response.getCustomParams().isEmpty());

		HTTPResponse httpResponse = response.toHTTPResponse();
		response = AccessTokenResponse.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals(tokens.getAccessToken(), response.getTokens().getAccessToken());
		assertEquals(tokens.getAccessToken(), response.getTokens().getBearerAccessToken());
		assertNull(response.getTokens().getRefreshToken());
		assertTrue(response.getCustomParameters().isEmpty());
		assertTrue(response.getCustomParams().isEmpty());
	}


	public void testConstructorForTokenExchange()
		throws ParseException {

		BearerAccessToken accessToken = new BearerAccessToken(
			"paip0cotheCh0Quahshaithoono1fie4",
			60,
			new Scope("read", "write"),
			TokenTypeURI.ACCESS_TOKEN
		);
		
		Tokens tokens = new Tokens(accessToken, null);

		AccessTokenResponse response = new AccessTokenResponse(tokens, null);

		assertTrue(response.indicatesSuccess());
		assertEquals(tokens.getAccessToken(), response.getTokens().getAccessToken());
		assertEquals(tokens.getAccessToken(), response.getTokens().getBearerAccessToken());
		assertNull(response.getTokens().getRefreshToken());
		assertTrue(response.getCustomParameters().isEmpty());
		assertTrue(response.getCustomParams().isEmpty());

		HTTPResponse httpResponse = response.toHTTPResponse();
		
		JSONObject jsonObject = httpResponse.getContentAsJSONObject();
		assertEquals(accessToken.getType().getValue(), jsonObject.get("token_type"));
		assertEquals(accessToken.getValue(), jsonObject.get("access_token"));
		assertEquals(accessToken.getLifetime(), jsonObject.get("expires_in"));
		assertEquals(accessToken.getScope().toString(), jsonObject.get("scope"));
		assertEquals(accessToken.getIssuedTokenType().toString(), jsonObject.get("issued_token_type"));
		assertEquals(5, jsonObject.size());
		
		response = AccessTokenResponse.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals(tokens.getAccessToken(), response.getTokens().getAccessToken());
		assertEquals(accessToken.getLifetime(), response.getTokens().getAccessToken().getLifetime());
		assertEquals(accessToken.getScope(), response.getTokens().getAccessToken().getScope());
		assertEquals(accessToken.getIssuedTokenType(), response.getTokens().getAccessToken().getIssuedTokenType());
		assertEquals(tokens.getAccessToken(), response.getTokens().getBearerAccessToken());
		assertEquals(accessToken.getValue(), response.getTokens().getAccessToken().getValue());
		assertNull(response.getTokens().getRefreshToken());
		assertTrue(response.getCustomParameters().isEmpty());
		assertTrue(response.getCustomParams().isEmpty());
	}


	public void testTokenExchange_withTokenTypeNotApplicable()
		throws ParseException {
		
		String tokenValue = "paip0cotheCh0Quahshaithoono1fie4";
		NAAccessToken naToken = new NAAccessToken(tokenValue, 0L, null, TokenTypeURI.JWT);
		
		assertEquals(AccessTokenType.N_A, naToken.getType());
		assertEquals(tokenValue, naToken.getValue());
		assertEquals(TokenTypeURI.JWT, naToken.getIssuedTokenType());
		
		Tokens tokens = new Tokens(naToken, null);

		AccessTokenResponse response = new AccessTokenResponse(tokens, null);

		assertTrue(response.indicatesSuccess());
		assertEquals(tokens.getAccessToken(), response.getTokens().getAccessToken());
		assertNull(response.getTokens().getBearerAccessToken());
		assertNull(response.getTokens().getDPoPAccessToken());
		assertNull(response.getTokens().getRefreshToken());
		assertTrue(response.getCustomParameters().isEmpty());
		assertTrue(response.getCustomParams().isEmpty());

		HTTPResponse httpResponse = response.toHTTPResponse();
		
		JSONObject jsonObject = httpResponse.getContentAsJSONObject();
		assertEquals(naToken.getType().getValue(), jsonObject.get("token_type"));
		assertEquals(naToken.getValue(), jsonObject.get("access_token"));
		assertEquals(naToken.getIssuedTokenType().toString(), jsonObject.get("issued_token_type"));
		assertEquals(3, jsonObject.size());
		
		response = AccessTokenResponse.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals(tokens.getAccessToken().getValue(), response.getTokens().getAccessToken().getValue());
		assertEquals(naToken.getLifetime(), response.getTokens().getAccessToken().getLifetime());
		assertEquals(naToken.getScope(), response.getTokens().getAccessToken().getScope());
		assertEquals(naToken.getIssuedTokenType(), response.getTokens().getAccessToken().getIssuedTokenType());
		assertNull(response.getTokens().getRefreshToken());
		assertTrue(response.getCustomParameters().isEmpty());
		assertTrue(response.getCustomParams().isEmpty());
	}


	public void testConstructorWithCustomParams()
		throws ParseException {

		Tokens tokens = new Tokens(new BearerAccessToken(), null);
		Map<String,Object> customParams = new HashMap<>();
		customParams.put("sub_sid", "abc");

		AccessTokenResponse response = new AccessTokenResponse(tokens, customParams);

		assertTrue(response.indicatesSuccess());
		assertEquals(tokens.getAccessToken(), response.getTokens().getAccessToken());
		assertEquals(tokens.getAccessToken(), response.getTokens().getBearerAccessToken());
		assertNull(response.getTokens().getRefreshToken());
		assertEquals("abc", (String) response.getCustomParameters().get("sub_sid"));
		assertEquals("abc", (String) response.getCustomParams().get("sub_sid"));

		HTTPResponse httpResponse = response.toHTTPResponse();
		response = AccessTokenResponse.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals(tokens.getAccessToken(), response.getTokens().getAccessToken());
		assertEquals(tokens.getAccessToken(), response.getTokens().getBearerAccessToken());
		assertNull(response.getTokens().getRefreshToken());
		assertEquals("abc", (String) response.getCustomParameters().get("sub_sid"));
		assertEquals("abc", (String) response.getCustomParams().get("sub_sid"));
	}


	public void testConstructor_rejectNullTokens() {

		try {
			new AccessTokenResponse(null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}


	public void testParseFromHTTPResponseWithCustomParams()
		throws Exception {

		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");

		JSONObject o = new JSONObject();

		final String accessTokenString = "SlAV32hkKG";
		o.put("access_token", accessTokenString);

		o.put("token_type", "Bearer");

		final String refreshTokenString = "8xLOxBtZp8";
		o.put("refresh_token", refreshTokenString);

		final long exp = 3600;
		o.put("expires_in", exp);

		o.put("sub_sid", "abc");
		o.put("priority", 10);

		httpResponse.setContent(o.toString());


		AccessTokenResponse atr = AccessTokenResponse.parse(httpResponse);

		assertTrue(atr.indicatesSuccess());

		AccessToken accessToken = atr.getTokens().getAccessToken();
		assertEquals(accessTokenString, accessToken.getValue());

		BearerAccessToken bearerAccessToken = atr.getTokens().getBearerAccessToken();
		assertEquals(accessTokenString, bearerAccessToken.getValue());

		assertEquals(exp, accessToken.getLifetime());
		assertNull(accessToken.getScope());

		RefreshToken refreshToken = atr.getTokens().getRefreshToken();
		assertEquals(refreshTokenString, refreshToken.getValue());

		// Custom param
		assertEquals("abc", (String)atr.getCustomParameters().get("sub_sid"));
		assertEquals("abc", (String)atr.getCustomParams().get("sub_sid"));
		assertEquals(10, ((Number)atr.getCustomParameters().get("priority")).intValue());
		assertEquals(10, ((Number)atr.getCustomParams().get("priority")).intValue());
		assertEquals(2, atr.getCustomParameters().size());
		assertEquals(2, atr.getCustomParams().size());

		// Test pair getter
		Tokens pair = atr.getTokens();
		assertEquals(accessToken, pair.getAccessToken());
		assertEquals(refreshToken, pair.getRefreshToken());

		httpResponse = atr.toHTTPResponse();

		assertEquals(ContentType.APPLICATION_JSON.toString(), httpResponse.getEntityContentType().toString());
		assertEquals("no-store", httpResponse.getCacheControl());
		assertEquals("no-cache", httpResponse.getPragma());

		o = httpResponse.getContentAsJSONObject();

		assertEquals(accessTokenString, o.get("access_token"));
		assertEquals("Bearer", o.get("token_type"));
		assertEquals(refreshTokenString, o.get("refresh_token"));
		assertEquals(3600L, o.get("expires_in"));

		// Custom param
		assertEquals("abc", (String)o.get("sub_sid"));
		assertEquals(10, ((Number)o.get("priority")).intValue());
	}


	public void testParseFromAltHTTPResponse()
		throws Exception {

		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");

		JSONObject o = new JSONObject();

		final String accessTokenString = "SlAV32hkKG";
		o.put("access_token", accessTokenString);

		o.put("token_type", "bearer");

		httpResponse.setContent(o.toString());

		AccessTokenResponse atr = AccessTokenResponse.parse(httpResponse);

		assertTrue(atr.indicatesSuccess());
		AccessToken accessToken = atr.getTokens().getAccessToken();
		assertEquals(accessTokenString, accessToken.getValue());
		BearerAccessToken bearerAccessToken = atr.getTokens().getBearerAccessToken();
		assertEquals(accessTokenString, bearerAccessToken.getValue());
		assertNull(accessToken.getScope());

		Tokens tokens = atr.getTokens();
		assertEquals(accessToken, tokens.getAccessToken());

		httpResponse = atr.toHTTPResponse();

		assertEquals(ContentType.APPLICATION_JSON.toString(), httpResponse.getEntityContentType().toString());
		assertEquals("no-store", httpResponse.getCacheControl());
		assertEquals("no-cache", httpResponse.getPragma());

		o = httpResponse.getContentAsJSONObject();

		assertEquals(accessTokenString, o.get("access_token"));
		assertEquals("Bearer", o.get("token_type"));
	}


	public void testParseFromHTTPResponseWithRAR()
		throws Exception {

		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");

		JSONObject o = new JSONObject();

		final String accessTokenString = "SlAV32hkKG";
		o.put("access_token", accessTokenString);

		o.put("token_type", "bearer");

		List<AuthorizationDetail> authorizationDetails = Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("example_api")).build());
		o.put("authorization_details", AuthorizationDetail.toJSONArray(authorizationDetails));

		httpResponse.setContent(o.toString());

		AccessTokenResponse atr = AccessTokenResponse.parse(httpResponse);

		assertTrue(atr.indicatesSuccess());
		AccessToken accessToken = atr.getTokens().getAccessToken();
		assertEquals(accessTokenString, accessToken.getValue());
		BearerAccessToken bearerAccessToken = atr.getTokens().getBearerAccessToken();
		assertEquals(accessTokenString, bearerAccessToken.getValue());
		assertNull(accessToken.getScope());
		assertEquals(authorizationDetails, accessToken.getAuthorizationDetails());

		Tokens tokens = atr.getTokens();
		assertEquals(accessToken, tokens.getAccessToken());

		httpResponse = atr.toHTTPResponse();

		assertEquals(ContentType.APPLICATION_JSON.toString(), httpResponse.getEntityContentType().toString());
		assertEquals("no-store", httpResponse.getCacheControl());
		assertEquals("no-cache", httpResponse.getPragma());

		o = httpResponse.getContentAsJSONObject();

		assertEquals(accessTokenString, o.get("access_token"));
		assertEquals("Bearer", o.get("token_type"));
		assertEquals(AuthorizationDetail.toJSONArray(authorizationDetails), o.get("authorization_details"));
		assertEquals(3, o.size());
	}
	
	
	public void testParseJSONObjectNoSideEffects()
		throws Exception {
		
		// {
		//   "access_token":"2YotnFZFEjr1zCsicMWpAA",
		//   "token_type":"Bearer",
		//   "expires_in":3600,
		//   "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
		//   "example_parameter":"example_value"
		// }
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("access_token", "2YotnFZFEjr1zCsicMWpAA");
		jsonObject.put("token_type", "Bearer");
		jsonObject.put("expires_in", 3600);
		jsonObject.put("refresh_token", "tGzv3JOkF0XG5Qx2TlKWIA");
		jsonObject.put("example_parameter", "example_value");
		
		Set<String> keys = new HashSet<>();
		keys.addAll(jsonObject.keySet());
		
		AccessTokenResponse response = AccessTokenResponse.parse(jsonObject);
		assertEquals("2YotnFZFEjr1zCsicMWpAA", response.getTokens().getBearerAccessToken().getValue());
		assertEquals(3600L, response.getTokens().getBearerAccessToken().getLifetime());
		assertEquals("tGzv3JOkF0XG5Qx2TlKWIA", response.getTokens().getRefreshToken().getValue());
		assertEquals("example_value", response.getCustomParameters().get(("example_parameter")));
		assertEquals(1, response.getCustomParameters().size());
		
		assertEquals(keys, jsonObject.keySet());
	}
	
	
	// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/281/json-object-member-with-key-scope-has-null
	public void testParseScopeNull()
		throws Exception {
		
		String json = "{\"access_token\":\"valid access token with a lot of characters\",\"expires_in\":1800,\"" +
			"token_type\":\"bearer\",\"scope\":null,\"refresh_token\":\"valid refresh token\"}";
		
		AccessTokenResponse response = AccessTokenResponse.parse(JSONObjectUtils.parse(json));
		assertEquals("valid access token with a lot of characters", response.getTokens().getBearerAccessToken().getValue());
		assertEquals(1800L, response.getTokens().getBearerAccessToken().getLifetime());
		assertEquals("valid refresh token", response.getTokens().getRefreshToken().getValue());
		assertNull(response.getTokens().getAccessToken().getScope());
	}


	// https://www.rfc-editor.org/rfc/rfc9396.html#figure-15
	public void testParseRAR()
		throws Exception {

		String jsonString = "{" +
			"   \"access_token\": \"2YotnFZFEjr1zCsicMWpAA\"," +
			"   \"token_type\": \"Bearer\"," +
			"   \"expires_in\": 3600," +
			"   \"refresh_token\": \"tGzv3JOkF0XG5Qx2TlKWIA\"," +
			"   \"authorization_details\": [" +
			"      {" +
			"         \"type\": \"payment_initiation\"," +
			"         \"actions\": [" +
			"            \"initiate\"," +
			"            \"status\"," +
			"            \"cancel\"" +
			"         ]," +
			"         \"locations\": [" +
			"            \"https://example.com/payments\"" +
			"         ]," +
			"         \"instructedAmount\": {" +
			"            \"currency\": \"EUR\"," +
			"            \"amount\": \"123.50\"" +
			"         }," +
			"         \"creditorName\": \"Merchant A\"," +
			"         \"creditorAccount\": {" +
			"            \"iban\": \"DE02100100109307118603\"" +
			"         }," +
			"         \"remittanceInformationUnstructured\": \"Ref Number Merchant\"" +
			"      }" +
			"   ]" +
			"}";

		AccessTokenResponse response = AccessTokenResponse.parse(JSONObjectUtils.parse(jsonString));

		AuthorizationDetail authzDetail = AuthorizationDetail.parse(
				JSONObjectUtils.parse(
				"{" +
				"         \"type\": \"payment_initiation\"," +
				"         \"actions\": [" +
				"            \"initiate\"," +
				"            \"status\"," +
				"            \"cancel\"" +
				"         ]," +
				"         \"locations\": [" +
				"            \"https://example.com/payments\"" +
				"         ]," +
				"         \"instructedAmount\": {" +
				"            \"currency\": \"EUR\"," +
				"            \"amount\": \"123.50\"" +
				"         }," +
				"         \"creditorName\": \"Merchant A\"," +
				"         \"creditorAccount\": {" +
				"            \"iban\": \"DE02100100109307118603\"" +
				"         }," +
				"         \"remittanceInformationUnstructured\": \"Ref Number Merchant\"" +
				"}"));

		assertEquals(
			new BearerAccessToken(
				"2YotnFZFEjr1zCsicMWpAA",
				3600,
				null,
				Collections.singletonList(authzDetail),
				null
				),
			response.getTokens().getBearerAccessToken()
		);

		assertEquals(
			new RefreshToken("tGzv3JOkF0XG5Qx2TlKWIA"),
			response.getTokens().getRefreshToken()
		);
	}


	// https://datatracker.ietf.org/doc/html/rfc8693#section-2.3
	public void testParseTokenExchangeResponse()
		throws Exception {
		String jsonString = "\n"
				+ "    {\n"
				+ "     \"access_token\":\"eyJhbGciOiJFUzI1NiIsImtpZCI6IjllciJ9.eyJhdWQiOiJodHRwczovL2JhY2tlbmQuZXhhbXBsZS5jb20i"
				+ "LCJpc3MiOiJodHRwczovL2FzLmV4YW1wbGUuY29tIiwiZXhwIjoxNDQxOTE3NTkzLCJpYXQiOjE0NDE5MTc1MzMsInN1YiI6ImJkY0BleGFt"
				+ "cGxlLmNvbSIsInNjb3BlIjoiYXBpIn0.40y3ZgQedw6rxf59WlwHDD9jryFOr0_Wh3CGozQBihNBhnXEQgU85AI9x3KmsPottVMLPIWvmDCMy"
				+ "5-kdXjwhw\",\n"
				+ "     \"issued_token_type\":\n"
				+ "         \"urn:ietf:params:oauth:token-type:access_token\",\n"
				+ "     \"token_type\":\"Bearer\",\n"
				+ "     \"expires_in\":60\n"
				+ "    }";

		String expectedAccessToken = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjllciJ9.eyJhdWQiOiJodHRwczovL2JhY2tlbmQuZXhhbXBsZS5jb20i"
				+ "LCJpc3MiOiJodHRwczovL2FzLmV4YW1wbGUuY29tIiwiZXhwIjoxNDQxOTE3NTkzLCJpYXQiOjE0NDE5MTc1MzMsInN1YiI6ImJkY0BleGFt"
				+ "cGxlLmNvbSIsInNjb3BlIjoiYXBpIn0.40y3ZgQedw6rxf59WlwHDD9jryFOr0_Wh3CGozQBihNBhnXEQgU85AI9x3KmsPottVMLPIWvmDCMy"
				+ "5-kdXjwhw";

		AccessTokenResponse response = AccessTokenResponse.parse(JSONObjectUtils.parse(jsonString));
		BearerAccessToken bearerAccessToken = response.getTokens().getBearerAccessToken();
		assertEquals(expectedAccessToken, bearerAccessToken.getValue());
		assertEquals(60, bearerAccessToken.getLifetime());
		assertEquals(TokenTypeURI.ACCESS_TOKEN, bearerAccessToken.getIssuedTokenType());
		assertNull(bearerAccessToken.getScope());
	}
}
