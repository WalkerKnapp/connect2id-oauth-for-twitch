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

package com.nimbusds.openid.connect.sdk.token;


import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail;
import com.nimbusds.oauth2.sdk.rar.AuthorizationType;
import com.nimbusds.oauth2.sdk.token.*;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.nativesso.DeviceSecret;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import java.util.Arrays;
import java.util.Collections;


public class OIDCTokensTest extends TestCase {


	// Example ID token from OIDC Standard
	private static final String ID_TOKEN_STRING =
		"eyJhbGciOiJSUzI1NiJ9.ew0KICAgICJpc3MiOiAiaHR0cDovL"+
		"3NlcnZlci5leGFtcGxlLmNvbSIsDQogICAgInVzZXJfaWQiOiAiMjQ4Mjg5NzYxM"+
		"DAxIiwNCiAgICAiYXVkIjogInM2QmhkUmtxdDMiLA0KICAgICJub25jZSI6ICJuL"+
		"TBTNl9XekEyTWoiLA0KICAgICJleHAiOiAxMzExMjgxOTcwLA0KICAgICJpYXQiO"+
		"iAxMzExMjgwOTcwDQp9.lsQI_KNHpl58YY24G9tUHXr3Yp7OKYnEaVpRL0KI4szT"+
		"D6GXpZcgxIpkOCcajyDiIv62R9rBWASV191Akk1BM36gUMm8H5s8xyxNdRfBViCa"+
		"xTqHA7X_vV3U-tSWl6McR5qaSJaNQBpg1oGPjZdPG7zWCG-yEJC4-Fbx2FPOS7-h"+
		"5V0k33O5Okd-OoDUKoFPMd6ur5cIwsNyBazcsHdFHqWlCby5nl_HZdW-PHq0gjzy"+
		"JydB5eYIvOfOHYBRVML9fKwdOLM2xVxJsPwvy3BqlVKc593p2WwItIg52ILWrc6A"+
		"tqkqHxKsAXLVyAoVInYkl_NDBkCqYe2KgNJFzfEC8g";

	private static final BearerAccessToken BEARER_ACCESS_TOKEN_ALL_SET =
		new BearerAccessToken(
			"Chei4euPai5Phai0mohnaexeex7shou4",
			60L,
			Scope.parse("openid email"),
			Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("example_api")).build()),
			TokenTypeURI.ACCESS_TOKEN
		);

	private static final BearerAccessToken BEARER_ACCESS_TOKEN_MINIMAL =
		new BearerAccessToken(
			"Chei4euPai5Phai0mohnaexeex7shou4",
			60L,
			null);


	private static final RefreshToken REFRESH_TOKEN = new RefreshToken();

	private static final DeviceSecret DEVICE_SECRET = new DeviceSecret("cc0abf90-dd97-45bb-a778-269813e695c9");


	public static JWT ID_TOKEN;


	static {
		try {
			ID_TOKEN = JWTParser.parse(ID_TOKEN_STRING);
		} catch (Exception e) {
			ID_TOKEN = null;
		}
	}


	public void testIDTokenConstructor()
		throws ParseException {

		for (RefreshToken refreshToken: Arrays.asList(REFRESH_TOKEN, null)) {

			OIDCTokens tokens = new OIDCTokens(ID_TOKEN, BEARER_ACCESS_TOKEN_ALL_SET, refreshToken);

			assertEquals(ID_TOKEN, tokens.getIDToken());
			assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET, tokens.getAccessToken());
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET, tokens.getBearerAccessToken());
			assertEquals(refreshToken, tokens.getRefreshToken());
			assertNull(tokens.getDeviceSecret());

			assertTrue(tokens.getParameterNames().contains("id_token"));
			assertTrue(tokens.getParameterNames().contains("token_type"));
			assertTrue(tokens.getParameterNames().contains("access_token"));
			assertTrue(tokens.getParameterNames().contains("expires_in"));
			assertTrue(tokens.getParameterNames().contains("scope"));
			assertTrue(tokens.getParameterNames().contains("authorization_details"));
			assertTrue(tokens.getParameterNames().contains("issued_token_type"));
			if (refreshToken != null) {
				assertTrue(tokens.getParameterNames().contains("refresh_token"));
			}
			assertEquals(refreshToken != null ? 8 : 7, tokens.getParameterNames().size());

			JSONObject jsonObject = tokens.toJSONObject();
			assertEquals(ID_TOKEN_STRING, jsonObject.get("id_token"));
			assertEquals("Bearer", jsonObject.get("token_type"));
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET.getValue(), jsonObject.get("access_token"));
			assertEquals(60L, jsonObject.get("expires_in"));
			assertEquals("openid email", jsonObject.get("scope"));
			assertEquals(AuthorizationDetail.toJSONArray(BEARER_ACCESS_TOKEN_ALL_SET.getAuthorizationDetails()), jsonObject.get("authorization_details"));
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET.getIssuedTokenType().getURI().toString(), jsonObject.get("issued_token_type"));
			assertEquals(refreshToken != null ? refreshToken.getValue() : null, jsonObject.get("refresh_token"));
			assertEquals(refreshToken != null ? 8 : 7, jsonObject.size());

			tokens = OIDCTokens.parse(jsonObject);

			assertEquals(ID_TOKEN.getParsedString(), tokens.getIDToken().getParsedString());
			assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET.getValue(), tokens.getAccessToken().getValue());
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET.getLifetime(), tokens.getAccessToken().getLifetime());
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET.getScope(), tokens.getAccessToken().getScope());
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET.getAuthorizationDetails(), tokens.getAccessToken().getAuthorizationDetails());
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET.getIssuedTokenType(), tokens.getAccessToken().getIssuedTokenType());
			assertEquals(refreshToken, tokens.getRefreshToken());
			assertNull(tokens.getDeviceSecret());
		}
	}


	public void testIDTokenConstructor_idTokenString()
		throws ParseException {

		for (RefreshToken refreshToken: Arrays.asList(REFRESH_TOKEN, null)) {

			OIDCTokens tokens = new OIDCTokens(ID_TOKEN_STRING, BEARER_ACCESS_TOKEN_ALL_SET, refreshToken);

			assertEquals(ID_TOKEN_STRING, tokens.getIDToken().getParsedString());
			assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET, tokens.getAccessToken());
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET, tokens.getBearerAccessToken());
			assertEquals(refreshToken, tokens.getRefreshToken());
			assertNull(tokens.getDeviceSecret());

			assertTrue(tokens.getParameterNames().contains("id_token"));
			assertTrue(tokens.getParameterNames().contains("token_type"));
			assertTrue(tokens.getParameterNames().contains("access_token"));
			assertTrue(tokens.getParameterNames().contains("expires_in"));
			assertTrue(tokens.getParameterNames().contains("scope"));
			assertTrue(tokens.getParameterNames().contains("authorization_details"));
			assertTrue(tokens.getParameterNames().contains("issued_token_type"));
			if (refreshToken != null) {
				assertTrue(tokens.getParameterNames().contains("refresh_token"));
			}
			assertEquals(refreshToken != null ? 8 : 7, tokens.getParameterNames().size());

			JSONObject jsonObject = tokens.toJSONObject();
			assertEquals(ID_TOKEN_STRING, jsonObject.get("id_token"));
			assertEquals("Bearer", jsonObject.get("token_type"));
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET.getValue(), jsonObject.get("access_token"));
			assertEquals(60L, jsonObject.get("expires_in"));
			assertEquals("openid email", jsonObject.get("scope"));
			assertEquals(AuthorizationDetail.toJSONArray(BEARER_ACCESS_TOKEN_ALL_SET.getAuthorizationDetails()), jsonObject.get("authorization_details"));
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET.getIssuedTokenType().getURI().toString(), jsonObject.get("issued_token_type"));
			assertEquals(refreshToken != null ? refreshToken.getValue() : null, jsonObject.get("refresh_token"));
			assertEquals(refreshToken != null ? 8 : 7, jsonObject.size());

			tokens = OIDCTokens.parse(jsonObject);

			assertEquals(ID_TOKEN_STRING, tokens.getIDToken().getParsedString());
			assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET.getValue(), tokens.getAccessToken().getValue());
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET.getLifetime(), tokens.getAccessToken().getLifetime());
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET.getScope(), tokens.getAccessToken().getScope());
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET.getAuthorizationDetails(), tokens.getAccessToken().getAuthorizationDetails());
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET.getIssuedTokenType(), tokens.getAccessToken().getIssuedTokenType());
			assertEquals(refreshToken, tokens.getRefreshToken());
			assertNull(tokens.getDeviceSecret());
		}
	}


	public void testIDTokenConstructor_withDeviceSecret() throws ParseException {

		for (OIDCTokens tokens: Arrays.asList(
			new OIDCTokens(ID_TOKEN, BEARER_ACCESS_TOKEN_MINIMAL, null, DEVICE_SECRET),
			new OIDCTokens(ID_TOKEN_STRING, BEARER_ACCESS_TOKEN_MINIMAL, null, DEVICE_SECRET))) {

			assertEquals(ID_TOKEN.serialize(), tokens.getIDToken().serialize());
			assertEquals(ID_TOKEN_STRING, tokens.getIDToken().serialize());
			assertEquals(BEARER_ACCESS_TOKEN_MINIMAL, tokens.getBearerAccessToken());
			assertEquals(DEVICE_SECRET, tokens.getDeviceSecret());

			assertTrue(tokens.getParameterNames().contains("device_secret"));

			JSONObject jsonObject = tokens.toJSONObject();

			tokens = OIDCTokens.parse(jsonObject);

			assertEquals(DEVICE_SECRET.getValue(), jsonObject.get("device_secret"));

			assertEquals(ID_TOKEN.serialize(), tokens.getIDToken().serialize());
			assertEquals(ID_TOKEN_STRING, tokens.getIDToken().serialize());
			assertEquals(BEARER_ACCESS_TOKEN_MINIMAL, tokens.getBearerAccessToken());
			assertEquals(DEVICE_SECRET, tokens.getDeviceSecret());
		}
	}


	// The token response from a refresh token grant may not include an id_token
	public void testNoIDTokenConstructor()
		throws ParseException {

		for (RefreshToken refreshToken : Arrays.asList(REFRESH_TOKEN, null)) {

			OIDCTokens tokens = new OIDCTokens(BEARER_ACCESS_TOKEN_MINIMAL, refreshToken);

			assertNull(tokens.getIDToken());
			assertNull(tokens.getIDTokenString());
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET, tokens.getAccessToken());
			assertEquals(BEARER_ACCESS_TOKEN_ALL_SET, tokens.getBearerAccessToken());
			assertEquals(refreshToken, tokens.getRefreshToken());
			assertNull(tokens.getDeviceSecret());

			assertTrue(tokens.getParameterNames().contains("token_type"));
			assertTrue(tokens.getParameterNames().contains("access_token"));
			assertTrue(tokens.getParameterNames().contains("expires_in"));
			if (refreshToken != null) {
				assertTrue(tokens.getParameterNames().contains("refresh_token"));
			}
			assertEquals(refreshToken != null ? 4 : 3, tokens.getParameterNames().size());

			JSONObject jsonObject = tokens.toJSONObject();
			assertEquals("Bearer", jsonObject.get("token_type"));
			assertEquals(BEARER_ACCESS_TOKEN_MINIMAL.getValue(), jsonObject.get("access_token"));
			assertEquals(BEARER_ACCESS_TOKEN_MINIMAL.getLifetime(), jsonObject.get("expires_in"));
			assertEquals(refreshToken != null ? refreshToken.getValue() : null, jsonObject.get("refresh_token"));
			assertEquals(refreshToken != null ? 4 : 3, jsonObject.size());

			tokens = OIDCTokens.parse(jsonObject);

			assertNull(tokens.getIDToken());
			assertNull(tokens.getIDTokenString());
			assertEquals(BEARER_ACCESS_TOKEN_MINIMAL.getValue(), tokens.getAccessToken().getValue());
			assertEquals(BEARER_ACCESS_TOKEN_MINIMAL.getLifetime(), tokens.getAccessToken().getLifetime());
			assertNull(tokens.getAccessToken().getScope());
			assertEquals(refreshToken, tokens.getRefreshToken());
			assertNull(tokens.getDeviceSecret());
		}
	}


	public void testNoIDTokenConstructor_withDeviceSecret() throws ParseException {

		OIDCTokens tokens = new OIDCTokens(BEARER_ACCESS_TOKEN_MINIMAL, null, DEVICE_SECRET);

		assertNull(tokens.getIDToken());
		assertNull(tokens.getIDToken());
		assertEquals(BEARER_ACCESS_TOKEN_MINIMAL, tokens.getBearerAccessToken());
		assertEquals(DEVICE_SECRET, tokens.getDeviceSecret());

		assertTrue(tokens.getParameterNames().contains("device_secret"));

		JSONObject jsonObject = tokens.toJSONObject();

		tokens = OIDCTokens.parse(jsonObject);

		assertEquals(DEVICE_SECRET.getValue(), jsonObject.get("device_secret"));

		assertNull(tokens.getIDToken());
		assertNull(tokens.getIDToken());
		assertEquals(BEARER_ACCESS_TOKEN_MINIMAL, tokens.getBearerAccessToken());
		assertEquals(DEVICE_SECRET, tokens.getDeviceSecret());
	}


	public void testMissingIDToken() {

		try {
			new OIDCTokens((JWT)null, new BearerAccessToken(), null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}

		try {
			new OIDCTokens((JWT)null, new BearerAccessToken(), null, null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}


	public void testMissingIDTokenString() {

		try {
			new OIDCTokens((String)null, new BearerAccessToken(), null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}

		try {
			new OIDCTokens((String)null, new BearerAccessToken(), null, null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}


	public void testParseInvalidIDToken() {

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("id_token", "ey..."); // invalid
		jsonObject.put("token_type", "Bearer");
		jsonObject.put("access_token", "abc123");
		jsonObject.put("expires_in", 60L);

		try {
			OIDCTokens.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertTrue(e.getMessage().startsWith("Couldn't parse ID token: Invalid unsecured/JWS/JWE header:"));
		}
	}
	
	
	public void testParseNullIDToken()
		throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("id_token", null); // invalid
		jsonObject.put("token_type", "Bearer");
		jsonObject.put("access_token", "abc123");
		jsonObject.put("expires_in", 60L);
		
		OIDCTokens oidcTokens = OIDCTokens.parse(jsonObject);
		
		assertNull(oidcTokens.getIDToken());
		assertNull(oidcTokens.getIDTokenString());
		
		assertEquals("abc123", oidcTokens.getAccessToken().getValue());
		assertEquals(60L, oidcTokens.getAccessToken().getLifetime());
		assertEquals(AccessTokenType.BEARER, oidcTokens.getAccessToken().getType());
	}
	
	
	public void testCastFromTokens() {
		
		Tokens tokens = new OIDCTokens(ID_TOKEN, BEARER_ACCESS_TOKEN_ALL_SET, REFRESH_TOKEN);
		
		OIDCTokens oidcTokens = tokens.toOIDCTokens();
		
		assertEquals(tokens, oidcTokens);
	}
	
	
	public void testMetadata() {
		OIDCTokens tokens = new OIDCTokens(new BearerAccessToken(), new RefreshToken());
		assertTrue(tokens.getMetadata().isEmpty());
		tokens.getMetadata().put("key", "value");
		assertEquals(Collections.singletonMap("key", "value"), tokens.getMetadata());
		tokens.getMetadata().clear();
		assertTrue(tokens.getMetadata().isEmpty());
	}
	
	
	public void testParseDeviceSecretExample() throws ParseException {
		
		String json = 
			"{" +
			"  \"access_token\":\"2YotnFZFEjr1zCsicMWpAA\"," +
			"  \"issued_token_type\": \"urn:ietf:params:oauth:token-type:access_token\"," +
			"  \"token_type\":\"Bearer\"," +
			"  \"expires_in\":3600," +
			"  \"refresh_token\":\"tGzv3JOkF0XG5Qx2TlKWIA\"," +
			"  \"device_secret\":\"casdfgarfgasdfg\"" +
			"}";

		OIDCTokens tokens = OIDCTokens.parse(JSONObjectUtils.parse(json));
		assertEquals("2YotnFZFEjr1zCsicMWpAA", tokens.getAccessToken().getValue());
		assertEquals(AccessTokenType.BEARER, tokens.getAccessToken().getType());
		assertEquals(3600L, tokens.getAccessToken().getLifetime());

		assertEquals(new RefreshToken("tGzv3JOkF0XG5Qx2TlKWIA"), tokens.getRefreshToken());

		assertEquals(new DeviceSecret("casdfgarfgasdfg"), tokens.getDeviceSecret());
	}
}
