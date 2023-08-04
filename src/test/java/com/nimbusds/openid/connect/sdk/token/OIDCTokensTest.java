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
import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import java.util.Collections;


/**
 * Tests the OpenID Connect tokens class.
 */
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


	public static JWT ID_TOKEN;


	static {
		try {
			ID_TOKEN = JWTParser.parse(ID_TOKEN_STRING);
		} catch (Exception e) {
			ID_TOKEN = null;
		}
	}


	public void testAllDefined()
		throws ParseException {

		AccessToken accessToken = new BearerAccessToken(
			"Chei4euPai5Phai0mohnaexeex7shou4",
			60L,
			Scope.parse("openid email"),
			Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("example_api")).build()),
			TokenTypeURI.ACCESS_TOKEN
		);
		RefreshToken refreshToken = new RefreshToken();

		OIDCTokens tokens = new OIDCTokens(ID_TOKEN, accessToken, refreshToken);

		assertEquals(ID_TOKEN, tokens.getIDToken());
		assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
		assertEquals(accessToken, tokens.getAccessToken());
		assertEquals(accessToken, tokens.getBearerAccessToken());
		assertEquals(refreshToken, tokens.getRefreshToken());

		assertTrue(tokens.getParameterNames().contains("id_token"));
		assertTrue(tokens.getParameterNames().contains("token_type"));
		assertTrue(tokens.getParameterNames().contains("access_token"));
		assertTrue(tokens.getParameterNames().contains("expires_in"));
		assertTrue(tokens.getParameterNames().contains("scope"));
		assertTrue(tokens.getParameterNames().contains("authorization_details"));
		assertTrue(tokens.getParameterNames().contains("issued_token_type"));
		assertTrue(tokens.getParameterNames().contains("refresh_token"));
		assertEquals(8, tokens.getParameterNames().size());

		JSONObject jsonObject = tokens.toJSONObject();
		assertEquals(ID_TOKEN_STRING, jsonObject.get("id_token"));
		assertEquals("Bearer", jsonObject.get("token_type"));
		assertEquals(accessToken.getValue(), jsonObject.get("access_token"));
		assertEquals(60L, jsonObject.get("expires_in"));
		assertEquals("openid email", jsonObject.get("scope"));
		assertEquals(AuthorizationDetail.toJSONArray(accessToken.getAuthorizationDetails()), jsonObject.get("authorization_details"));
		assertEquals(accessToken.getIssuedTokenType().getURI().toString(), jsonObject.get("issued_token_type"));
		assertEquals(refreshToken.getValue(), jsonObject.get("refresh_token"));
		assertEquals(8, jsonObject.size());

		tokens = OIDCTokens.parse(jsonObject);

		assertEquals(ID_TOKEN.getParsedString(), tokens.getIDToken().getParsedString());
		assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
		assertEquals(accessToken.getValue(), tokens.getAccessToken().getValue());
		assertEquals(accessToken.getLifetime(), tokens.getAccessToken().getLifetime());
		assertEquals(accessToken.getScope(), tokens.getAccessToken().getScope());
		assertEquals(accessToken.getAuthorizationDetails(), tokens.getAccessToken().getAuthorizationDetails());
		assertEquals(accessToken.getIssuedTokenType(), tokens.getAccessToken().getIssuedTokenType());
		assertEquals(refreshToken.getValue(), tokens.getRefreshToken().getValue());
	}


	public void testAllDefined_fromIDTokenString()
		throws ParseException {
		
		AccessToken accessToken = new BearerAccessToken(
			"Chei4euPai5Phai0mohnaexeex7shou4",
			60L,
			Scope.parse("openid email"),
			Collections.singletonList(new AuthorizationDetail.Builder(new AuthorizationType("example_api")).build()),
			TokenTypeURI.ACCESS_TOKEN
		);
		RefreshToken refreshToken = new RefreshToken();

		OIDCTokens tokens = new OIDCTokens(ID_TOKEN_STRING, accessToken, refreshToken);

		assertEquals(ID_TOKEN_STRING, tokens.getIDToken().getParsedString());
		assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
		assertEquals(accessToken, tokens.getAccessToken());
		assertEquals(accessToken, tokens.getBearerAccessToken());
		assertEquals(refreshToken, tokens.getRefreshToken());

		assertTrue(tokens.getParameterNames().contains("id_token"));
		assertTrue(tokens.getParameterNames().contains("token_type"));
		assertTrue(tokens.getParameterNames().contains("access_token"));
		assertTrue(tokens.getParameterNames().contains("expires_in"));
		assertTrue(tokens.getParameterNames().contains("scope"));
		assertTrue(tokens.getParameterNames().contains("authorization_details"));
		assertTrue(tokens.getParameterNames().contains("issued_token_type"));
		assertTrue(tokens.getParameterNames().contains("refresh_token"));
		assertEquals(8, tokens.getParameterNames().size());

		JSONObject jsonObject = tokens.toJSONObject();
		assertEquals(ID_TOKEN_STRING, jsonObject.get("id_token"));
		assertEquals("Bearer", jsonObject.get("token_type"));
		assertEquals(accessToken.getValue(), jsonObject.get("access_token"));
		assertEquals(60L, jsonObject.get("expires_in"));
		assertEquals("openid email", jsonObject.get("scope"));
		assertEquals(AuthorizationDetail.toJSONArray(accessToken.getAuthorizationDetails()), jsonObject.get("authorization_details"));
		assertEquals(accessToken.getIssuedTokenType().getURI().toString(), jsonObject.get("issued_token_type"));
		assertEquals(refreshToken.getValue(), jsonObject.get("refresh_token"));
		assertEquals(8, jsonObject.size());

		tokens = OIDCTokens.parse(jsonObject);

		assertEquals(ID_TOKEN_STRING, tokens.getIDToken().getParsedString());
		assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
		assertEquals(accessToken.getValue(), tokens.getAccessToken().getValue());
		assertEquals(accessToken.getLifetime(), tokens.getAccessToken().getLifetime());
		assertEquals(accessToken.getScope(), tokens.getAccessToken().getScope());
		assertEquals(accessToken.getAuthorizationDetails(), tokens.getAccessToken().getAuthorizationDetails());
		assertEquals(accessToken.getIssuedTokenType(), tokens.getAccessToken().getIssuedTokenType());
		assertEquals(refreshToken.getValue(), tokens.getRefreshToken().getValue());
	}


	// The token response from a refresh token grant may not include an id_token
	public void testNoIDToken()
		throws ParseException {

		AccessToken accessToken = new BearerAccessToken();

		OIDCTokens tokens = new OIDCTokens(accessToken, null);

		assertNull(tokens.getIDToken());
		assertNull(tokens.getIDTokenString());
		assertEquals(accessToken, tokens.getAccessToken());
		assertEquals(accessToken, tokens.getBearerAccessToken());
		assertNull(tokens.getRefreshToken());

		assertTrue(tokens.getParameterNames().contains("token_type"));
		assertTrue(tokens.getParameterNames().contains("access_token"));
		assertEquals(2, tokens.getParameterNames().size());

		JSONObject jsonObject = tokens.toJSONObject();
		assertEquals("Bearer", jsonObject.get("token_type"));
		assertEquals(accessToken.getValue(), jsonObject.get("access_token"));
		assertEquals(2, jsonObject.size());

		tokens = OIDCTokens.parse(jsonObject);

		assertNull(tokens.getIDToken());
		assertNull(tokens.getIDTokenString());
		assertEquals(accessToken.getValue(), tokens.getAccessToken().getValue());
		assertEquals(0L, tokens.getAccessToken().getLifetime());
		assertNull(tokens.getAccessToken().getScope());
		assertNull(tokens.getRefreshToken());
	}


	public void testMinimal()
		throws ParseException {

		AccessToken accessToken = new BearerAccessToken();

		OIDCTokens tokens = new OIDCTokens(ID_TOKEN, accessToken, null);

		assertEquals(ID_TOKEN, tokens.getIDToken());
		assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
		assertEquals(accessToken, tokens.getAccessToken());
		assertEquals(accessToken, tokens.getBearerAccessToken());
		assertNull(tokens.getRefreshToken());

		assertTrue(tokens.getParameterNames().contains("id_token"));
		assertTrue(tokens.getParameterNames().contains("token_type"));
		assertTrue(tokens.getParameterNames().contains("access_token"));
		assertEquals(3, tokens.getParameterNames().size());

		JSONObject jsonObject = tokens.toJSONObject();
		assertEquals(ID_TOKEN_STRING, jsonObject.get("id_token"));
		assertEquals("Bearer", jsonObject.get("token_type"));
		assertEquals(accessToken.getValue(), jsonObject.get("access_token"));
		assertEquals(3, jsonObject.size());

		tokens = OIDCTokens.parse(jsonObject);

		assertEquals(ID_TOKEN.getParsedString(), tokens.getIDToken().getParsedString());
		assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
		assertEquals(accessToken.getValue(), tokens.getAccessToken().getValue());
		assertEquals(0L, tokens.getAccessToken().getLifetime());
		assertNull(tokens.getAccessToken().getScope());
		assertNull(tokens.getAccessToken().getAuthorizationDetails());
		assertNull(tokens.getAccessToken().getIssuedTokenType());
		assertNull(tokens.getRefreshToken());
	}


	public void testMinimal_fromIDTokenString()
		throws ParseException {

		AccessToken accessToken = new BearerAccessToken();

		OIDCTokens tokens = new OIDCTokens(ID_TOKEN_STRING, accessToken, null);

		assertEquals(ID_TOKEN_STRING, tokens.getIDToken().getParsedString());
		assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
		assertEquals(accessToken, tokens.getAccessToken());
		assertEquals(accessToken, tokens.getBearerAccessToken());
		assertNull(tokens.getRefreshToken());

		assertTrue(tokens.getParameterNames().contains("id_token"));
		assertTrue(tokens.getParameterNames().contains("token_type"));
		assertTrue(tokens.getParameterNames().contains("access_token"));
		assertEquals(3, tokens.getParameterNames().size());

		JSONObject jsonObject = tokens.toJSONObject();
		assertEquals(ID_TOKEN_STRING, jsonObject.get("id_token"));
		assertEquals("Bearer", jsonObject.get("token_type"));
		assertEquals(accessToken.getValue(), jsonObject.get("access_token"));
		assertEquals(3, jsonObject.size());

		tokens = OIDCTokens.parse(jsonObject);

		assertEquals(ID_TOKEN_STRING, tokens.getIDToken().getParsedString());
		assertEquals(ID_TOKEN_STRING, tokens.getIDTokenString());
		assertEquals(accessToken.getValue(), tokens.getAccessToken().getValue());
		assertEquals(0L, tokens.getAccessToken().getLifetime());
		assertNull(tokens.getAccessToken().getScope());
		assertNull(tokens.getAccessToken().getAuthorizationDetails());
		assertNull(tokens.getAccessToken().getIssuedTokenType());
		assertNull(tokens.getRefreshToken());
	}


	public void testMissingIDToken() {

		try {
			new OIDCTokens((JWT)null, new BearerAccessToken(), null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The ID token must not be null", e.getMessage());
		}
	}


	public void testMissingIDTokenString() {

		try {
			new OIDCTokens((String)null, new BearerAccessToken(), null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The ID token string must not be null", e.getMessage());
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
		
		AccessToken accessToken = new BearerAccessToken(
			"eviegheing6pee2I",
			60L,
			Scope.parse("openid email"),
			TokenTypeURI.ACCESS_TOKEN
		);
		RefreshToken refreshToken = new RefreshToken();
		
		Tokens tokens = new OIDCTokens(ID_TOKEN, accessToken, refreshToken);
		
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
}
