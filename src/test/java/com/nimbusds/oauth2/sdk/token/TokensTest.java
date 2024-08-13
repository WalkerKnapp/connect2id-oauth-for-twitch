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


import java.util.Collections;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;


/**
 * Tests the token pair class.
 */
public class TokensTest extends TestCase {


	public void testBearerAllDefined()
		throws ParseException {

		AccessToken accessToken = new BearerAccessToken(
			"Chei4euPai5Phai0mohnaexeex7shou4",
			60L,
			Scope.parse("openid email"),
			TokenTypeURI.ACCESS_TOKEN
		);
		RefreshToken refreshToken = new RefreshToken();

		Tokens tokens = new Tokens(accessToken, refreshToken);

		assertEquals(accessToken, tokens.getAccessToken());
		assertEquals(accessToken, tokens.getBearerAccessToken());
		assertNull(tokens.getDPoPAccessToken());
		assertEquals(refreshToken, tokens.getRefreshToken());

		assertTrue(tokens.getParameterNames().contains("token_type"));
		assertTrue(tokens.getParameterNames().contains("access_token"));
		assertTrue(tokens.getParameterNames().contains("expires_in"));
		assertTrue(tokens.getParameterNames().contains("scope"));
		assertTrue(tokens.getParameterNames().contains("issued_token_type"));
		assertTrue(tokens.getParameterNames().contains("refresh_token"));
		assertEquals(6, tokens.getParameterNames().size());

		JSONObject jsonObject = tokens.toJSONObject();
		assertEquals("Bearer", jsonObject.get("token_type"));
		assertEquals(accessToken.getValue(), jsonObject.get("access_token"));
		assertEquals(60L, jsonObject.get("expires_in"));
		assertEquals("openid email", jsonObject.get("scope"));
		assertEquals(TokenTypeURI.ACCESS_TOKEN.getURI().toString(), jsonObject.get("issued_token_type"));
		assertEquals(refreshToken.getValue(), jsonObject.get("refresh_token"));
		assertEquals(6, jsonObject.size());

		tokens = Tokens.parse(jsonObject);

		assertEquals(accessToken.getValue(), tokens.getAccessToken().getValue());
		assertEquals(accessToken.getLifetime(), tokens.getAccessToken().getLifetime());
		assertEquals(accessToken.getScope(), tokens.getAccessToken().getScope());
		assertEquals(accessToken.getIssuedTokenType(), tokens.getAccessToken().getIssuedTokenType());
		assertEquals(refreshToken.getValue(), tokens.getRefreshToken().getValue());
	}


	public void testDPoPAllDefined()
		throws ParseException {

		AccessToken accessToken = new DPoPAccessToken(
			"Chei4euPai5Phai0mohnaexeex7shou4",
			60L,
			Scope.parse("openid email"),
			TokenTypeURI.ACCESS_TOKEN
		);
		RefreshToken refreshToken = new RefreshToken();

		Tokens tokens = new Tokens(accessToken, refreshToken);

		assertEquals(accessToken, tokens.getAccessToken());
		assertNull(tokens.getBearerAccessToken());
		assertEquals(accessToken, tokens.getDPoPAccessToken());
		assertEquals(refreshToken, tokens.getRefreshToken());

		assertTrue(tokens.getParameterNames().contains("token_type"));
		assertTrue(tokens.getParameterNames().contains("access_token"));
		assertTrue(tokens.getParameterNames().contains("expires_in"));
		assertTrue(tokens.getParameterNames().contains("scope"));
		assertTrue(tokens.getParameterNames().contains("refresh_token"));
		assertTrue(tokens.getParameterNames().contains("issued_token_type"));
		assertEquals(6, tokens.getParameterNames().size());

		JSONObject jsonObject = tokens.toJSONObject();
		assertEquals("DPoP", jsonObject.get("token_type"));
		assertEquals(accessToken.getValue(), jsonObject.get("access_token"));
		assertEquals(60L, jsonObject.get("expires_in"));
		assertEquals("openid email", jsonObject.get("scope"));
		assertEquals(TokenTypeURI.ACCESS_TOKEN.getURI().toString(), jsonObject.get("issued_token_type"));
		assertEquals(refreshToken.getValue(), jsonObject.get("refresh_token"));
		assertEquals(6, jsonObject.size());

		tokens = Tokens.parse(jsonObject);

		assertEquals(accessToken.getValue(), tokens.getAccessToken().getValue());
		assertEquals(accessToken.getLifetime(), tokens.getAccessToken().getLifetime());
		assertEquals(accessToken.getScope(), tokens.getAccessToken().getScope());
		assertEquals(accessToken.getIssuedTokenType(), tokens.getAccessToken().getIssuedTokenType());
		assertEquals(refreshToken.getValue(), tokens.getRefreshToken().getValue());
	}


	public void testMinimalAccessTokenOnly()
		throws ParseException {

		AccessToken accessToken = new BearerAccessToken();

		Tokens tokens = new Tokens(accessToken, null);

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

		tokens = Tokens.parse(jsonObject);

		assertEquals(accessToken.getValue(), tokens.getAccessToken().getValue());
		assertEquals(0, tokens.getAccessToken().getLifetime());
		assertNull(tokens.getAccessToken().getScope());
		assertNull(tokens.getAccessToken().getIssuedTokenType());
		assertNull(tokens.getRefreshToken());
	}
	
	
	public void testMetadata() {
		Tokens tokens = new Tokens(new BearerAccessToken(), new RefreshToken());
		assertTrue(tokens.getMetadata().isEmpty());
		tokens.getMetadata().put("key", "value");
		assertEquals(Collections.singletonMap("key", "value"), tokens.getMetadata());
		tokens.getMetadata().clear();
		assertTrue(tokens.getMetadata().isEmpty());
	}


	public void testMissingAccessToken() {

		try {
			new Tokens(null, null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testToBearerAccessToken_recreate() {
		
		String value = "a45e77b1-5af1-4a84-b500-e94d123b1103";
		long lifetime = 3600;
		Scope scope = new Scope("read", "write");
		TokenTypeURI tokenTypeURI = TokenTypeURI.ACCESS_TOKEN;
		
		AccessToken accessToken = new AccessToken(AccessTokenType.BEARER, value, lifetime, scope, tokenTypeURI) {
			@Override
			public String toAuthorizationHeader() {
				throw new UnsupportedOperationException();
			}
		};
		
		Tokens tokens = new Tokens(accessToken, null);
		
		BearerAccessToken bearerAccessToken = tokens.getBearerAccessToken();
		assertEquals(AccessTokenType.BEARER, bearerAccessToken.getType());
		assertEquals(value, bearerAccessToken.getValue());
		assertEquals(lifetime, bearerAccessToken.getLifetime());
		assertEquals(scope, bearerAccessToken.getScope());
		assertEquals(tokenTypeURI, bearerAccessToken.getIssuedTokenType());
	}
	
	
	public void testToDPoPAccessToken_recreate() {
		
		String value = "a45e77b1-5af1-4a84-b500-e94d123b1103";
		long lifetime = 3600;
		Scope scope = new Scope("read", "write");
		TokenTypeURI tokenTypeURI = TokenTypeURI.ACCESS_TOKEN;
		
		AccessToken accessToken = new AccessToken(AccessTokenType.DPOP, value, lifetime, scope, tokenTypeURI) {
			@Override
			public String toAuthorizationHeader() {
				throw new UnsupportedOperationException();
			}
		};
		
		Tokens tokens = new Tokens(accessToken, null);
		
		DPoPAccessToken dPoPAccessToken = tokens.getDPoPAccessToken();
		assertEquals(AccessTokenType.DPOP, dPoPAccessToken.getType());
		assertEquals(value, dPoPAccessToken.getValue());
		assertEquals(lifetime, dPoPAccessToken.getLifetime());
		assertEquals(scope, dPoPAccessToken.getScope());
		assertEquals(tokenTypeURI, dPoPAccessToken.getIssuedTokenType());
	}
}