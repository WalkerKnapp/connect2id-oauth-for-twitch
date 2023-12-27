/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


public class NAAccessTokenTest extends TestCase {


	public void testConstructAndParse()
		throws ParseException {
		
		String tokenValue = "paip0cotheCh0Quahshaithoono1fie4";
		long lifetime = 60L;
		Scope scope = new Scope("read", "write");
		NAAccessToken naToken = new NAAccessToken(tokenValue, lifetime, scope, TokenTypeURI.JWT);
		
		assertEquals(AccessTokenType.N_A, naToken.getType());
		assertEquals(tokenValue, naToken.getValue());
		assertEquals(lifetime, naToken.getLifetime());
		assertEquals(scope, naToken.getScope());
		assertEquals(TokenTypeURI.JWT, naToken.getIssuedTokenType());
		
		JSONObject jsonObject = naToken.toJSONObject();
		
		naToken = NAAccessToken.parse(jsonObject);
		
		assertEquals(AccessTokenType.N_A, naToken.getType());
		assertEquals(tokenValue, naToken.getValue());
		assertEquals(lifetime, naToken.getLifetime());
		assertEquals(scope, naToken.getScope());
		assertEquals(TokenTypeURI.JWT, naToken.getIssuedTokenType());
	}


	public void testConstructAndParseMinimal()
		throws ParseException {
		
		String tokenValue = "paip0cotheCh0Quahshaithoono1fie4";
		NAAccessToken naToken = new NAAccessToken(tokenValue, 0L, null, null);
		
		assertEquals(AccessTokenType.N_A, naToken.getType());
		assertEquals(tokenValue, naToken.getValue());
		assertEquals(0L, naToken.getLifetime());
		assertNull(naToken.getScope());
		assertNull(naToken.getIssuedTokenType());
		
		JSONObject jsonObject = naToken.toJSONObject();
		
		naToken = NAAccessToken.parse(jsonObject);
		
		assertEquals(AccessTokenType.N_A, naToken.getType());
		assertEquals(tokenValue, naToken.getValue());
		assertEquals(0L, naToken.getLifetime());
		assertNull(naToken.getScope());
		assertNull(naToken.getIssuedTokenType());
	}
	
	
	public void testToAuthorizationHeaderNotSupported() {
		
		String tokenValue = "paip0cotheCh0Quahshaithoono1fie4";
		
		NAAccessToken naToken = new NAAccessToken(tokenValue, 0L, null, null);
		
		Exception exception = null;
		try {
			naToken.toAuthorizationHeader();
			fail();
		} catch (UnsupportedOperationException e) {
			exception = e;
		}
		assertTrue(exception instanceof UnsupportedOperationException);
	}


	public void testCustomParameters() {

		NAAccessToken token = new NAAccessToken("abc", 600L, new Scope("read"), TokenTypeURI.ACCESS_TOKEN);

		assertTrue(token.getCustomParameters().isEmpty());

		token.getCustomParameters().put("access_token_x", "xyz");

		assertEquals("xyz", token.getCustomParameters().get("access_token_x"));
		assertEquals(1, token.getCustomParameters().size());

		assertTrue(token.getParameterNames().contains("token_type"));
		assertTrue(token.getParameterNames().contains("issued_token_type"));
		assertTrue(token.getParameterNames().contains("access_token"));
		assertTrue(token.getParameterNames().contains("expires_in"));
		assertTrue(token.getParameterNames().contains("scope"));
		assertTrue(token.getParameterNames().contains("access_token_x"));
		assertEquals(6, token.getParameterNames().size());

		JSONObject jsonObject = token.toJSONObject();
		assertEquals(token.getType().getValue(), jsonObject.get("token_type"));
		assertEquals(token.getIssuedTokenType().getURI().toString(), jsonObject.get("issued_token_type"));
		assertEquals(token.getValue(), jsonObject.get("access_token"));
		assertEquals(token.getLifetime(), jsonObject.get("expires_in"));
		assertEquals(token.getScope().toString(), jsonObject.get("scope"));
		assertEquals("xyz", jsonObject.get("access_token_x"));
		assertEquals(6, jsonObject.size());
	}
}
