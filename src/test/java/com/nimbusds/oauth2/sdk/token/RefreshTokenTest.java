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
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


public class RefreshTokenTest extends TestCase {


	public void testValueConstructor() {

		RefreshToken rt = new RefreshToken("abc");
		assertEquals("abc", rt.getValue());
		assertTrue(rt.getParameterNames().contains("refresh_token"));
		assertEquals(1, rt.getParameterNames().size());
	}


	public void testGeneratorConstructor() {

		RefreshToken rt = new RefreshToken(16);
		assertEquals(16, new Base64(rt.getValue()).decode().length);
		assertTrue(rt.getParameterNames().contains("refresh_token"));
		assertEquals(1, rt.getParameterNames().size());
	}


	public void testCustomParameters() {

		RefreshToken rt = new RefreshToken("abc");
		assertTrue(rt.getCustomParameters().isEmpty());

		rt.getCustomParameters().put("refresh_token_expires_in", 3600L);

		assertEquals(3600L, rt.getCustomParameters().get("refresh_token_expires_in"));
		assertEquals(1, rt.getCustomParameters().size());

		assertTrue(rt.getParameterNames().contains("refresh_token"));
		assertTrue(rt.getParameterNames().contains("refresh_token_expires_in"));
		assertEquals(2, rt.getParameterNames().size());

		JSONObject jsonObject = rt.toJSONObject();
		assertEquals(rt.getValue(), jsonObject.get("refresh_token"));
		assertEquals(3600L, jsonObject.get("refresh_token_expires_in"));
		assertEquals(2, jsonObject.size());
	}


	public void testParseEmpty() {

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("refresh_token", "");

		try {
			RefreshToken.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal refresh token", e.getMessage());
		}
	}


	public void testParseBlank() {

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("refresh_token", "");

		try {
			RefreshToken.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal refresh token", e.getMessage());
		}
	}
}
