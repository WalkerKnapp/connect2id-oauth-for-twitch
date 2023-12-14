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
import junit.framework.TestCase;


public class AccessTokenUtilsTest extends TestCase {
	
	
	public void testDetermineAccessTokenType_Bearer() throws ParseException {
		
		assertEquals(AccessTokenType.BEARER, AccessTokenUtils.determineAccessTokenTypeFromAuthorizationHeader("Bearer na3uJaeJaipheexohf8zi0ong9ayienu"));
		assertEquals(AccessTokenType.BEARER, AccessTokenUtils.determineAccessTokenTypeFromAuthorizationHeader("bearer na3uJaeJaipheexohf8zi0ong9ayienu"));
		assertEquals(AccessTokenType.BEARER, AccessTokenUtils.determineAccessTokenTypeFromAuthorizationHeader("BEARER na3uJaeJaipheexohf8zi0ong9ayienu"));
	}
	
	
	public void testDetermineAccessTokenType_DPoP() throws ParseException {
		
		assertEquals(AccessTokenType.DPOP, AccessTokenUtils.determineAccessTokenTypeFromAuthorizationHeader("DPoP na3uJaeJaipheexohf8zi0ong9ayienu"));
		assertEquals(AccessTokenType.DPOP, AccessTokenUtils.determineAccessTokenTypeFromAuthorizationHeader("dpop na3uJaeJaipheexohf8zi0ong9ayienu"));
		assertEquals(AccessTokenType.DPOP, AccessTokenUtils.determineAccessTokenTypeFromAuthorizationHeader("DPOP na3uJaeJaipheexohf8zi0ong9ayienu"));
	}


	public void testDetermineAccessTokenType_null() {
		
		try {
			AccessTokenUtils.determineAccessTokenTypeFromAuthorizationHeader(null);
			fail();
		} catch (ParseException e) {
			assertEquals("Couldn't determine access token type from Authorization header", e.getMessage());
		}
	}


	public void testDetermineAccessTokenType_empty() {
		
		try {
			AccessTokenUtils.determineAccessTokenTypeFromAuthorizationHeader("");
			fail();
		} catch (ParseException e) {
			assertEquals("Couldn't determine access token type from Authorization header", e.getMessage());
		}
	}


	public void testDetermineAccessTokenType_blank() {
		
		try {
			AccessTokenUtils.determineAccessTokenTypeFromAuthorizationHeader(" ");
			fail();
		} catch (ParseException e) {
			assertEquals("Couldn't determine access token type from Authorization header", e.getMessage());
		}
	}


	public void testDetermineAccessTokenType_unknown() {
		
		try {
			AccessTokenUtils.determineAccessTokenTypeFromAuthorizationHeader("Unknown na3uJaeJaipheexohf8zi0ong9ayienu");
			fail();
		} catch (ParseException e) {
			assertEquals("Couldn't determine access token type from Authorization header", e.getMessage());
		}
	}


	public void testParseValueFromHeader_Bearer() throws ParseException {

		String tokenValue = "ooth3oo1Ahth9toh";

		assertEquals(tokenValue, AccessTokenUtils.parseValueFromHeader("Bearer " + tokenValue, AccessTokenType.BEARER));
	}


	public void testParseValueFromHeader_Bearer_caseInsensitive() throws ParseException {

		String tokenValue = "ooth3oo1Ahth9toh";

		assertEquals(tokenValue, AccessTokenUtils.parseValueFromHeader("BEARER " + tokenValue, AccessTokenType.BEARER));
	}


	public void testParseValueFromHeader_DPoP() throws ParseException {

		String tokenValue = "ooth3oo1Ahth9toh";

		assertEquals(tokenValue, AccessTokenUtils.parseValueFromHeader("DPoP " + tokenValue, AccessTokenType.DPOP));
	}


	public void testParseValueFromHeader_DPoP_caseInsensitive() throws ParseException {

		String tokenValue = "ooth3oo1Ahth9toh";

		assertEquals(tokenValue, AccessTokenUtils.parseValueFromHeader("dpop " + tokenValue, AccessTokenType.DPOP));
	}
}
