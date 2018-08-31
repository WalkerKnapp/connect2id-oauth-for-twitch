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


import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import junit.framework.TestCase;


/**
 * Tests the authorisation code grant class.
 */
public class AuthorizationCodeGrantTest extends TestCase {


	public void testConstructor()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode("abc");
		URI redirectURI = new URI("https://client.com/in");

		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(code, redirectURI);

		assertEquals(code, grant.getAuthorizationCode());
		assertEquals(redirectURI, grant.getRedirectionURI());

		assertEquals(GrantType.AUTHORIZATION_CODE, grant.getType());

		Map<String,List<String>> params = grant.toParameters();
		assertEquals(Collections.singletonList("abc"), params.get("code"));
		assertEquals(Collections.singletonList("https://client.com/in"), params.get("redirect_uri"));
		assertEquals(Collections.singletonList("authorization_code"), params.get("grant_type"));
		assertEquals(3, params.size());

		grant = AuthorizationCodeGrant.parse(params);
		assertEquals(code, grant.getAuthorizationCode());
		assertEquals(redirectURI, grant.getRedirectionURI());
		assertEquals(GrantType.AUTHORIZATION_CODE, grant.getType());
	}


	// PKCE
	public void testConstructorWithCodeVerifier()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode("abc");
		URI redirectURI = new URI("https://client.com/in");
		CodeVerifier codeVerifier = new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(code, redirectURI, codeVerifier);

		assertEquals(code, grant.getAuthorizationCode());
		assertEquals(redirectURI, grant.getRedirectionURI());
		assertEquals(codeVerifier, grant.getCodeVerifier());

		assertEquals(GrantType.AUTHORIZATION_CODE, grant.getType());

		Map<String,List<String>> params = grant.toParameters();
		assertEquals(Collections.singletonList("abc"), params.get("code"));
		assertEquals(Collections.singletonList("https://client.com/in"), params.get("redirect_uri"));
		assertEquals(Collections.singletonList("authorization_code"), params.get("grant_type"));
		assertEquals(Collections.singletonList(codeVerifier.getValue()), params.get("code_verifier"));
		assertEquals(4, params.size());

		grant = AuthorizationCodeGrant.parse(params);
		assertEquals(code, grant.getAuthorizationCode());
		assertEquals(redirectURI, grant.getRedirectionURI());
		assertEquals(GrantType.AUTHORIZATION_CODE, grant.getType());
		assertEquals(codeVerifier, grant.getCodeVerifier());
	}


	public void testConstructorWithoutRedirectionURI()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode("abc");

		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(code, null);

		assertEquals(code, grant.getAuthorizationCode());
		assertNull(grant.getRedirectionURI());

		assertEquals(GrantType.AUTHORIZATION_CODE, grant.getType());

		Map<String,List<String>> params = grant.toParameters();
		assertEquals(Collections.singletonList("abc"), params.get("code"));
		assertEquals(Collections.singletonList("authorization_code"), params.get("grant_type"));
		assertEquals(2, params.size());

		grant = AuthorizationCodeGrant.parse(params);
		assertEquals(code, grant.getAuthorizationCode());
		assertNull(grant.getRedirectionURI());
		assertEquals(GrantType.AUTHORIZATION_CODE, grant.getType());
	}
	
	
	public void testParse()
		throws Exception {
		
		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("authorization_code"));
		params.put("code", Collections.singletonList("abc"));
		params.put("redirect_uri", Collections.singletonList("https://client.com/in"));
		
		AuthorizationCodeGrant grant = AuthorizationCodeGrant.parse(params);
		
		assertEquals(GrantType.AUTHORIZATION_CODE, grant.getType());
		assertEquals("abc", grant.getAuthorizationCode().getValue());
		assertEquals("https://client.com/in", grant.getRedirectionURI().toString());
	}


	public void testParse_codeVerifierTooShort()
		throws Exception {

		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("authorization_code"));
		params.put("code", Collections.singletonList("abc"));
		params.put("redirect_uri", Collections.singletonList("https://client.com/in"));
		params.put("code_verifier", Collections.singletonList("abc"));

		try {
			AuthorizationCodeGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("The code verifier must be at least 43 characters", e.getMessage());
		}
	}


	public void testParseMissingGrantType() {

		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", null);
		params.put("code", Collections.singletonList("abc"));
		params.put("redirect_uri", Collections.singletonList("https://client.com/in"));

		try {
			AuthorizationCodeGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing \"grant_type\" parameter", e.getErrorObject().getDescription());
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testParseUnsupportedGrant() {

		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("no-such-grant"));
		params.put("code", Collections.singletonList("abc"));
		params.put("redirect_uri", Collections.singletonList("https://client.com/in"));

		try {
			AuthorizationCodeGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE.getCode(), e.getErrorObject().getCode());
			assertEquals("Unsupported grant type: The \"grant_type\" must be \"authorization_code\"", e.getErrorObject().getDescription());
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testParseMissingCode() {

		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("authorization_code"));
		params.put("code", Collections.singletonList(""));
		params.put("redirect_uri", Collections.singletonList("https://client.com/in"));

		try {
			AuthorizationCodeGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing or empty \"code\" parameter", e.getErrorObject().getDescription());
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testParseInvalidRedirectionURI() {

		Map<String,List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("authorization_code"));
		params.put("code", Collections.singletonList("abc"));
		params.put("redirect_uri", Collections.singletonList("invalid uri"));

		try {
			AuthorizationCodeGrant.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Invalid \"redirect_uri\" parameter: Illegal character in path at index 7: invalid uri", e.getErrorObject().getDescription());
			assertNull(e.getErrorObject().getURI());
			assertTrue(e.getCause() instanceof URISyntaxException);
		}
	}


	public void testEquality() {

		assertTrue(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), null)
			.equals(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), null)));

		assertTrue(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), URI.create("https://client.com/cb"))
			.equals(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), URI.create("https://client.com/cb"))));

		assertTrue(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), URI.create("https://client.com/cb"), new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
			.equals(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), URI.create("https://client.com/cb"), new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))));
	}


	public void testInequality() {

		assertFalse(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), null)
			.equals(new AuthorizationCodeGrant(new AuthorizationCode("abc"), null)));

		assertFalse(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), URI.create("https://client.com/cb"))
			.equals(new AuthorizationCodeGrant(new AuthorizationCode("abc"), URI.create("https://client.com/cb"))));

		assertFalse(new AuthorizationCodeGrant(new AuthorizationCode("abc"), URI.create("https://client.com/cb"), new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
			.equals(new AuthorizationCodeGrant(new AuthorizationCode("abc"), URI.create("https://client.com/cb"))));

		assertFalse(new AuthorizationCodeGrant(new AuthorizationCode("abc"), URI.create("https://client.com/cb"), new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
			.equals(new AuthorizationCodeGrant(new AuthorizationCode("abc"), URI.create("https://client.com/cb"), new CodeVerifier("DBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))));

		assertFalse(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), URI.create("https://client.com/cb"))
			.equals(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), null)));

		assertFalse(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), URI.create("https://client.com/cb"))
			.equals(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), URI.create("https://other.com/cb"))));
	}
}
