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


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import org.junit.Test;

import java.net.URI;
import java.util.Arrays;

import static org.junit.Assert.*;


public class AccessTokenTest {


        @Test
        public void testEquality() {
		
		AccessToken t1 = new TypelessAccessToken("abc");
		AccessToken t2 = new BearerAccessToken("abc");

                assertEquals(t1, t2);
	}


        @Test
        public void testEqualityAlt() {

                assertEquals(new TypelessAccessToken("abc"), new BearerAccessToken("abc"));
	}


        @Test
        public void testInequality_caseSensitive() {
		
		AccessToken t1 = new TypelessAccessToken("abc");
		AccessToken t2 = new BearerAccessToken("ABC");

                assertNotEquals(t1, t2);
	}


	@Test
	public void parseAccessToken_httpRequest_POST_header()
		throws ParseException {

		for (AccessToken accessToken: Arrays.asList(new BearerAccessToken("nah6Aizohsh4"), new DPoPAccessToken("eiCh9Ooyi9ze"))) {

			HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, URI.create("https://c2id.com/userinfo"));
			httpRequest.setAuthorization(accessToken.toAuthorizationHeader());

			AccessToken parsed = AccessToken.parse(httpRequest);

			assertEquals(accessToken, parsed);
			assertEquals(accessToken.getType(), parsed.getType());
		}
	}


	@Test
	public void parseAccessToken_httpRequest_POST_header_unknownTokenType() {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, URI.create("https://c2id.com/userinfo"));
		httpRequest.setAuthorization("XXXToken feiF6eig5ath");

		try {
			AccessToken.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Couldn't determine access token type from Authorization header", e.getMessage());
		}
	}


	@Test
	public void parseAccessToken_httpRequest_POST_form()
		throws ParseException {

		BearerAccessToken accessToken = new BearerAccessToken("nah6Aizohsh4");

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, URI.create("https://c2id.com/accounts/"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("access_token=" + accessToken.getValue());

		AccessToken parsed = AccessToken.parse(httpRequest);

		assertEquals(accessToken.getValue(), parsed.getValue());
		assertEquals(AccessTokenType.UNKNOWN, parsed.getType());
	}


	@Test
	public void parseAccessToken_httpRequest_GET()
		throws ParseException {

		BearerAccessToken accessToken = new BearerAccessToken("nah6Aizohsh4");

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, URI.create("https://c2id.com/accounts/"));
		httpRequest.appendQueryString("access_token=" + accessToken.getValue());

		AccessToken parsed = AccessToken.parse(httpRequest);

		assertEquals(accessToken.getValue(), parsed.getValue());
		assertEquals(AccessTokenType.UNKNOWN, parsed.getType());
	}


	@Test
	public void parseAccessToken_httpRequest_POST_none() {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, URI.create("https://c2id.com/accounts/"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("account=123");

		try {
			AccessToken.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing access token parameter", e.getMessage());
		}
	}


	@Test
	public void parseAccessToken_httpRequest_GET_none() {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, URI.create("https://c2id.com/accounts/"));

		try {
			AccessToken.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing access token parameter", e.getMessage());
		}
	}
}
