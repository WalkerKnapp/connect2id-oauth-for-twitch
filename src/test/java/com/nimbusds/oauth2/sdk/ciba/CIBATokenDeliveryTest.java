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

package com.nimbusds.oauth2.sdk.ciba;


import java.net.URI;

import junit.framework.TestCase;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;


public class CIBATokenDeliveryTest extends TestCase {
	
	
	private static final URI ENDPOINT = URI.create("https://client.example.com/ciba");
	
	private static final BearerAccessToken CLIENT_NOTIFICATION_TOKEN = new BearerAccessToken();
	
	private static final AuthRequestID AUTH_REQUEST_ID = new AuthRequestID();
	
	private static final AccessToken ACCESS_TOKEN = new BearerAccessToken(16, 120, new Scope("openid", "email"));
	
	private static final RefreshToken REFRESH_TOKEN = new RefreshToken();
	
	private static final JWT ID_TOKEN;
	
	static {
		try {
			// https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0-03.html#successful_token_push
			ID_TOKEN = SignedJWT.parse(
				"eyJhbGciOiJSUzI1NiIsImtpZCI6IjE2NzcyNiJ9.eyJpc3MiOiJ" +
				"odHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsInN1YiI6IjI0ODI4OTc2MTAwMS" +
				"IsImF1ZCI6InM2QmhkUmtxdDMiLCJlbWFpbCI6ImphbmVkb2VAZXhhbXBsZS5jb" +
				"20iLCJleHAiOjE1Mzc4MTk4MDMsImlhdCI6MTUzNzgxOTUwMywiYXRfaGFzaCI6" +
				"Ild0MGtWRlhNYWNxdm5IZXlVMDAwMXciLCJ1cm46b3BlbmlkOnBhcmFtczpqd3Q" +
				"6Y2xhaW06cnRfaGFzaCI6InNIYWhDdVNwWENSZzVta0REdnZyNHciLCJ1cm46b3" +
				"BlbmlkOnBhcmFtczpqd3Q6Y2xhaW06YXV0aF9yZXFfaWQiOiIxYzI2NjExNC1hM" +
				"WJlLTQyNTItOGFkMS0wNDk4NmM1YjlhYzEifQ.SGB5_a8E7GjwtoYrkFyqOhLK6" +
				"L8-Wh1nLeREwWj30gNYOZW_ZB2mOeQ5yiXqeKJeNpDPssGUrNo-3N-CqNrbmVCb" +
				"XYTwmNB7IvwE6ZPRcfxFV22oou-NS4-3rEa2ghG44Fi9D9fVURwxrRqgyezeD3H" +
				"HVIFUnCxHUou3OOpj6aOgDqKI4Xl2xJ0-kKAxNR8LljUp64OHgoS-UO3qyfOwIk" +
				"IAR7o4OTK_3Oy78rJNT0Y0RebAWyA81UDCSf_gWVBp-EUTI5CdZ1_odYhwB9OWD" +
				"W1A22Sf6rmjhMHGbQW4A9Z822yiZZveuT_AFZ2hi7yNp8iFPZ8fgPQJ5pPpjA7u" +
				"dg");
		} catch (java.text.ParseException e) {
			throw new RuntimeException(e);
		}
	}


	public void testLifeCycleOAuth()
		throws ParseException {
		
		Tokens tokens = new Tokens(ACCESS_TOKEN, REFRESH_TOKEN);
		
		CIBATokenDelivery tokenDelivery = new CIBATokenDelivery(
			ENDPOINT,
			CLIENT_NOTIFICATION_TOKEN,
			AUTH_REQUEST_ID,
			tokens);
		
		assertTrue(tokenDelivery.indicatesSuccess());
		assertEquals(tokens, tokenDelivery.getTokens());
		assertNull(tokenDelivery.getOIDCTokens());
		
		HTTPRequest httpRequest = tokenDelivery.toHTTPRequest();
		assertEquals(ENDPOINT, httpRequest.getURI());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(CLIENT_NOTIFICATION_TOKEN.toAuthorizationHeader(), httpRequest.getAuthorization());
		assertEquals(ContentType.APPLICATION_JSON, httpRequest.getEntityContentType());
		assertEquals(2, httpRequest.getHeaderMap().size());
		Tokens parsedTokens = Tokens.parse(httpRequest.getQueryAsJSONObject());
		assertEquals(tokens.toJSONObject(), parsedTokens.toJSONObject());
		
		tokenDelivery = CIBATokenDelivery.parse(httpRequest);
		
		assertTrue(tokenDelivery.indicatesSuccess());
		assertEquals(tokens.toJSONObject(), tokenDelivery.getTokens().toJSONObject());
		assertNull(tokenDelivery.getOIDCTokens());
	}


	public void testLifeCycleOpenIDConnect()
		throws ParseException {
		
		OIDCTokens tokens = new OIDCTokens(ID_TOKEN, ACCESS_TOKEN, REFRESH_TOKEN);
		
		CIBATokenDelivery tokenDelivery = new CIBATokenDelivery(
			ENDPOINT,
			CLIENT_NOTIFICATION_TOKEN,
			AUTH_REQUEST_ID,
			tokens);
		
		assertTrue(tokenDelivery.indicatesSuccess());
		assertEquals(tokens, tokenDelivery.getTokens());
		assertEquals(tokens, tokenDelivery.getOIDCTokens());
		
		HTTPRequest httpRequest = tokenDelivery.toHTTPRequest();
		assertEquals(ENDPOINT, httpRequest.getURI());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(CLIENT_NOTIFICATION_TOKEN.toAuthorizationHeader(), httpRequest.getAuthorization());
		assertEquals(ContentType.APPLICATION_JSON, httpRequest.getEntityContentType());
		assertEquals(2, httpRequest.getHeaderMap().size());
		OIDCTokens parsedTokens = OIDCTokens.parse(httpRequest.getQueryAsJSONObject());
		assertEquals(tokens.toJSONObject(), parsedTokens.toJSONObject());
		
		tokenDelivery = CIBATokenDelivery.parse(httpRequest);
		
		assertTrue(tokenDelivery.indicatesSuccess());
		assertEquals(tokens.toJSONObject(), tokenDelivery.getTokens().toJSONObject());
		assertEquals(tokens.toJSONObject(), tokenDelivery.getOIDCTokens().toJSONObject());
	}
	
	
	public void testParse_requirePOST() {
		try {
			CIBAErrorDelivery.parse(new HTTPRequest(HTTPRequest.Method.PUT, ENDPOINT));
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP request method must be POST", e.getMessage());
		}
	}
	
	
	public void testParse_requireClientNotificationToken() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT);
		httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);
		
		try {
			CIBAErrorDelivery.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing access token parameter", e.getMessage());
		}
	}
	
	
	public void testParse_requireAuthReqID() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT);
		httpRequest.setAuthorization(CLIENT_NOTIFICATION_TOKEN.toAuthorizationHeader());
		httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);
		httpRequest.setBody(new Tokens(ACCESS_TOKEN, null).toJSONObject().toJSONString());
		
		try {
			CIBAErrorDelivery.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key auth_req_id", e.getMessage());
		}
	}
}
