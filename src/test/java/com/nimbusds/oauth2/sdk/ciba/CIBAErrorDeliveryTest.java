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
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


public class CIBAErrorDeliveryTest  extends TestCase {
	
	
	private static final URI ENDPOINT = URI.create("https://client.example.com/ciba");
	
	private static final BearerAccessToken CLIENT_NOTIFICATION_TOKEN = new BearerAccessToken();
	
	private static final AuthRequestID AUTH_REQUEST_ID = new AuthRequestID();


	public void testStandardErrors() {
		
		assertTrue(CIBAErrorDelivery.getStandardErrors().contains(OAuth2Error.ACCESS_DENIED));
		assertTrue(CIBAErrorDelivery.getStandardErrors().contains(CIBAError.EXPIRED_TOKEN));
		assertTrue(CIBAErrorDelivery.getStandardErrors().contains(CIBAError.TRANSACTION_FAILED));
		assertEquals(3, CIBAErrorDelivery.getStandardErrors().size());
	}
	
	
	public void testLifeCycle()
		throws ParseException {
		
		CIBAErrorDelivery errorDelivery = new CIBAErrorDelivery(
			ENDPOINT,
			CLIENT_NOTIFICATION_TOKEN,
			AUTH_REQUEST_ID,
			CIBAError.EXPIRED_TOKEN);
		
		assertFalse(errorDelivery.indicatesSuccess());
		assertEquals(ENDPOINT, errorDelivery.getEndpointURI());
		assertEquals(CLIENT_NOTIFICATION_TOKEN, errorDelivery.getAccessToken());
		assertEquals(AUTH_REQUEST_ID, errorDelivery.getAuthRequestID());
		assertEquals(CIBAError.EXPIRED_TOKEN, errorDelivery.getErrorObject());
		
		HTTPRequest httpRequest = errorDelivery.toHTTPRequest();
		assertEquals(ENDPOINT, httpRequest.getURI());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(CLIENT_NOTIFICATION_TOKEN.toAuthorizationHeader(), httpRequest.getAuthorization());
		assertEquals(ContentType.APPLICATION_JSON, httpRequest.getEntityContentType());
		assertEquals(2, httpRequest.getHeaderMap().size());
		
		JSONObject expectedJSONObject = new JSONObject();
		expectedJSONObject.putAll(errorDelivery.getErrorObject().toJSONObject());
		expectedJSONObject.put("auth_req_id", errorDelivery.getAuthRequestID().getValue());
		assertEquals(expectedJSONObject, httpRequest.getQueryAsJSONObject());
		
		errorDelivery = CIBAErrorDelivery.parse(httpRequest);
		
		assertFalse(errorDelivery.indicatesSuccess());
		assertEquals(ENDPOINT, errorDelivery.getEndpointURI());
		assertEquals(CLIENT_NOTIFICATION_TOKEN, errorDelivery.getAccessToken());
		assertEquals(AUTH_REQUEST_ID, errorDelivery.getAuthRequestID());
		assertEquals(CIBAError.EXPIRED_TOKEN, errorDelivery.getErrorObject());
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
		httpRequest.setBody(CIBAError.EXPIRED_TOKEN.toJSONObject().toJSONString());
		
		try {
			CIBAErrorDelivery.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key auth_req_id", e.getMessage());
		}
	}
}
