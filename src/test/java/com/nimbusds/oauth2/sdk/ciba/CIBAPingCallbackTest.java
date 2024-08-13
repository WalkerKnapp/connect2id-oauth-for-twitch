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


import java.net.MalformedURLException;
import java.net.URI;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


public class CIBAPingCallbackTest extends TestCase {
	
	
	private static final URI ENDPOINT = URI.create("https://client.example.com/ciba");
	
	private static final BearerAccessToken ACCESS_TOKEN = new BearerAccessToken();
	
	private static final AuthRequestID AUTH_REQUEST_ID = new AuthRequestID();
	
	
	public void testLifeCycle()
		throws MalformedURLException, ParseException {
		
		CIBAPingCallback pingCallback = new CIBAPingCallback(
			ENDPOINT,
			ACCESS_TOKEN,
			AUTH_REQUEST_ID);
		
		assertEquals(ENDPOINT, pingCallback.getEndpointURI());
		assertEquals(ACCESS_TOKEN, pingCallback.getAccessToken());
		assertEquals(AUTH_REQUEST_ID, pingCallback.getAuthRequestID());
		
		JSONObject expectedJSONObject = new JSONObject();
		expectedJSONObject.put("auth_req_id", AUTH_REQUEST_ID.getValue());
		
		HTTPRequest httpRequest = pingCallback.toHTTPRequest();
		assertEquals(ENDPOINT.toURL(), httpRequest.getURL());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertFalse(httpRequest.getFollowRedirects());
		assertEquals(ACCESS_TOKEN.toAuthorizationHeader(), httpRequest.getAuthorization());
		assertEquals(ContentType.APPLICATION_JSON, httpRequest.getEntityContentType());
		assertEquals(2, httpRequest.getHeaderMap().size());
		assertEquals(expectedJSONObject, httpRequest.getQueryAsJSONObject());
		
		pingCallback = CIBAPingCallback.parse(httpRequest);
		
		assertEquals(ENDPOINT, pingCallback.getEndpointURI());
		assertEquals(ACCESS_TOKEN, pingCallback.getAccessToken());
		assertEquals(AUTH_REQUEST_ID, pingCallback.getAuthRequestID());
	}


	public void testAuthRequestIDNotNull() {
		NullPointerException exception = null;
		try {
			new CIBAPingCallback(
				ENDPOINT,
				new BearerAccessToken(),
				null);
			fail();
		} catch (NullPointerException e) {
			exception = e;
		}
		assertNull(exception.getMessage());
	}
	
	
	public void testParse_requirePOST()
		throws MalformedURLException {
		
		try {
			CIBAPingCallback.parse(new HTTPRequest(HTTPRequest.Method.PUT, ENDPOINT.toURL()));
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP request method must be POST", e.getMessage());
		}
	}
	
	
	public void testParse_missingContentType()
		throws MalformedURLException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT.toURL());
		
		try {
			CIBAPingCallback.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing HTTP Content-Type header", e.getMessage());
		}
	}
	
	
	public void testParse_applicationJSON()
		throws MalformedURLException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT.toURL());
		httpRequest.setEntityContentType(ContentType.TEXT_PLAIN);
		
		try {
			CIBAPingCallback.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP Content-Type header must be application/json, received text/plain", e.getMessage());
		}
	}
	
	
	public void testParse_missingToken()
		throws MalformedURLException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT.toURL());
		httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);
		
		try {
			CIBAPingCallback.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing access token parameter", e.getMessage());
		}
	}
	
	
	public void testParse_missingAuthReqID()
		throws MalformedURLException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT.toURL());
		httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);
		httpRequest.setAuthorization(ACCESS_TOKEN.toAuthorizationHeader());
		httpRequest.setBody("{}");
		
		try {
			CIBAPingCallback.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key auth_req_id", e.getMessage());
		}
	}
}
