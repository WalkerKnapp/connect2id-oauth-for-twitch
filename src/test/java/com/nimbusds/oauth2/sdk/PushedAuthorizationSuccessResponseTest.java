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

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


public class PushedAuthorizationSuccessResponseTest extends TestCase {
	
	
	public void testLifeCycle() throws ParseException {
		
		// https://tools.ietf.org/html/rfc6755
		URI requestURI = URI.create("urn:ietf:params:oauth:request_uri:tioteej8");
		long lifetime = 3600L;
		
		PushedAuthorizationSuccessResponse response = new PushedAuthorizationSuccessResponse(requestURI, lifetime);
		assertEquals(requestURI, response.getRequestURI());
		assertEquals(lifetime, response.getLifetime());
		assertTrue(response.indicatesSuccess());
		
		JSONObject jsonObject = response.toJSONObject();
		assertEquals(requestURI.toString(), jsonObject.get("request_uri"));
		assertEquals(lifetime, jsonObject.get("expires_in"));
		assertEquals(2, jsonObject.size());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertEquals(201, httpResponse.getStatusCode());
		assertEquals(ContentType.APPLICATION_JSON.toString(), httpResponse.getEntityContentType().toString());
		jsonObject = response.toJSONObject();
		assertEquals(requestURI.toString(), jsonObject.get("request_uri"));
		assertEquals(lifetime, jsonObject.get("expires_in"));
		assertEquals(2, jsonObject.size());
		
		response = PushedAuthorizationSuccessResponse.parse(jsonObject);
		assertEquals(requestURI, response.getRequestURI());
		assertEquals(lifetime, response.getLifetime());
	}
	
	
	public void testRejectNullRequestURI() {
		
		try {
			new PushedAuthorizationSuccessResponse(null, 3600);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testRejectNonPositiveLifetime() {
		
		try {
			new PushedAuthorizationSuccessResponse(URI.create("urn:ietf:params:oauth:request_uri:tioteej8"), 0L);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The request lifetime must be a positive integer", e.getMessage());
		}
		
		try {
			new PushedAuthorizationSuccessResponse(URI.create("urn:ietf:params:oauth:request_uri:tioteej8"), -1L);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The request lifetime must be a positive integer", e.getMessage());
		}
	}
	
	
	public void testParse_missingRequestURI() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("expires_in", 3600L);
		try {
			PushedAuthorizationSuccessResponse.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key request_uri", e.getMessage());
		}
	}
	
	
	public void testParse_missingLifetime() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("request_uri", "urn:ietf:params:oauth:request_uri:tioteej8");
		try {
			PushedAuthorizationSuccessResponse.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key expires_in", e.getMessage());
		}
	}
}
