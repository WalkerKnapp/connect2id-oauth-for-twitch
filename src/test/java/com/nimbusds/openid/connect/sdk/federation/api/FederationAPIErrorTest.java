/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.federation.api;


import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


public class FederationAPIErrorTest extends TestCase {
	
	
	public void testMinimalConstructor() {
		
		String code = "invalid_request";
		String description = "Missing required iss (issuer) parameter";
		FederationAPIError error = new FederationAPIError(code, description);
		assertEquals(code, error.getCode());
		assertEquals(description, error.getDescription());
		assertNull(error.getURI());
		assertEquals(0, error.getHTTPStatusCode());
		
		JSONObject jsonObject = error.toJSONObject();
		assertEquals(code, jsonObject.get("error"));
		assertEquals(description, jsonObject.get("error_description"));
		assertEquals(2, jsonObject.size());
		
		error = FederationAPIError.parse(jsonObject);
		assertEquals(code, error.getCode());
		assertEquals(description, error.getDescription());
		assertNull(error.getURI());
		assertEquals(0, error.getHTTPStatusCode());
		
		HTTPResponse httpResponse = error.toHTTPResponse();
		assertEquals(400, httpResponse.getStatusCode());
		assertEquals(ContentType.APPLICATION_JSON, httpResponse.getEntityContentType());
		
		error = FederationAPIError.parse(httpResponse);
		assertEquals(code, error.getCode());
		assertEquals(description, error.getDescription());
		assertNull(error.getURI());
		assertEquals(400, error.getHTTPStatusCode());
	}
	
	
	public void testFullConstructor() {
		
		String code = "invalid_request";
		String description = "Missing required iss (issuer) parameter";
		FederationAPIError error = new FederationAPIError(code, description, 400);
		assertEquals(code, error.getCode());
		assertEquals(description, error.getDescription());
		assertNull(error.getURI());
		assertEquals(400, error.getHTTPStatusCode());
		
		JSONObject jsonObject = error.toJSONObject();
		assertEquals(code, jsonObject.get("error"));
		assertEquals(description, jsonObject.get("error_description"));
		assertEquals(2, jsonObject.size());
		
		error = FederationAPIError.parse(jsonObject);
		assertEquals(code, error.getCode());
		assertEquals(description, error.getDescription());
		assertNull(error.getURI());
		assertEquals(0, error.getHTTPStatusCode());
		
		HTTPResponse httpResponse = error.toHTTPResponse();
		assertEquals(400, httpResponse.getStatusCode());
		assertEquals(ContentType.APPLICATION_JSON, httpResponse.getEntityContentType());
		
		error = FederationAPIError.parse(httpResponse);
		assertEquals(code, error.getCode());
		assertEquals(description, error.getDescription());
		assertNull(error.getURI());
		assertEquals(400, error.getHTTPStatusCode());
	}
	
	
	public void testWithNullParams() {
		
		FederationAPIError error = new FederationAPIError(null, null);
		assertNull(error.getCode());
		assertNull(error.getDescription());
		assertEquals(0, error.getHTTPStatusCode());
		
		JSONObject jsonObject = error.toJSONObject();
		assertTrue(jsonObject.isEmpty());
		
		error = FederationAPIError.parse(jsonObject);
		assertNull(error.getCode());
		assertNull(error.getDescription());
		assertEquals(0, error.getHTTPStatusCode());
		
		HTTPResponse httpResponse = error.toHTTPResponse();
		assertEquals(400, httpResponse.getStatusCode());
		assertNull(httpResponse.getEntityContentType());
		assertNull(httpResponse.getContent());
		
		error = FederationAPIError.parse(httpResponse);
		assertNull(error.getCode());
		assertNull(error.getDescription());
		assertEquals(400, error.getHTTPStatusCode());
	}
	
	
	public void testWithHTTPStatusCode() {
		
		FederationAPIError error = new FederationAPIError("invalid_request", "Missing iss");
		assertEquals("invalid_request", error.getCode());
		assertEquals("Missing iss", error.getDescription());
		assertEquals(0, error.getHTTPStatusCode());
		
		error = error.withStatusCode(400);
		assertEquals("invalid_request", error.getCode());
		assertEquals("Missing iss", error.getDescription());
		assertEquals(400, error.getHTTPStatusCode());
		
		HTTPResponse httpResponse = error.toHTTPResponse();
		assertEquals(400, httpResponse.getStatusCode());
		assertEquals(ContentType.APPLICATION_JSON, httpResponse.getEntityContentType());
		
		error = FederationAPIError.parse(httpResponse);
		assertEquals("invalid_request", error.getCode());
		assertEquals("Missing iss", error.getDescription());
		assertNull(error.getURI());
		assertEquals(400, error.getHTTPStatusCode());
	}
	
	
	public void testParseHTTPResponseNoContent() {
		
		HTTPResponse httpResponse = new HTTPResponse(400);
		FederationAPIError error = FederationAPIError.parse(httpResponse);
		assertNull(error.getCode());
		assertNull(error.getDescription());
		assertEquals(400, error.getHTTPStatusCode());
	}
}
