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

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


public class TrustMarkStatusSuccessResponseTest extends TestCase {
	
	
	public void testLifecycle() throws Exception {
		
		TrustMarkStatusSuccessResponse response = new TrustMarkStatusSuccessResponse(true);
		assertTrue(response.isActive());
		assertTrue(response.indicatesSuccess());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertEquals(200, httpResponse.getStatusCode());
		assertEquals("application/json; charset=UTF-8", httpResponse.getEntityContentType().toString());
		JSONObject jsonObject = httpResponse.getContentAsJSONObject();
		assertTrue(JSONObjectUtils.getBoolean(jsonObject, "active"));
		assertEquals(1, jsonObject.size());
		
		response = TrustMarkStatusSuccessResponse.parse(httpResponse);
		assertTrue(response.isActive());
		assertTrue(response.indicatesSuccess());
	}
	
	
	public void testLifecycle_notActive() throws Exception {
		
		TrustMarkStatusSuccessResponse response = new TrustMarkStatusSuccessResponse(false);
		assertFalse(response.isActive());
		assertTrue(response.indicatesSuccess());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertEquals(200, httpResponse.getStatusCode());
		assertEquals("application/json; charset=UTF-8", httpResponse.getEntityContentType().toString());
		JSONObject jsonObject = httpResponse.getContentAsJSONObject();
		assertFalse(JSONObjectUtils.getBoolean(jsonObject, "active"));
		assertEquals(1, jsonObject.size());
		
		response = TrustMarkStatusSuccessResponse.parse(httpResponse);
		assertFalse(response.isActive());
		assertTrue(response.indicatesSuccess());
	}
	
	
	public void testRejectNotOK() {
		
		try {
			TrustMarkStatusSuccessResponse.parse(new HTTPResponse(400));
			fail();
		} catch (ParseException e) {
			assertEquals("Unexpected HTTP status code 400, must be [200]", e.getMessage());
		}
	}
}
