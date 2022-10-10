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

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


public class TrustMarkStatusErrorResponseTest extends TestCase {
	
	
	public void testLifecycle() throws Exception {
		
		FederationAPIError error = new FederationAPIError(
			"invalid_request",
			"Missing required sub (subject) request parameter")
			.withStatusCode(400);
		
		TrustMarkStatusErrorResponse response = new TrustMarkStatusErrorResponse(error);
		assertEquals(error, response.getErrorObject());
		assertFalse(response.indicatesSuccess());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertEquals(400, httpResponse.getStatusCode());
		assertEquals("application/json; charset=UTF-8", httpResponse.getEntityContentType().toString());
		assertEquals(error.toJSONObject(), httpResponse.getContentAsJSONObject());
		
		response = TrustMarkStatusErrorResponse.parse(httpResponse);
		assertEquals(error, response.getErrorObject());
		assertFalse(response.indicatesSuccess());
	}
	
	
	public void testRejectHTTPSuccess() {
		
		try {
			TrustMarkStatusErrorResponse.parse(new HTTPResponse(200));
			fail();
		} catch (ParseException e) {
			assertEquals("Unexpected HTTP status code, must not be 200 (OK)", e.getMessage());
		}
	}
	
	
	public void testNoErrorObject() throws ParseException {
		
		TrustMarkStatusErrorResponse response = TrustMarkStatusErrorResponse.parse(new HTTPResponse(400));
		FederationAPIError error = response.getErrorObject();
		assertEquals(400, error.getHTTPStatusCode());
		assertNull(error.getDescription());
		assertNull(error.getCode());
	}
	
	
	public void testRejectNullErrorObject() {
		
		try {
			new TrustMarkStatusErrorResponse(null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The error object must not be null", e.getMessage());
		}
	}
}
