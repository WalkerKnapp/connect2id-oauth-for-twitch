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


public class TrustMarkStatusResponseTest extends TestCase {
	
	
	public void testParseSuccess_active() throws ParseException {
		
		TrustMarkStatusSuccessResponse response = new TrustMarkStatusSuccessResponse(true);
		HTTPResponse httpResponse = response.toHTTPResponse();
		
		response = TrustMarkStatusSuccessResponse.parse(httpResponse).toSuccessResponse();
		assertTrue(response.isActive());
		assertTrue(response.indicatesSuccess());
	}
	
	
	public void testParseSuccess_notActive() throws ParseException {
		
		TrustMarkStatusSuccessResponse response = new TrustMarkStatusSuccessResponse(false);
		HTTPResponse httpResponse = response.toHTTPResponse();
		
		response = TrustMarkStatusSuccessResponse.parse(httpResponse).toSuccessResponse();
		assertFalse(response.isActive());
		assertTrue(response.indicatesSuccess());
	}
	

	public void testParseError() throws ParseException {
		
		FederationAPIError error = new FederationAPIError(
			"invalid_request",
			"Missing required sub (subject) request parameter")
			.withStatusCode(400);
		
		TrustMarkStatusErrorResponse response = new TrustMarkStatusErrorResponse(error);
		HTTPResponse httpResponse = response.toHTTPResponse();
		
		response = TrustMarkStatusErrorResponse.parse(httpResponse).toErrorResponse();
		assertEquals(error.toJSONObject(), response.getErrorObject().toJSONObject());
		assertFalse(response.indicatesSuccess());
	}
}
