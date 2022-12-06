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


import static com.nimbusds.openid.connect.sdk.federation.api.EntityListingSuccessResponseTest.ENTITY_IDS;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


public class EntityListingResponseTest extends TestCase {
	
	
	public void testParseSuccess() throws ParseException {
		
		EntityListingSuccessResponse response = new EntityListingSuccessResponse(ENTITY_IDS);
		HTTPResponse httpResponse = response.toHTTPResponse();
		
		response = EntityListingResponse.parse(httpResponse).toSuccessResponse();
		assertEquals(ENTITY_IDS, response.getEntityListing());
		assertTrue(response.indicatesSuccess());
	}
	
	
	public void testUnsupportedParameterError() throws ParseException {
		
		FederationAPIError error = new FederationAPIError(
			"unsupported_parameter",
			"Unsupported parameter")
			.withStatusCode(400);
		
		EntityListingErrorResponse response = new EntityListingErrorResponse(error);
		HTTPResponse httpResponse = response.toHTTPResponse();
		
		response = EntityListingErrorResponse.parse(httpResponse).toErrorResponse();
		assertEquals(error.toJSONObject(), response.getErrorObject().toJSONObject());
		assertFalse(response.indicatesSuccess());
		
		assertEquals(OAuth2Error.UNSUPPORTED_PARAMETER, response.getErrorObject());
	}
	
	
	public void testParseError() throws ParseException {
		
		FederationAPIError error = new FederationAPIError(
			"invalid_request",
			"Missing required iss (issuer) request parameter")
			.withStatusCode(400);
		
		EntityListingErrorResponse response = new EntityListingErrorResponse(error);
		HTTPResponse httpResponse = response.toHTTPResponse();
		
		response = EntityListingErrorResponse.parse(httpResponse).toErrorResponse();
		assertEquals(error.toJSONObject(), response.getErrorObject().toJSONObject());
		assertFalse(response.indicatesSuccess());
		
		assertEquals(OAuth2Error.INVALID_REQUEST, response.getErrorObject());
	}
}
