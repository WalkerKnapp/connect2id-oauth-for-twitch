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
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;


public class TrustNegotiationResponseTest extends TestCase {
	
	
	public void testParseSuccess() throws ParseException {
		
		OIDCProviderMetadata opMetadata = TrustNegotiationSuccessResponseTest.createSampleOPMetadata();
		JSONObject jsonObject = opMetadata.toJSONObject();
		TrustNegotiationSuccessResponse response = new TrustNegotiationSuccessResponse(jsonObject);
		HTTPResponse httpResponse = response.toHTTPResponse();
		
		response = TrustNegotiationResponse.parse(httpResponse).toSuccessResponse();
		assertEquals(jsonObject, response.getMetadataJSONObject());
		assertTrue(response.indicatesSuccess());
	}
	

	public void testParseError() throws ParseException {
		
		FederationAPIError error = new FederationAPIError(OperationType.FETCH,
			"invalid_request",
			"Missing required iss (issuer) request parameter")
			.withStatusCode(400);
		
		TrustNegotiationErrorResponse response = new TrustNegotiationErrorResponse(error);
		HTTPResponse httpResponse = response.toHTTPResponse();
		
		response = TrustNegotiationErrorResponse.parse(httpResponse).toErrorResponse();
		assertEquals(error.toJSONObject(), response.getErrorObject().toJSONObject());
		assertFalse(response.indicatesSuccess());
	}
}
