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

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;


public class FetchEntityStatementResponseTest extends TestCase {
	
	
	public void testParseSuccess() throws Exception {
		
		EntityStatement signedStmt = FetchEntityStatementSuccessResponseTest.createSignedEntityStatement();
		FetchEntityStatementSuccessResponse response = new FetchEntityStatementSuccessResponse(signedStmt);
		HTTPResponse httpResponse = response.toHTTPResponse();
		
		response = FetchEntityStatementResponse.parse(httpResponse).toSuccessResponse();
		assertEquals(signedStmt.getSignedStatement().serialize(), response.getEntityStatement().getSignedStatement().serialize());
	}
	
	
	public void testParseError() throws Exception {
		
		FederationAPIError error = new FederationAPIError(
			"invalid_request",
			"Missing required iss (issuer) request parameter")
			.withStatusCode(400);
		
		FetchEntityStatementErrorResponse response = new FetchEntityStatementErrorResponse(error);
		HTTPResponse httpResponse = response.toHTTPResponse();
		
		response = FetchEntityStatementResponse.parse(httpResponse).toErrorResponse();
		assertEquals(error.toJSONObject(), response.getErrorObject().toJSONObject());
		assertFalse(response.indicatesSuccess());
	}
}
