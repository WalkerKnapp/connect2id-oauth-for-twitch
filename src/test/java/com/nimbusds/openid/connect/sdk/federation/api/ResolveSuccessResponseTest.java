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


import java.net.URI;
import java.util.Arrays;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;


public class ResolveSuccessResponseTest extends TestCase {
	
	
	static OIDCProviderMetadata createSampleOPMetadata() {
		
		OIDCProviderMetadata opMetadata = new OIDCProviderMetadata(
			new Issuer("https://c2id.com"),
			Arrays.asList(SubjectType.PAIRWISE, SubjectType.PUBLIC),
			URI.create("https://c2id.com/jwks.json")
		);
		opMetadata.setAuthorizationEndpointURI(URI.create("https://c2id.com/login"));
		opMetadata.setTokenEndpointURI(URI.create("https://c2id.com/token"));
		opMetadata.applyDefaults();
		return opMetadata;
	}
	
	
	public void testLifecycle() throws Exception {
		
		OIDCProviderMetadata opMetadata = createSampleOPMetadata();
		
		JSONObject jsonObject = opMetadata.toJSONObject();
		
		ResolveSuccessResponse response = new ResolveSuccessResponse(jsonObject);
		assertEquals(jsonObject, response.getMetadataJSONObject());
		assertTrue(response.indicatesSuccess());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertEquals(200, httpResponse.getStatusCode());
		assertEquals("application/json; charset=UTF-8", httpResponse.getEntityContentType().toString());
		assertEquals(jsonObject, httpResponse.getContentAsJSONObject());
		
		response = ResolveSuccessResponse.parse(httpResponse);
		assertEquals(jsonObject, response.getMetadataJSONObject());
		assertTrue(response.indicatesSuccess());
	}
	
	
	public void testRejectNotOK() {
		
		try {
			ResolveSuccessResponse.parse(new HTTPResponse(400));
			fail();
		} catch (ParseException e) {
			assertEquals("Unexpected HTTP status code 400, must be [200]", e.getMessage());
		}
	}
}
