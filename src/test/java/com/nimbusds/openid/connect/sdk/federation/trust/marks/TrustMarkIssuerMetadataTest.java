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

package com.nimbusds.openid.connect.sdk.federation.trust.marks;


import java.net.URI;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


public class TrustMarkIssuerMetadataTest extends TestCase {
	
	
	private static final URI FEDERATION_STATUS_ENDPOINT = URI.create("https://trust-mark-issuer.example.com/status");


	public void testWithEndpoint() throws ParseException {
		
		TrustMarkIssuerMetadata metadata = new TrustMarkIssuerMetadata(FEDERATION_STATUS_ENDPOINT);
		assertEquals(FEDERATION_STATUS_ENDPOINT, metadata.getFederationStatusEndpointURI());
		
		JSONObject jsonObject = metadata.toJSONObject();
		assertEquals(FEDERATION_STATUS_ENDPOINT, JSONObjectUtils.getURI(jsonObject, "federation_status_endpoint"));
		
		String json = jsonObject.toJSONString();
		
		metadata = TrustMarkIssuerMetadata.parse(json);
		
		assertEquals(FEDERATION_STATUS_ENDPOINT, metadata.getFederationStatusEndpointURI());
	}
	
	
	public void testEmpty() throws ParseException {
		
		TrustMarkIssuerMetadata metadata = new TrustMarkIssuerMetadata(null);
		assertNull(metadata.getFederationStatusEndpointURI());
		
		JSONObject jsonObject = metadata.toJSONObject();
		assertTrue(jsonObject.isEmpty());
		
		String json = jsonObject.toJSONString();
		
		metadata = TrustMarkIssuerMetadata.parse(json);
		
		assertNull(metadata.getFederationStatusEndpointURI());
	}
}
