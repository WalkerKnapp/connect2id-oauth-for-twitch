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


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;
import junit.framework.TestCase;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Map;


public class EntityListingRequestTest extends TestCase {
	
	
	public void testLifecycle() throws Exception {
		
		URI endpoint = new URI("https://openid.sunet.se/federation_api_endpoint");
		EntityListingRequest request = new EntityListingRequest(endpoint);
		assertEquals(endpoint, request.getEndpointURI());
		assertNull(request.getEntityType());
		
		assertTrue(request.toParameters().isEmpty());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertTrue(httpRequest.getQueryStringParameters().isEmpty());
		
		request = EntityListingRequest.parse(httpRequest);
		assertEquals(endpoint, request.getEndpointURI());
		assertNull(request.getEntityType());
	}
	
	
	public void testLifecycle_withEntityType() throws Exception {
		
		URI endpoint = new URI("https://openid.sunet.se/federation_api_endpoint");
		EntityType entityType = EntityType.OPENID_PROVIDER;
		EntityListingRequest request = new EntityListingRequest(endpoint, entityType);
		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(entityType, request.getEntityType());
		
		Map<String, List<String>> params = request.toParameters();
		assertEquals(Collections.singletonList(entityType.getValue()), params.get("entity_type"));
		assertEquals(1, params.size());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		params = httpRequest.getQueryStringParameters();
		assertEquals(Collections.singletonList(entityType.getValue()), params.get("entity_type"));
		assertEquals(1, params.size());
		
		request = EntityListingRequest.parse(httpRequest);
		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(entityType, request.getEntityType());
	}
	
	
	public void testParse_notPOST() throws MalformedURLException {
		
		try {
			EntityListingRequest.parse(new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/federation")));
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP request method must be GET", e.getMessage());
		}
	}
}
