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


import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;


public class EntityListingRequestTest extends TestCase {
	
	
	public void testLifecycle() throws Exception {
		
		URI endpoint = new URI("https://openid.sunet.se/federation_api_endpoint");
		EntityListingRequest request = new EntityListingRequest(endpoint);
		
		assertTrue(request.toParameters().isEmpty());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertTrue(httpRequest.getQueryParameters().isEmpty());
		
		request = EntityListingRequest.parse(httpRequest);
		assertEquals(endpoint, request.getEndpointURI());
	}
	
	
	public void testParse_notGET() throws MalformedURLException {
		
		try {
			EntityListingRequest.parse(new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/federation")));
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP request method must be GET", e.getMessage());
		}
	}
}
