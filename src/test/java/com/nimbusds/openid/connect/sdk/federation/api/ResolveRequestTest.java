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
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;


public class ResolveRequestTest extends TestCase {
	
	
	public void testLifecycle() throws Exception {
		
		URI endpoint = URI.create("https://openid.sunet.se/resolve");
		Subject subject = new Subject("https://idp.umu.se/openid");
		EntityID anchor = new EntityID("https://swamid.se");
		EntityType entityType = EntityType.OPENID_PROVIDER;
		
		ResolveRequest request = new ResolveRequest(
			endpoint,
			subject,
			anchor,
			entityType
		);
		
		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(subject, request.getSubject());
		assertEquals(new EntityID(subject), request.getSubjectEntityID());
		assertEquals(anchor, request.getTrustAnchor());
		assertEquals(entityType, request.getEntityType());
		
		Map<String, List<String>> params = request.toParameters();
		assertEquals(subject.getValue(), MultivaluedMapUtils.getFirstValue(params, "sub"));
		assertEquals(anchor.getValue(), MultivaluedMapUtils.getFirstValue(params, "anchor"));
		assertEquals(entityType.getValue(), MultivaluedMapUtils.getFirstValue(params, "type"));
		assertEquals(3, params.size());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertEquals(endpoint.toURL(), httpRequest.getURL());
		assertEquals(params, httpRequest.getQueryParameters());
		
		request = ResolveRequest.parse(httpRequest);
		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(subject, request.getSubject());
		assertEquals(new EntityID(subject), request.getSubjectEntityID());
		assertEquals(anchor, request.getTrustAnchor());
		assertEquals(entityType, request.getEntityType());
		
		request = ResolveRequest.parse(params);
		assertNull(request.getEndpointURI());
		assertEquals(subject, request.getSubject());
		assertEquals(new EntityID(subject), request.getSubjectEntityID());
		assertEquals(anchor, request.getTrustAnchor());
		assertEquals(entityType, request.getEntityType());
	}
	
	
	public void testLifecycle_entityTypeNotSpecified() throws Exception {
		
		URI endpoint = URI.create("https://openid.sunet.se/resolve");
		Subject subject = new Subject("https://idp.umu.se/openid");
		EntityID anchor = new EntityID("https://swamid.se");
		
		ResolveRequest request = new ResolveRequest(
			endpoint,
			subject,
			anchor,
			null
		);
		
		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(subject, request.getSubject());
		assertEquals(new EntityID(subject), request.getSubjectEntityID());
		assertEquals(anchor, request.getTrustAnchor());
		assertNull(request.getEntityType());
		
		Map<String, List<String>> params = request.toParameters();
		assertEquals(subject.getValue(), MultivaluedMapUtils.getFirstValue(params, "sub"));
		assertEquals(anchor.getValue(), MultivaluedMapUtils.getFirstValue(params, "anchor"));
		assertEquals(2, params.size());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertEquals(endpoint.toURL(), httpRequest.getURL());
		assertEquals(params, httpRequest.getQueryParameters());
		
		request = ResolveRequest.parse(httpRequest);
		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(subject, request.getSubject());
		assertEquals(new EntityID(subject), request.getSubjectEntityID());
		assertEquals(anchor, request.getTrustAnchor());
		assertNull(request.getEntityType());
		
		request = ResolveRequest.parse(params);
		assertNull(request.getEndpointURI());
		assertEquals(subject, request.getSubject());
		assertEquals(new EntityID(subject), request.getSubjectEntityID());
		assertEquals(anchor, request.getTrustAnchor());
		assertNull(request.getEntityType());
	}
	
	
	public void testParse_notGET() throws MalformedURLException {
		
		try {
			ResolveRequest.parse(new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/resolve")));
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP request method must be GET", e.getMessage());
		}
	}
	
	
	public void testParse_missingSubject() throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://openid.sunet.se/resolve"));
		httpRequest.setQuery("anchor=https%3A%2F%2Fswamid.se&type=openid_provider");
		
		try {
			ResolveRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing sub", e.getMessage());
		}
	}
	
	
	public void testParse_missingAnchor() throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://openid.sunet.se/federation_api_endpoint"));
		httpRequest.setQuery("sub=https%3A%2F%2Fidp.umu.se%2Fopenid&type=openid_provider");
		
		try {
			ResolveRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing anchor", e.getMessage());
		}
	}
}
