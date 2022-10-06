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
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;


public class TrustNegotiationRequestTest extends TestCase {
	
	
	public void testLifecycle() throws Exception {
		
		URI endpoint = URI.create("https://openid.sunet.se/federation_api_endpoint");
		EntityID respondent = new EntityID("https://openid.sunet.se/federation_api_endpoint");
		EntityID peer = new EntityID("https://idp.umu.se/openid");
		EntityType metadataType = EntityType.OPENID_PROVIDER;
		EntityID anchor = new EntityID("https://swamid.se");
		
		TrustNegotiationRequest request = new TrustNegotiationRequest(
			endpoint,
			respondent,
			peer,
			metadataType,
			anchor
		);
		
		assertEquals(OperationType.RESOLVE_METADATA, request.getOperationType());
		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(respondent, request.getRespondent());
		assertEquals(peer, request.getPeer());
		assertEquals(metadataType, request.getMetadataType());
		assertEquals(anchor, request.getTrustAnchor());
		
		Map<String, List<String>> params = request.toParameters();
		assertEquals(OperationType.RESOLVE_METADATA.getValue(), MultivaluedMapUtils.getFirstValue(params, "operation"));
		assertEquals(respondent.getValue(), MultivaluedMapUtils.getFirstValue(params, "respondent"));
		assertEquals(peer.getValue(), MultivaluedMapUtils.getFirstValue(params, "peer"));
		assertEquals(metadataType.getValue(), MultivaluedMapUtils.getFirstValue(params, "type"));
		assertEquals(anchor.getValue(), MultivaluedMapUtils.getFirstValue(params, "anchor"));
		assertEquals(5, params.size());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertEquals(endpoint.toURL(), httpRequest.getURL());
		assertEquals(params, httpRequest.getQueryParameters());
		
		request = TrustNegotiationRequest.parse(httpRequest);
		assertEquals(OperationType.RESOLVE_METADATA, request.getOperationType());
		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(respondent, request.getRespondent());
		assertEquals(peer, request.getPeer());
		assertEquals(metadataType, request.getMetadataType());
		assertEquals(anchor, request.getTrustAnchor());
		
		request = TrustNegotiationRequest.parse(params);
		assertEquals(OperationType.RESOLVE_METADATA, request.getOperationType());
		assertNull(request.getEndpointURI());
		assertEquals(respondent, request.getRespondent());
		assertEquals(peer, request.getPeer());
		assertEquals(metadataType, request.getMetadataType());
		assertEquals(anchor, request.getTrustAnchor());
	}
	
	
	public void testParse_notGET() throws MalformedURLException {
		
		try {
			TrustNegotiationRequest.parse(new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/federation")));
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP request method must be GET", e.getMessage());
		}
	}
	
	
	public void testParse_operationMissing() throws MalformedURLException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://c2id.com/federation"));
		httpRequest.setQuery("respondent=https%3A%2F%2Fopenid.sunet.se%2Ffederation&" +
			"type=openid_provider&" +
			"anchor=https%3A%2F%2Fswamid.se&" +
			"peer=https%3A%2F%2Fidp.umu.se%2Fopenid");
		
		try {
			TrustNegotiationRequest.parse(httpRequest);
			fail();
		} catch (ParseException  e) {
			assertEquals("Missing operation type", e.getMessage());
		}
	}
	
	
	public void testParse_operationMismatch() throws MalformedURLException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://c2id.com/federation"));
		httpRequest.setQuery("operation=listing&" +
			"respondent=https%3A%2F%2Fopenid.sunet.se%2Ffederation&" +
			"type=openid_provider&" +
			"anchor=https%3A%2F%2Fswamid.se&" +
			"peer=https%3A%2F%2Fidp.umu.se%2Fopenid");
		
		try {
			TrustNegotiationRequest.parse(httpRequest);
			fail();
		} catch (ParseException  e) {
			assertEquals("The operation type must be resolve_metadata", e.getMessage());
		}
	}
	
	
	public void testParse_missingRespondent() throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://openid.sunet.se/federation_api_endpoint"));
		httpRequest.setQuery("operation=resolve_metadata&" +
			"type=openid_provider&" +
			"anchor=https%3A%2F%2Fswamid.se&" +
			"peer=https%3A%2F%2Fidp.umu.se%2Fopenid");
		
		try {
			TrustNegotiationRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing respondent", e.getMessage());
		}
	}
	
	
	public void testParse_missingPeer() throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://openid.sunet.se/federation_api_endpoint"));
		httpRequest.setQuery("operation=resolve_metadata&" +
			"respondent=https%3A%2F%2Fopenid.sunet.se%2Ffederation&" +
			"type=openid_provider&" +
			"anchor=https%3A%2F%2Fswamid.se");
		
		try {
			TrustNegotiationRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing peer", e.getMessage());
		}
	}
	
	
	public void testParse_missingMetadataType() throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://openid.sunet.se/federation_api_endpoint"));
		httpRequest.setQuery("operation=resolve_metadata&" +
			"respondent=https%3A%2F%2Fopenid.sunet.se%2Ffederation&" +
			"anchor=https%3A%2F%2Fswamid.se&" +
			"peer=https%3A%2F%2Fidp.umu.se%2Fopenid");
		
		try {
			TrustNegotiationRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing metadata type", e.getMessage());
		}
	}
	
	
	public void testParse_missingAnchor() throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://openid.sunet.se/federation_api_endpoint"));
		httpRequest.setQuery("operation=resolve_metadata&" +
			"respondent=https%3A%2F%2Fopenid.sunet.se%2Ffederation&" +
			"type=openid_provider&" +
			"peer=https%3A%2F%2Fidp.umu.se%2Fopenid");
		
		try {
			TrustNegotiationRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing anchor", e.getMessage());
		}
	}
}
