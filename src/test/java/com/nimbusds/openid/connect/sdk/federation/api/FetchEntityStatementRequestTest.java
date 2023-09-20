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
import java.util.Collections;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;


public class FetchEntityStatementRequestTest extends TestCase {
	
	
	public void testConstructorMinimal() throws Exception {
		URI endpoint = new URI("https://openid.sunet.se/federation_api_endpoint");
		FetchEntityStatementRequest request = new FetchEntityStatementRequest(endpoint, (Issuer) null, null);
		assertEquals(endpoint, request.getEndpointURI());
		assertNull(request.getIssuer());
		assertNull(request.getIssuerEntityID());;
		assertNull(request.getSubject());
		assertNull(request.getSubjectEntityID());;
		
		assertTrue(request.toParameters().isEmpty());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertEquals(endpoint, httpRequest.getURI());
		assertTrue(httpRequest.getQueryStringParameters().isEmpty());
		
		request = FetchEntityStatementRequest.parse(httpRequest);
		assertEquals(endpoint, request.getEndpointURI());
		assertNull(request.getIssuer());
		assertNull(request.getIssuerEntityID());;
		assertNull(request.getSubject());
		assertNull(request.getSubjectEntityID());;
	}
	
	
	public void testConstructor() throws Exception {
		URI endpoint = new URI("https://openid.sunet.se/federation_api_endpoint");
		Issuer issuer = new Issuer("https://openid.sunet.se");
		Subject subject = new Subject("https://https://ntnu.andreas.labs.uninett.no/");
		FetchEntityStatementRequest request = new FetchEntityStatementRequest(endpoint, issuer, subject);
		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(issuer, request.getIssuer());
		assertEquals(new EntityID(issuer.getValue()), request.getIssuerEntityID());
		assertEquals(subject, request.getSubject());
		assertEquals(subject.getValue(), request.getSubjectEntityID().getValue());
		
		Map<String,List<String>> params = request.toParameters();
		assertEquals(Collections.singletonList(issuer.getValue()), params.get("iss"));
		assertEquals(Collections.singletonList(subject.getValue()), params.get("sub"));
		assertEquals(2, params.size());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertTrue(httpRequest.getURI().toString().startsWith(endpoint.toString()));
		assertEquals(params, httpRequest.getQueryStringParameters());
		
		request = FetchEntityStatementRequest.parse(httpRequest);
		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(issuer, request.getIssuer());
		assertEquals(new EntityID(issuer.getValue()), request.getIssuerEntityID());
		assertEquals(subject, request.getSubject());
		assertEquals(subject.getValue(), request.getSubjectEntityID().getValue());
	}
	
	
	public void testEntityIDConstructor() throws Exception {
		
		URI endpoint = new URI("https://openid.sunet.se/federation_api_endpoint");
		EntityID issuer = new EntityID("https://openid.sunet.se");
		EntityID subject = new EntityID("https://https://ntnu.andreas.labs.uninett.no/");
		FetchEntityStatementRequest request = new FetchEntityStatementRequest(endpoint, issuer, subject);
		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(issuer.getValue(), request.getIssuer().getValue());
		assertEquals(issuer, request.getIssuerEntityID());
		assertEquals(subject.getValue(), request.getSubject().getValue());
		assertEquals(subject, request.getSubjectEntityID());
		
		Map<String,List<String>> params = request.toParameters();
		assertEquals(Collections.singletonList(issuer.getValue()), params.get("iss"));
		assertEquals(Collections.singletonList(subject.getValue()), params.get("sub"));
		assertEquals(2, params.size());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertTrue(httpRequest.getURI().toString().startsWith(endpoint.toString()));
		assertEquals(params, httpRequest.getQueryStringParameters());
		
		request = FetchEntityStatementRequest.parse(httpRequest);
		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(issuer.getValue(), request.getIssuer().getValue());
		assertEquals(issuer, request.getIssuerEntityID());
		assertEquals(subject.getValue(), request.getSubject().getValue());
		assertEquals(subject, request.getSubjectEntityID());
	}
	
	
	public void testParse_notGET() throws MalformedURLException {
		
		try {
			FetchEntityStatementRequest.parse(new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/federation")));
			fail();
		} catch (ParseException  e) {
			assertEquals("The HTTP request method must be GET", e.getMessage());
		}
	}
}
