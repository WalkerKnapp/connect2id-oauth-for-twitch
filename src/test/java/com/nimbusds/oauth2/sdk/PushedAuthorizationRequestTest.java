/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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

package com.nimbusds.oauth2.sdk;


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import junit.framework.TestCase;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Map;


public class PushedAuthorizationRequestTest extends TestCase {
	
	
	public void testLifeCycle_clientSecretBasic_plainOAuth() throws ParseException {
		
		URI endpoint = URI.create("https://c2id.com/par");
		ClientID clientID = new ClientID();
		Secret clientSecret = new Secret();
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
		AuthorizationRequest authzRequest = new AuthorizationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE), clientID)
			.scope(new Scope("read", "write"))
			.build();
		
		PushedAuthorizationRequest par = new PushedAuthorizationRequest(endpoint, clientAuth, authzRequest);
		assertEquals(endpoint, par.getEndpointURI());
		assertEquals(clientAuth, par.getClientAuthentication());
		assertEquals(authzRequest, par.getAuthorizationRequest());
		
		HTTPRequest httpRequest = par.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		assertEquals(clientID, ClientSecretBasic.parse(httpRequest).getClientID());
		assertEquals(clientSecret, ClientSecretBasic.parse(httpRequest).getClientSecret());
		assertEquals(Collections.singletonList("code"), httpRequest.getBodyAsFormParameters().get("response_type"));
		assertEquals(Collections.singletonList(clientID.getValue()), httpRequest.getBodyAsFormParameters().get("client_id"));
		assertEquals(Collections.singletonList("read write"), httpRequest.getBodyAsFormParameters().get("scope"));
		assertEquals(3, httpRequest.getBodyAsFormParameters().size());
		
		par = PushedAuthorizationRequest.parse(httpRequest);
		assertEquals(endpoint, par.getEndpointURI());
		assertEquals(clientID, par.getClientAuthentication().getClientID());
		assertEquals(clientSecret, ((ClientSecretBasic)par.getClientAuthentication()).getClientSecret());
		assertEquals(authzRequest.toParameters(), par.getAuthorizationRequest().toParameters());
	}
	
	
	public void testLifeCycle_clientSecretBasic_openID() throws ParseException {
		
		URI endpoint = URI.create("https://c2id.com/par");
		ClientID clientID = new ClientID();
		Secret clientSecret = new Secret();
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
		AuthorizationRequest authzRequest = new AuthenticationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE), new Scope(OIDCScopeValue.OPENID), clientID, URI.create("https://example.com/cb"))
			.build();
		
		PushedAuthorizationRequest par = new PushedAuthorizationRequest(endpoint, clientAuth, authzRequest);
		assertEquals(endpoint, par.getEndpointURI());
		assertEquals(clientAuth, par.getClientAuthentication());
		assertEquals(authzRequest, par.getAuthorizationRequest());
		
		HTTPRequest httpRequest = par.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		assertEquals(clientID, ClientSecretBasic.parse(httpRequest).getClientID());
		assertEquals(clientSecret, ClientSecretBasic.parse(httpRequest).getClientSecret());
		assertEquals(Collections.singletonList("code"), httpRequest.getBodyAsFormParameters().get("response_type"));
		assertEquals(Collections.singletonList(clientID.getValue()), httpRequest.getBodyAsFormParameters().get("client_id"));
		assertEquals(Collections.singletonList("openid"), httpRequest.getBodyAsFormParameters().get("scope"));
		assertEquals(Collections.singletonList("https://example.com/cb"), httpRequest.getBodyAsFormParameters().get("redirect_uri"));
		assertEquals(4, httpRequest.getBodyAsFormParameters().size());
		
		par = PushedAuthorizationRequest.parse(httpRequest);
		assertEquals(endpoint, par.getEndpointURI());
		assertEquals(clientID, par.getClientAuthentication().getClientID());
		assertEquals(clientSecret, ((ClientSecretBasic)par.getClientAuthentication()).getClientSecret());
		assertEquals(authzRequest.toParameters(), par.getAuthorizationRequest().toParameters());
	}
	
	
	public void testLifeCycle_publicClient_plainOAuth() throws ParseException {
		
		URI endpoint = URI.create("https://c2id.com/par");
		ClientID clientID = new ClientID();
		AuthorizationRequest authzRequest = new AuthorizationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE), clientID)
			.scope(new Scope("read", "write"))
			.build();
		
		PushedAuthorizationRequest par = new PushedAuthorizationRequest(endpoint, authzRequest);
		assertEquals(endpoint, par.getEndpointURI());
		assertNull(par.getClientAuthentication());
		assertEquals(authzRequest, par.getAuthorizationRequest());
		
		HTTPRequest httpRequest = par.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		assertNull(httpRequest.getAuthorization());
		assertEquals(Collections.singletonList("code"), httpRequest.getBodyAsFormParameters().get("response_type"));
		assertEquals(Collections.singletonList(clientID.getValue()), httpRequest.getBodyAsFormParameters().get("client_id"));
		assertEquals(Collections.singletonList("read write"), httpRequest.getBodyAsFormParameters().get("scope"));
		assertEquals(3, httpRequest.getBodyAsFormParameters().size());
		
		par = PushedAuthorizationRequest.parse(httpRequest);
		assertEquals(endpoint, par.getEndpointURI());
		assertNull(par.getClientAuthentication());
		assertEquals(authzRequest.toParameters(), par.getAuthorizationRequest().toParameters());
	}
	
	
	public void testEndpointOptional() {
		
		ClientID clientID = new ClientID();
		Secret clientSecret = new Secret();
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
		AuthorizationRequest authzRequest = new AuthorizationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE), clientID)
			.scope(new Scope("read", "write"))
			.build();
		
		PushedAuthorizationRequest par = new PushedAuthorizationRequest(null, clientAuth, authzRequest);
		assertNull(par.getEndpointURI());
		assertEquals(clientAuth, par.getClientAuthentication());
		assertEquals(authzRequest, par.getAuthorizationRequest());
	}
	
	
	public void testConfidentialClientConstructor_requireClientAuthentication() {
		
		try {
			new PushedAuthorizationRequest(
				URI.create("https://c2id.com/par"),
				null,
				new AuthorizationRequest.Builder(new ResponseType(ResponseType.Value.CODE), new ClientID()).build());
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testRequireAuthzRequest() {
		
		// confidential client
		try {
			new PushedAuthorizationRequest(
				URI.create("https://c2id.com/par"),
				new ClientSecretBasic(new ClientID(), new Secret()),
				null);
			fail();
		} catch (NullPointerException e) {
			assertEquals("Cannot invoke \"com.nimbusds.oauth2.sdk.AuthorizationRequest.getRequestURI()\" because \"authzRequest\" is null", e.getMessage());
		}
		
		// public client
		try {
			new PushedAuthorizationRequest(
				URI.create("https://c2id.com/par"),
				null);
			fail();
		} catch (NullPointerException e) {
			assertEquals("Cannot invoke \"com.nimbusds.oauth2.sdk.AuthorizationRequest.getRequestURI()\" because \"authzRequest\" is null", e.getMessage());
		}
	}
	
	
	public void testParseHTTPRequest_requirePOST() {
		
		try {
			PushedAuthorizationRequest.parse(new HTTPRequest(HTTPRequest.Method.GET, new URL("https://c2id.com/par")));
			fail();
		} catch (ParseException | MalformedURLException e) {
			assertEquals("The HTTP request method must be POST", e.getMessage());
		}
	}
	
	
	public void testParseHTTPRequest_requireContentTypeHeader() throws ParseException {
		
		URI endpoint = URI.create("https://c2id.com/par");
		ClientID clientID = new ClientID();
		Secret clientSecret = new Secret();
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
		AuthorizationRequest authzRequest = new AuthorizationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE), clientID)
			.scope(new Scope("read", "write"))
			.build();
		PushedAuthorizationRequest par = new PushedAuthorizationRequest(endpoint, clientAuth, authzRequest);
		HTTPRequest httpRequest = par.toHTTPRequest();
		
		// Remove encoding
		httpRequest.setContentType((String)null);
		
		try {
			PushedAuthorizationRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing HTTP Content-Type header", e.getMessage());
		}
	}
	
	
	public void testParseHTTPRequest_requireURLEncodedParams() {
		
		URI endpoint = URI.create("https://c2id.com/par");
		ClientID clientID = new ClientID();
		Secret clientSecret = new Secret();
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
		AuthorizationRequest authzRequest = new AuthorizationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE), clientID)
			.scope(new Scope("read", "write"))
			.build();
		PushedAuthorizationRequest par = new PushedAuthorizationRequest(endpoint, clientAuth, authzRequest);
		HTTPRequest httpRequest = par.toHTTPRequest();
		
		// Remove encoding
		httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);
		
		try {
			PushedAuthorizationRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP Content-Type header must be application/x-www-form-urlencoded, received application/json", e.getMessage());
		}
	}
	
	// client_id param optional in request body when found in client auth (authZ header)
	public void testExtractClientIDFromClientSecretBasic() throws ParseException {
		
		URI endpoint = URI.create("https://c2id.com/par");
		ClientID clientID = new ClientID();
		Secret clientSecret = new Secret();
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
		AuthorizationRequest authzRequest = new AuthorizationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE), clientID)
			.scope(new Scope("read", "write"))
			.build();
		
		PushedAuthorizationRequest par = new PushedAuthorizationRequest(endpoint, clientAuth, authzRequest);
		
		HTTPRequest httpRequest = par.toHTTPRequest();
		
		Map<String, List<String>> params = httpRequest.getBodyAsFormParameters();
		params.remove("client_id"); // remove from body
		
		HTTPRequest modifiedHTTPRequest = new HTTPRequest(httpRequest.getMethod(), httpRequest.getURL());
		modifiedHTTPRequest.setEntityContentType(httpRequest.getEntityContentType());
		modifiedHTTPRequest.setAuthorization(httpRequest.getAuthorization());
		modifiedHTTPRequest.setBody(URLUtils.serializeParameters(params));
		
		par = PushedAuthorizationRequest.parse(modifiedHTTPRequest);
		assertEquals(endpoint, par.getEndpointURI());
		assertEquals(clientID, par.getClientAuthentication().getClientID());
		assertEquals(clientSecret, ((ClientSecretBasic)par.getClientAuthentication()).getClientSecret());
		assertEquals(authzRequest.toParameters(), par.getAuthorizationRequest().toParameters());
	}
	
	
	public void testRejectAuthorizationRequestWithRequestURI() {
		
		URI endpoint = URI.create("https://c2id.com/par");
		ClientID clientID = new ClientID();
		Secret clientSecret = new Secret();
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
		AuthorizationRequest authzRequest = new AuthorizationRequest.Builder(
			URI.create("https://example.com/eimeeph8"),
			clientID)
			.build();
		
		try {
			new PushedAuthorizationRequest(endpoint, clientAuth, authzRequest);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("Authorization request_uri parameter not allowed", e.getMessage());
		}
		
		try {
			new PushedAuthorizationRequest(endpoint, authzRequest);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("Authorization request_uri parameter not allowed", e.getMessage());
		}
	}
	
	
	public void testParseRejectAuthorizationRequestWithRequestURI() throws MalformedURLException {
		
		URI endpoint = URI.create("https://c2id.com/par");
		ClientID clientID = new ClientID();
		Secret clientSecret = new Secret();
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
		AuthorizationRequest authzRequest = new AuthorizationRequest.Builder(
			URI.create("https://example.com/eimeeph8"),
			clientID)
			.build();
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpoint.toURL());
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		clientAuth.applyTo(httpRequest);
		httpRequest.setBody(authzRequest.toQueryString());
		
		try {
			PushedAuthorizationRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Authorization request_uri parameter not allowed", e.getMessage());
			assertEquals(400, e.getErrorObject().getHTTPStatusCode());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Authorization request_uri parameter not allowed", e.getErrorObject().getDescription());
		}
	}
}
