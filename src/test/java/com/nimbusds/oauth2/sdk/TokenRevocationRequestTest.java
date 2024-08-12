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
import com.nimbusds.oauth2.sdk.token.*;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import junit.framework.TestCase;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Tests the token revocation request.
 */
public class TokenRevocationRequestTest extends TestCase {


	public void testWithAccessToken_publicClient()
		throws Exception {

		URI endpointURI = new URI("https://c2id.com/token/revoke");
		Token token = new BearerAccessToken();

		TokenRevocationRequest request = new TokenRevocationRequest(endpointURI, new ClientID("123"), token);
		assertEquals(endpointURI, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals(token, request.getToken());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(endpointURI.toURL().toString(), httpRequest.getURL().toString());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		assertNull(httpRequest.getAuthorization());

		assertEquals(Collections.singletonList(token.getValue()), httpRequest.getQueryParameters().get("token"));
		assertEquals(Collections.singletonList("access_token"), httpRequest.getQueryParameters().get("token_type_hint"));
		assertEquals(Collections.singletonList("123"), httpRequest.getQueryParameters().get("client_id"));
		assertEquals(3, httpRequest.getQueryParameters().size());

		request = TokenRevocationRequest.parse(httpRequest);
		assertEquals(endpointURI, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals(token.getValue(), request.getToken().getValue());
		assertTrue(request.getToken() instanceof AccessToken);
	}


	public void testWithAccessToken_confidentialClient()
		throws Exception {

		URI endpointURI = new URI("https://c2id.com/token/revoke");
		Token token = new BearerAccessToken();
		ClientSecretBasic clientAuth = new ClientSecretBasic(new ClientID("123"), new Secret("secret"));

		TokenRevocationRequest request = new TokenRevocationRequest(endpointURI, clientAuth, token);
		assertEquals(endpointURI, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertNull(request.getClientID());
		assertEquals(token, request.getToken());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(endpointURI.toURL().toString(), httpRequest.getURL().toString());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());

		assertEquals(Collections.singletonList(token.getValue()), httpRequest.getQueryParameters().get("token"));
		assertEquals(Collections.singletonList("access_token"), httpRequest.getQueryParameters().get("token_type_hint"));
		assertEquals(2, httpRequest.getQueryParameters().size());

		ClientSecretBasic basicAuth = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertEquals("123", basicAuth.getClientID().getValue());
		assertEquals("secret", basicAuth.getClientSecret().getValue());

		request = TokenRevocationRequest.parse(httpRequest);
		assertEquals(endpointURI, request.getEndpointURI());
		assertEquals(clientAuth.getClientID(), request.getClientAuthentication().getClientID());
		assertEquals(clientAuth.getClientSecret(), ((ClientSecretBasic)request.getClientAuthentication()).getClientSecret());
		assertNull(request.getClientID());
		assertEquals(token.getValue(), request.getToken().getValue());
		assertTrue(request.getToken() instanceof AccessToken);
	}


	public void testWithRefreshToken_publicClient()
		throws Exception {

		URI endpointURI = new URI("https://c2id.com/token/revoke");
		Token token = new RefreshToken();

		TokenRevocationRequest request = new TokenRevocationRequest(endpointURI, new ClientID("123"), token);
		assertEquals(endpointURI, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(token, request.getToken());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(endpointURI.toURL().toString(), httpRequest.getURL().toString());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		assertNull(httpRequest.getAuthorization());

		assertEquals(Collections.singletonList(token.getValue()), httpRequest.getQueryParameters().get("token"));
		assertEquals(Collections.singletonList("refresh_token"), httpRequest.getQueryParameters().get("token_type_hint"));
		assertEquals(Collections.singletonList("123"), httpRequest.getQueryParameters().get("client_id"));
		assertEquals(3, httpRequest.getQueryParameters().size());

		request = TokenRevocationRequest.parse(httpRequest);
		assertEquals(endpointURI, request.getEndpointURI());
		assertNull(request.getClientAuthentication());
		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals(token.getValue(), request.getToken().getValue());
		assertTrue(request.getToken() instanceof RefreshToken);
	}


	public void testWithRefreshToken_confidentialClient()
		throws Exception {

		URI endpointURI = new URI("https://c2id.com/token/revoke");
		Token token = new RefreshToken();
		ClientSecretBasic clientAuth = new ClientSecretBasic(new ClientID("123"), new Secret("secret"));

		TokenRevocationRequest request = new TokenRevocationRequest(endpointURI, clientAuth, token);
		assertEquals(endpointURI, request.getEndpointURI());
		assertEquals(clientAuth, request.getClientAuthentication());
		assertEquals(token, request.getToken());

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(endpointURI.toURL().toString(), httpRequest.getURL().toString());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());

		assertEquals(Collections.singletonList(token.getValue()), httpRequest.getQueryParameters().get("token"));
		assertEquals(Collections.singletonList("refresh_token"), httpRequest.getQueryParameters().get("token_type_hint"));
		assertEquals(2, httpRequest.getQueryParameters().size());

		ClientSecretBasic basicAuth = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertEquals("123", basicAuth.getClientID().getValue());
		assertEquals("secret", basicAuth.getClientSecret().getValue());

		request = TokenRevocationRequest.parse(httpRequest);
		assertEquals(endpointURI, request.getEndpointURI());
		assertEquals(clientAuth.getClientID(), request.getClientAuthentication().getClientID());
		assertEquals(clientAuth.getClientSecret(), ((ClientSecretBasic)request.getClientAuthentication()).getClientSecret());
		assertNull(request.getClientID());
		assertEquals(token.getValue(), request.getToken().getValue());
		assertTrue(request.getToken() instanceof RefreshToken);
	}


	public void testWithUnknownToken_publicClient()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token/revoke"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		Map<String,List<String>> queryParams = new HashMap<>();
		queryParams.put("token", Collections.singletonList("abc"));
		queryParams.put("client_id", Collections.singletonList("123"));
		httpRequest.setBody(URLUtils.serializeParameters(queryParams));

		TokenRevocationRequest request = TokenRevocationRequest.parse(httpRequest);
		assertEquals("abc", request.getToken().getValue());
		assertTrue(request.getToken() instanceof TypelessToken);
		assertNull(request.getClientAuthentication());
		assertEquals(new ClientID("123"), request.getClientID());
	}


	public void testWithUnknownToken_confidentialClient()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token/revoke"));
		httpRequest.setAuthorization(new ClientSecretBasic(new ClientID("123"), new Secret("secret")).toHTTPAuthorizationHeader());
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		Map<String,List<String>> queryParams = new HashMap<>();
		queryParams.put("token", Collections.singletonList("abc"));
		httpRequest.setBody(URLUtils.serializeParameters(queryParams));

		TokenRevocationRequest request = TokenRevocationRequest.parse(httpRequest);
		assertEquals("abc", request.getToken().getValue());
		assertTrue(request.getToken() instanceof TypelessToken);
		assertEquals(new ClientID("123"), request.getClientAuthentication().getClientID());
		assertEquals(new Secret("secret"), ((ClientSecretBasic)request.getClientAuthentication()).getClientSecret());
		assertNull(request.getClientID());
	}


	public void testWithUnsupportedToken_publicClient()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token/revoke"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		Map<String,List<String>> queryParams = new HashMap<>();
		queryParams.put("token", Collections.singletonList("abc"));
		queryParams.put("token_type_hint", Collections.singletonList("xxx"));
		queryParams.put("client_id", Collections.singletonList("123"));
		httpRequest.setBody(URLUtils.serializeParameters(queryParams));

		TokenRevocationRequest request = TokenRevocationRequest.parse(httpRequest);
		assertEquals("abc", request.getToken().getValue());
		assertTrue(request.getToken() instanceof TypelessToken);
		assertNull(request.getClientAuthentication());
		assertEquals(new ClientID("123"), request.getClientID());
	}


	public void testWithUnsupportedToken_confidentialClient()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token/revoke"));
		httpRequest.setAuthorization(new ClientSecretBasic(new ClientID("123"), new Secret("secret")).toHTTPAuthorizationHeader());
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		Map<String,List<String>> queryParams = new HashMap<>();
		queryParams.put("token", Collections.singletonList("abc"));
		queryParams.put("token_type_hint", Collections.singletonList("xxx"));
		httpRequest.setBody(URLUtils.serializeParameters(queryParams));

		TokenRevocationRequest request = TokenRevocationRequest.parse(httpRequest);
		assertEquals("abc", request.getToken().getValue());
		assertTrue(request.getToken() instanceof TypelessToken);
		assertEquals(new ClientID("123"), request.getClientAuthentication().getClientID());
		assertEquals(new Secret("secret"), ((ClientSecretBasic)request.getClientAuthentication()).getClientSecret());
		assertNull(request.getClientID());
	}


	public void testConstructorRequireClientAuthentication() {

		try {
			new TokenRevocationRequest(URI.create("https://c2id.com/token"), (ClientAuthentication)null, new BearerAccessToken());
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}


	public void testConstructorRequireClientID() {

		try {
			new TokenRevocationRequest(URI.create("https://c2id.com/token"), (ClientID) null, new BearerAccessToken());
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}


	public void testParseMissingClientIdentification()
		throws MalformedURLException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token/revoke"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		Map<String,List<String>> queryParams = new HashMap<>();
		queryParams.put("token", Collections.singletonList("abc"));
		httpRequest.setBody(URLUtils.serializeParameters(queryParams));

		try {
			TokenRevocationRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid token revocation request: No client authentication or client_id parameter found", e.getMessage());
		}
	}


	public void testParseBlankToken()
		throws MalformedURLException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token/revoke"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		Map<String,List<String>> queryParams = new HashMap<>();
		queryParams.put("client_id", Collections.singletonList("123"));
		queryParams.put("token", Collections.singletonList(" "));
		httpRequest.setBody(URLUtils.serializeParameters(queryParams));

		try {
			TokenRevocationRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing required token parameter", e.getMessage());
		}
	}
}
