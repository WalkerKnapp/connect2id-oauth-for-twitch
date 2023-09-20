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

package com.nimbusds.oauth2.sdk.device;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import junit.framework.TestCase;

import java.net.URI;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DeviceAuthorizationRequestTest extends TestCase {

	public void testRegisteredParameters() {

		assertTrue(DeviceAuthorizationRequest.getRegisteredParameterNames().contains("client_id"));
		assertTrue(DeviceAuthorizationRequest.getRegisteredParameterNames().contains("scope"));
		assertEquals(2, DeviceAuthorizationRequest.getRegisteredParameterNames().size());
	}


	public void testMinimal() throws Exception {

		URI uri = new URI("https://c2id.com/devauthz/");

		ClientID clientID = new ClientID("123456");

		DeviceAuthorizationRequest req = new DeviceAuthorizationRequest(uri, clientID);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(clientID, req.getClientID());

		assertNull(req.getScope());

		assertNull(req.getCustomParameter("custom-param"));
		assertTrue(req.getCustomParameters().isEmpty());

		HTTPRequest httpReq = req.toHTTPRequest();
		Map<String, List<String>> params = httpReq.getBodyAsFormParameters();
		assertEquals(HTTPRequest.Method.POST, httpReq.getMethod());
		assertEquals(uri, httpReq.getURL().toURI());
		assertEquals(params.size(), 1);

		req = DeviceAuthorizationRequest.parse(httpReq);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(clientID, req.getClientID());

		assertNull(req.getScope());

		assertNull(req.getCustomParameter("custom-param"));
		assertTrue(req.getCustomParameters().isEmpty());
	}


	public void testFull() throws Exception {

		URI uri = new URI("https://c2id.com/devauthz/");

		ClientID clientID = new ClientID("123456");
		Scope scope = Scope.parse("read write");

		Map<String, List<String>> customParams = new HashMap<>();
		customParams.put("x", Collections.singletonList("100"));
		customParams.put("y", Collections.singletonList("200"));
		customParams.put("z", Collections.singletonList("300"));

		DeviceAuthorizationRequest req = new DeviceAuthorizationRequest(uri, clientID, scope, customParams);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(clientID, req.getClientID());
		assertEquals(scope, req.getScope());

		HTTPRequest httpReq = req.toHTTPRequest();
		Map<String, List<String>> params = httpReq.getBodyAsFormParameters();
		assertEquals(HTTPRequest.Method.POST, httpReq.getMethod());
		assertEquals(5, params.size());

		req = DeviceAuthorizationRequest.parse(httpReq);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(clientID, req.getClientID());
		assertEquals(scope, req.getScope());
		assertEquals(Collections.singletonList("100"), req.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), req.getCustomParameter("y"));
		assertEquals(Collections.singletonList("300"), req.getCustomParameter("z"));
		assertEquals(Collections.singletonList("100"), req.getCustomParameters().get("x"));
		assertEquals(Collections.singletonList("200"), req.getCustomParameters().get("y"));
		assertEquals(Collections.singletonList("300"), req.getCustomParameters().get("z"));
		assertEquals(3, req.getCustomParameters().size());
	}


	public void testClientAuth() throws Exception {

		URI uri = new URI("https://c2id.com/devauthz/");

		ClientSecretBasic clientAuth = new ClientSecretBasic(new ClientID("123456"), new Secret("secret"));
		Scope scope = Scope.parse("read write");

		Map<String, List<String>> customParams = new HashMap<>();
		customParams.put("q", Collections.singletonList("abc"));
		customParams.put("r", Collections.singletonList("xyz"));

		DeviceAuthorizationRequest req = new DeviceAuthorizationRequest(uri, clientAuth, scope, customParams);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, req.getClientAuthentication().getMethod());
		assertEquals(clientAuth.getClientID(), req.getClientAuthentication().getClientID());
		assertEquals(clientAuth.getClientSecret(),
		                ((ClientSecretBasic) req.getClientAuthentication()).getClientSecret());
		assertEquals(scope, req.getScope());

		HTTPRequest httpReq = req.toHTTPRequest();
		Map<String, List<String>> params = httpReq.getBodyAsFormParameters();
		assertEquals(HTTPRequest.Method.POST, httpReq.getMethod());
		assertEquals(3, params.size());

		req = DeviceAuthorizationRequest.parse(httpReq);

		assertEquals(uri, req.getEndpointURI());
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, req.getClientAuthentication().getMethod());
		assertEquals(clientAuth.getClientID(), req.getClientAuthentication().getClientID());
		assertEquals(clientAuth.getClientSecret(),
		                ((ClientSecretBasic) req.getClientAuthentication()).getClientSecret());
		assertEquals(scope, req.getScope());
		assertEquals(Collections.singletonList("abc"), req.getCustomParameter("q"));
		assertEquals(Collections.singletonList("xyz"), req.getCustomParameter("r"));
		assertEquals(Collections.singletonList("abc"), req.getCustomParameters().get("q"));
		assertEquals(Collections.singletonList("xyz"), req.getCustomParameters().get("r"));
		assertEquals(2, req.getCustomParameters().size());
	}


	public void testBuilderMinimal() {

		DeviceAuthorizationRequest request = new DeviceAuthorizationRequest.Builder(new ClientID("123"))
		                .build();

		assertEquals(new ClientID("123"), request.getClientID());
		assertNull(request.getEndpointURI());
		assertNull(request.getScope());
		assertTrue(request.getCustomParameters().isEmpty());
	}


	public void testBuilderFull() throws Exception {

		DeviceAuthorizationRequest request = new DeviceAuthorizationRequest.Builder(new ClientID("123"))
		                .endpointURI(new URI("https://c2id.com/devauthz")).scope(new Scope("openid", "email"))
		                .build();

		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals("https://c2id.com/devauthz", request.getEndpointURI().toString());
		assertEquals(new Scope("openid", "email"), request.getScope());
	}


	public void testBuilderFullAlt() throws Exception {

		DeviceAuthorizationRequest request = new DeviceAuthorizationRequest.Builder(new ClientID("123"))
		                .endpointURI(new URI("https://c2id.com/devauthz")).scope(new Scope("openid", "email"))
		                .customParameter("x", "100").customParameter("y", "200").customParameter("z", "300")
		                .build();

		assertEquals(new ClientID("123"), request.getClientID());
		assertEquals("https://c2id.com/devauthz", request.getEndpointURI().toString());
		assertEquals(new Scope("openid", "email"), request.getScope());
		assertEquals(Collections.singletonList("100"), request.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameter("y"));
		assertEquals(Collections.singletonList("300"), request.getCustomParameter("z"));
		assertEquals(Collections.singletonList("100"), request.getCustomParameters().get("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameters().get("y"));
		assertEquals(Collections.singletonList("300"), request.getCustomParameters().get("z"));
		assertEquals(3, request.getCustomParameters().size());
	}


	public void testBuilderFullAuth() throws Exception {

		DeviceAuthorizationRequest request = new DeviceAuthorizationRequest.Builder(
		                new ClientSecretPost(new ClientID("123"), new Secret("secret")))
		                                .endpointURI(new URI("https://c2id.com/devauthz"))
		                                .scope(new Scope("openid", "email")).customParameter("x", "100")
		                                .customParameter("y", "200").customParameter("z", "300").build();

		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_POST,
		                request.getClientAuthentication().getMethod());
		assertEquals(new ClientID("123"), request.getClientAuthentication().getClientID());
		assertEquals("https://c2id.com/devauthz", request.getEndpointURI().toString());
		assertEquals(new Scope("openid", "email"), request.getScope());
		assertEquals(Collections.singletonList("100"), request.getCustomParameter("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameter("y"));
		assertEquals(Collections.singletonList("300"), request.getCustomParameter("z"));
		assertEquals(Collections.singletonList("100"), request.getCustomParameters().get("x"));
		assertEquals(Collections.singletonList("200"), request.getCustomParameters().get("y"));
		assertEquals(Collections.singletonList("300"), request.getCustomParameters().get("z"));
		assertEquals(3, request.getCustomParameters().size());
	}


	public void testConstructParseExceptionMissingClientID() throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/devauthz");

		try {
			new DeviceAuthorizationRequest(tokenEndpoint, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The client ID must not be null", e.getMessage());
		}

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST,
		                new URL("https://c2id.com/devauthz"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		try {
			DeviceAuthorizationRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing client_id parameter", e.getMessage());
			assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid request: Missing client_id parameter",
			                e.getErrorObject().getDescription());
			assertNull(e.getErrorObject().getURI());
		}
	}


	public void testCopyConstructorBuilder() throws Exception {

		Map<String, List<String>> customParams = new HashMap<>();
		customParams.put("apples", Collections.singletonList("10"));

		DeviceAuthorizationRequest in = new DeviceAuthorizationRequest(new URI("https://c2id.com/devauthz"),
		                new ClientID("123"), new Scope("openid"), customParams);

		DeviceAuthorizationRequest out = new DeviceAuthorizationRequest.Builder(in).build();

		assertEquals(in.getScope(), out.getScope());
		assertEquals(in.getClientID(), out.getClientID());
		assertEquals(in.getCustomParameters(), out.getCustomParameters());
		assertEquals(in.getEndpointURI(), out.getEndpointURI());
	}
}
