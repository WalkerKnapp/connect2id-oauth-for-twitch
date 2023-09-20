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

package com.nimbusds.oauth2.sdk.http;


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.Nonce;
import junit.framework.TestCase;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;
import java.util.Map;


public class HTTPResponseTest extends TestCase {
	
	
	public void testStatusCodeConstants() {
		
		assertEquals(200, HTTPResponse.SC_OK);
		assertEquals(201, HTTPResponse.SC_CREATED);
		assertEquals(302, HTTPResponse.SC_FOUND);
		assertEquals(400, HTTPResponse.SC_BAD_REQUEST);
		assertEquals(401, HTTPResponse.SC_UNAUTHORIZED);
		assertEquals(403, HTTPResponse.SC_FORBIDDEN);
		assertEquals(404, HTTPResponse.SC_NOT_FOUND);
		assertEquals(500, HTTPResponse.SC_SERVER_ERROR);
		assertEquals(503, HTTPResponse.SC_SERVICE_UNAVAILABLE);
	}


	public void testConstructorAndAccessors()
		throws Exception {

		HTTPResponse response = new HTTPResponse(200);

		assertTrue(response.indicatesSuccess());
		assertEquals(200, response.getStatusCode());

		response.ensureStatusCode(200);
		response.ensureStatusCode(200, 201);

		try {
			response.ensureStatusCode(302);
			fail();
		} catch (ParseException e) {
			// ok
			assertEquals("Unexpected HTTP status code 200, must be [302]", e.getMessage());
		}
		
		assertNull(response.getStatusMessage());
		response.setStatusMessage("OK");
		assertEquals("OK", response.getStatusMessage());

		assertNull(response.getEntityContentType());
		response.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), response.getEntityContentType().toString());

		assertNull(response.getLocation());
		URI location = new URI("https://client.com/cb");
		response.setLocation(location);
		assertEquals(location, response.getLocation());

		assertNull(response.getCacheControl());
		response.setCacheControl("no-cache");
		assertEquals("no-cache", response.getCacheControl());

		assertNull(response.getPragma());
		response.setPragma("no-cache");
		assertEquals("no-cache", response.getPragma());

		assertNull(response.getWWWAuthenticate());
		response.setWWWAuthenticate("Basic");
		assertEquals("Basic", response.getWWWAuthenticate());
		
		assertNull(response.getDPoPNonce());
		response.setDPoPNonce(new Nonce("waeHieMa4dan"));
		assertEquals(new Nonce("waeHieMa4dan"), response.getDPoPNonce());
		

		assertNull(response.getBody());

		try {
			response.getBodyAsJSONObject();
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP Content-Type header must be application/json, received application/x-www-form-urlencoded", e.getMessage());
		}

		try {
			response.getBodyAsJWT();
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP Content-Type header must be application/jwt, received application/x-www-form-urlencoded", e.getMessage());
		}

		response.setEntityContentType(ContentType.APPLICATION_JSON);
		response.setBody("{\"apples\":\"123\"}");
		assertEquals("{\"apples\":\"123\"}", response.getBody());

		JSONObject jsonObject = response.getBodyAsJSONObject();
		assertEquals("123", (String)jsonObject.get("apples"));

		// From http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-13#section-3.1
		String exampleJWTString = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
			"." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
			"." +
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		response.setEntityContentType(ContentType.APPLICATION_JWT);
		response.setBody(exampleJWTString);

		JWT jwt = response.getBodyAsJWT();
		assertEquals(JWSAlgorithm.HS256, jwt.getHeader().getAlgorithm());
	}


	public void testConstructorAndAccessors_deprecated()
		throws Exception {

		HTTPResponse response = new HTTPResponse(200);

		assertTrue(response.indicatesSuccess());
		assertEquals(200, response.getStatusCode());

		response.ensureStatusCode(200);
		response.ensureStatusCode(200, 201);

		try {
			response.ensureStatusCode(302);
			fail();
		} catch (ParseException e) {
			// ok
			assertEquals("Unexpected HTTP status code 200, must be [302]", e.getMessage());
		}

		assertNull(response.getStatusMessage());
		response.setStatusMessage("OK");
		assertEquals("OK", response.getStatusMessage());

		assertNull(response.getEntityContentType());
		response.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), response.getEntityContentType().toString());

		assertNull(response.getLocation());
		URI location = new URI("https://client.com/cb");
		response.setLocation(location);
		assertEquals(location, response.getLocation());

		assertNull(response.getCacheControl());
		response.setCacheControl("no-cache");
		assertEquals("no-cache", response.getCacheControl());

		assertNull(response.getPragma());
		response.setPragma("no-cache");
		assertEquals("no-cache", response.getPragma());

		assertNull(response.getWWWAuthenticate());
		response.setWWWAuthenticate("Basic");
		assertEquals("Basic", response.getWWWAuthenticate());

		assertNull(response.getDPoPNonce());
		response.setDPoPNonce(new Nonce("waeHieMa4dan"));
		assertEquals(new Nonce("waeHieMa4dan"), response.getDPoPNonce());


		assertNull(response.getContent());

		try {
			response.getContentAsJSONObject();
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP Content-Type header must be application/json, received application/x-www-form-urlencoded", e.getMessage());
		}

		try {
			response.getContentAsJWT();
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP Content-Type header must be application/jwt, received application/x-www-form-urlencoded", e.getMessage());
		}

		response.setEntityContentType(ContentType.APPLICATION_JSON);
		response.setContent("{\"apples\":\"123\"}");
		assertEquals("{\"apples\":\"123\"}", response.getBody());

		JSONObject jsonObject = response.getContentAsJSONObject();
		assertEquals("123", (String)jsonObject.get("apples"));

		// From http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-13#section-3.1
		String exampleJWTString = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
			"." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
			"." +
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		response.setEntityContentType(ContentType.APPLICATION_JWT);
		response.setContent(exampleJWTString);

		JWT jwt = response.getContentAsJWT();
		assertEquals(JWSAlgorithm.HS256, jwt.getHeader().getAlgorithm());
	}


	public void testGetBodyAsFormParameters()
		throws Exception {

		HTTPResponse response = new HTTPResponse(200);
		response.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		response.setBody("apples=10&pears=20");

		Map<String, List<String>> params = response.getBodyAsFormParameters();
		assertEquals(Collections.singletonList("10"), params.get("apples"));
		assertEquals(Collections.singletonList("20"), params.get("pears"));
		assertEquals(2, params.size());
	}


	public void testGetBodyAsFormParameters_noBody()
		throws Exception {

		HTTPResponse response = new HTTPResponse(200);
		response.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		assertTrue(response.getBodyAsFormParameters().isEmpty());
	}


	public void testGetBodyAsFormParameters_emptyBody()
		throws Exception {

		HTTPResponse response = new HTTPResponse(200);
		response.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		response.setBody("");

		assertTrue(response.getBodyAsFormParameters().isEmpty());
	}


	public void testGetBodyAsFormParameters_blankBody()
		throws Exception {

		HTTPResponse response = new HTTPResponse(200);
		response.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		response.setBody(" ");

		assertTrue(response.getBodyAsFormParameters().isEmpty());
	}


	public void testGetBodyAsFormParameters_missingContentType() {

		HTTPResponse response = new HTTPResponse(200);

		try {
			response.getBodyAsFormParameters();
			fail();
		} catch (ParseException e) {
			assertEquals("Missing HTTP Content-Type header", e.getMessage());
		}
	}


	public void testGetBodyAsFormParameters_illegalContentType() {

		HTTPResponse response = new HTTPResponse(200);
		response.setEntityContentType(ContentType.APPLICATION_JWT);

		try {
			response.getBodyAsFormParameters();
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP Content-Type header must be application/x-www-form-urlencoded, received application/jwt", e.getMessage());
		}
	}


	public void testGetBodyAsJSONArray()
		throws Exception {

		HTTPResponse response = new HTTPResponse(200);
		response.setEntityContentType(ContentType.APPLICATION_JSON);
		response.setBody("[\"apples\",\"pears\"]");

		JSONArray array = response.getBodyAsJSONArray();
		assertEquals("apples", array.get(0));
		assertEquals("pears", array.get(1));
		assertEquals(2, array.size());
	}


	public void testGetContentAsJSONArray_deprecated()
		throws Exception {

		HTTPResponse response = new HTTPResponse(200);
		response.setEntityContentType(ContentType.APPLICATION_JSON);
		response.setContent("[\"apples\",\"pears\"]");

		JSONArray array = response.getContentAsJSONArray();
		assertEquals("apples", array.get(0));
		assertEquals("pears", array.get(1));
		assertEquals(2, array.size());
	}


	public void testPreserveHeaderCase() {
		HTTPResponse response = new HTTPResponse(302);
		response.setHeader("Location", "http://example.org");

		assertEquals("Location", response.getHeaderMap().keySet().iterator().next());
	}


	public void testGetHeaderWithCaseMismatch()
		throws URISyntaxException{

		HTTPResponse response = new HTTPResponse(302);
		response.setHeader("location", "http://example.org");

		assertEquals(new URI("http://example.org"), response.getLocation());
	}


	public void testRemoveHeaderWithCaseMismatch()
		throws URISyntaxException{

		HTTPResponse response = new HTTPResponse(302);
		response.setHeader("location", "http://example.org");

		assertEquals(new URI("http://example.org"), response.getLocation());

		response.setHeader("LOCATION", (String) null);

		assertNull(response.getLocation());
	}
	
	
	public void testClientIP() {
		
		HTTPResponse httpResponse = new HTTPResponse(200);
		
		assertNull(httpResponse.getClientIPAddress());
		
		String ip = "192.168.0.1";
		httpResponse.setClientIPAddress(ip);
		assertEquals(ip, httpResponse.getClientIPAddress());
	}
	
	
	public void testDPoPNonce_empty() {
		
		HTTPResponse httpResponse = new HTTPResponse(200);
		httpResponse.setHeader("DPoP-Nonce", "");
		
		assertNull(httpResponse.getDPoPNonce());
	}
}
