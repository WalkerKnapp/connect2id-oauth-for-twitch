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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.net.*;
import java.net.Proxy.Type;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;


public class HTTPRequestTest {

	private static final String LINE_SEPARATOR = System.getProperty("line.separator");

	@Test
	public void testDefaultHostnameVerifier() {

		assertEquals(HttpsURLConnection.getDefaultHostnameVerifier(), HTTPRequest.getDefaultHostnameVerifier());
	}


	@Test
	public void testDefaultSSLSocketFactory() {

		assertNotNull(HTTPRequest.getDefaultSSLSocketFactory());
	}


	@Test
	public void testConstructorPOSTAndAccessors()
		throws Exception {

		URL url = new URL("https://localhost/login");

		HTTPRequest request = new HTTPRequest(HTTPRequest.Method.POST, url);

		assertEquals(HTTPRequest.Method.POST, request.getMethod());
		assertEquals(url, request.getURL());
		assertEquals(url.toURI(), request.getURI());

		request.ensureMethod(HTTPRequest.Method.POST);

		try {
			request.ensureMethod(HTTPRequest.Method.GET);
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP request method must be GET", e.getMessage());
		}

		assertNull(request.getEntityContentType());
		request.setEntityContentType(ContentType.APPLICATION_JSON);
		assertEquals(ContentType.APPLICATION_JSON.toString(), request.getEntityContentType().toString());

		assertNull(request.getAuthorization());
		request.setAuthorization("Bearer 123");
		assertEquals("Bearer 123", request.getAuthorization());

		assertNull(request.getAccept());
		request.setAccept("text/plain");
		assertEquals("text/plain", request.getAccept());

		request.appendQueryString("x=123&y=456");
		assertEquals("x=123&y=456", request.getURL().getQuery());
		assertEquals("x=123&y=456", request.getURI().getQuery());

		Map<String,List<String>> params = request.getQueryStringParameters();
		assertEquals(Collections.singletonList("123"), params.get("x"));
		assertEquals(Collections.singletonList("456"), params.get("y"));

		request.setBody("{\"apples\":\"123\"}");
		JSONObject jsonObject = request.getBodyAsJSONObject();
		assertEquals("123", jsonObject.get("apples"));

		request.setFragment("fragment");
		assertEquals("fragment", request.getFragment());

		assertEquals(0, request.getConnectTimeout());
		request.setConnectTimeout(250);
		assertEquals(250, request.getConnectTimeout());

		assertEquals(0, request.getReadTimeout());
		request.setReadTimeout(750);
		assertEquals(750, request.getReadTimeout());

		assertTrue(request.getFollowRedirects());
		request.setFollowRedirects(false);
		assertFalse(request.getFollowRedirects());
	}


	@Test
	public void testConstructorPOSTAndAccessors_deprecated()
		throws Exception {

		URL url = new URL("https://localhost/login");

		HTTPRequest request = new HTTPRequest(HTTPRequest.Method.POST, url);

		assertEquals(HTTPRequest.Method.POST, request.getMethod());
		assertEquals(url, request.getURL());

		request.ensureMethod(HTTPRequest.Method.POST);

		try {
			request.ensureMethod(HTTPRequest.Method.GET);
			fail();
		} catch (ParseException e) {
			// ok
		}

		assertNull(request.getEntityContentType());
		request.setEntityContentType(ContentType.APPLICATION_JSON);
		assertEquals(ContentType.APPLICATION_JSON.toString(), request.getEntityContentType().toString());

		assertNull(request.getAuthorization());
		request.setAuthorization("Bearer 123");
		assertEquals("Bearer 123", request.getAuthorization());

		assertNull(request.getAccept());
		request.setAccept("text/plain");
		assertEquals("text/plain", request.getAccept());

		assertNull(request.getQuery());
		request.setQuery("x=123&y=456");
		assertEquals("x=123&y=456", request.getQuery());

		Map<String,List<String>> params = request.getQueryParameters();
		assertEquals(Collections.singletonList("123"), params.get("x"));
		assertEquals(Collections.singletonList("456"), params.get("y"));

		request.setQuery("{\"apples\":\"123\"}");
		JSONObject jsonObject = request.getQueryAsJSONObject();
		assertEquals("123", jsonObject.get("apples"));

		request.setFragment("fragment");
		assertEquals("fragment", request.getFragment());

		assertEquals(0, request.getConnectTimeout());
		request.setConnectTimeout(250);
		assertEquals(250, request.getConnectTimeout());

		assertEquals(0, request.getReadTimeout());
		request.setReadTimeout(750);
		assertEquals(750, request.getReadTimeout());

		assertTrue(request.getFollowRedirects());
		request.setFollowRedirects(false);
		assertFalse(request.getFollowRedirects());
	}


	@Test
	public void testConstructorGETAndAccessors_deprecated()
		throws Exception {

		URL url = new URL("https://localhost/login");

		HTTPRequest request = new HTTPRequest(HTTPRequest.Method.GET, url);

		assertEquals(HTTPRequest.Method.GET, request.getMethod());
		assertEquals(url, request.getURL());

		request.ensureMethod(HTTPRequest.Method.GET);

		try {
			request.ensureMethod(HTTPRequest.Method.POST);
			fail();
		} catch (ParseException e) {
			// ok
		}

		assertNull(request.getAuthorization());
		request.setAuthorization("Bearer 123");
		assertEquals("Bearer 123", request.getAuthorization());

		assertNull(request.getAccept());
		request.setAccept("text/plain");
		assertEquals("text/plain", request.getAccept());

		assertNull(request.getQuery());
		request.setQuery("x=123&y=456");
		assertEquals("x=123&y=456", request.getQuery());

		Map<String,List<String>> params = request.getQueryParameters();
		assertEquals(Collections.singletonList("123"), params.get("x"));
		assertEquals(Collections.singletonList("456"), params.get("y"));

		request.setFragment("fragment");
		assertEquals("fragment", request.getFragment());

		assertEquals(0, request.getConnectTimeout());
		request.setConnectTimeout(250);
		assertEquals(250, request.getConnectTimeout());

		assertEquals(0, request.getReadTimeout());
		request.setReadTimeout(750);
		assertEquals(750, request.getReadTimeout());

		assertTrue(request.getFollowRedirects());
		request.setFollowRedirects(false);
		assertFalse(request.getFollowRedirects());
	}


	@Test
	public void testWithQueryStringAndBody()
		throws MalformedURLException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://localhost/token"));
		String queryString = "q-param-1=a&q-param-2=b";
		httpRequest.appendQueryString(queryString);
		String body = "f-param-3=d&f-param-4=e";
		httpRequest.setBody(body);

		assertEquals(queryString, httpRequest.getURL().getQuery());
		assertEquals(queryString, httpRequest.getURI().getQuery());
		assertEquals(body, httpRequest.getBody());
	}


	@Test
	public void testAppendQueryParameters()
		throws MalformedURLException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost/login"));

		Map<String, List<String>> params = new LinkedHashMap<>();
		params.put("client_id", Collections.singletonList("123"));
		params.put("redirect_uri", Collections.singletonList("https://example.com/cb"));
		params.put("x-param", Arrays.asList("one", "two"));

		httpRequest.appendQueryParameters(params);

		assertEquals(
			"http://localhost/login?client_id=123&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&x-param=one&x-param=two",
			httpRequest.getURL().toString()
		);
	}


	@Test
	public void testAppendQueryParameters_toExistingQuery()
		throws MalformedURLException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost/login?tenant=abc"));

		Map<String, List<String>> params = new LinkedHashMap<>();
		params.put("client_id", Collections.singletonList("123"));
		params.put("redirect_uri", Collections.singletonList("https://example.com/cb"));
		params.put("x-param", Arrays.asList("one", "two"));

		httpRequest.appendQueryParameters(params);

		assertEquals(
			"http://localhost/login?tenant=abc&client_id=123&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&x-param=one&x-param=two",
			httpRequest.getURL().toString()
		);
	}


	@Test
	public void testAppendQueryParameters_null()
		throws MalformedURLException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost/login?tenant=abc"));

		httpRequest.appendQueryParameters(null);

		assertEquals(
			"http://localhost/login?tenant=abc",
			httpRequest.getURL().toString()
		);
	}


	@Test
	public void testAppendQueryParameters_empty()
		throws MalformedURLException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost/login?tenant=abc"));

		Map<String, List<String>> params = Collections.emptyMap();

		httpRequest.appendQueryParameters(params);

		assertEquals(
			"http://localhost/login?tenant=abc",
			httpRequest.getURL().toString()
		);
	}


	@Test
	public void testAppendQueryString()
		throws MalformedURLException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost/login"));
		httpRequest.appendQueryString("apples=10&some%20pears=20");
		assertEquals("http://localhost/login?apples=10&some%20pears=20", httpRequest.getURL().toString());
	}


	@Test
	public void testAppendQueryString_toExistingQuery()
		throws MalformedURLException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost/login?oranges=0"));
		httpRequest.appendQueryString("apples=10&some%20pears=20");
		assertEquals("http://localhost/login?oranges=0&apples=10&some%20pears=20", httpRequest.getURL().toString());
	}


	@Test
	public void testAppendQueryString_null()
		throws MalformedURLException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost/login"));
		httpRequest.appendQueryString(null);
		assertEquals("http://localhost/login", httpRequest.getURL().toString());
	}


	@Test
	public void testAppendQueryString_empty()
		throws MalformedURLException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost/login"));
		httpRequest.appendQueryString("");
		assertEquals("http://localhost/login", httpRequest.getURL().toString());
	}


	@Test
	public void testAppendQueryString_blank()
		throws MalformedURLException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost/login"));
		httpRequest.appendQueryString(" ");
		assertEquals("http://localhost/login", httpRequest.getURL().toString());
	}


	@Test
	public void testAppendQueryString_startsWithQuestionMark()
		throws MalformedURLException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://localhost/token"));

		try {
			httpRequest.appendQueryString("?a=1&b=2");
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The query string must not start with ?", e.getMessage());
		}
	}


	@Test
	public void testParseJSONObject()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost"));

		httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);

		httpRequest.setBody("{\"apples\":30, \"pears\":\"green\"}");

		JSONObject jsonObject = httpRequest.getBodyAsJSONObject();

		assertEquals(30, JSONObjectUtils.getInt(jsonObject, "apples"));
		assertEquals("green", JSONObjectUtils.getString(jsonObject, "pears"));
		assertEquals(2, jsonObject.size());
	}


	@Test
	public void testParseJSONObject_subTypeSuffix()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost"));

		httpRequest.setEntityContentType(ContentType.parse("application/fruit+json"));

		httpRequest.setBody("{\"apples\":30, \"pears\":\"green\"}");

		JSONObject jsonObject = httpRequest.getBodyAsJSONObject();

		assertEquals(30, JSONObjectUtils.getInt(jsonObject, "apples"));
		assertEquals("green", JSONObjectUtils.getString(jsonObject, "pears"));
		assertEquals(2, jsonObject.size());
	}


	@Test
	public void testParseJSONObject_deprecated()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost"));

		httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);

		httpRequest.setQuery("{\"apples\":30, \"pears\":\"green\"}");

		JSONObject jsonObject = httpRequest.getQueryAsJSONObject();

		assertEquals(30, JSONObjectUtils.getInt(jsonObject, "apples"));
		assertEquals("green", JSONObjectUtils.getString(jsonObject, "pears"));
		assertEquals(2, jsonObject.size());
	}


	@Test
	public void testParseJSONObjectException()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost"));

		httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);

		httpRequest.setBody(" ");

		try {
			httpRequest.getBodyAsJSONObject();
			fail();
		} catch (ParseException e) {
			// ok
			assertEquals("Invalid JSON: Unexpected token  at position 1.", e.getMessage());
		}
	}


	@Test
	public void testParseJSONObjectException_deprecated()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost"));

		httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);

		httpRequest.setQuery(" ");

		try {
			httpRequest.getQueryAsJSONObject();
			fail();
		} catch (ParseException e) {
			// ok
			assertEquals("Missing or empty HTTP query string / entity body", e.getMessage());
		}
	}


	@Test
	public void testSendWithHTTPRequestSenderInterface_minimal()
		throws IOException {

		final HTTPRequest.Method method = HTTPRequest.Method.GET;
		final URL url = new URL("http://localhost:8080/path?query");

		HTTPRequest httpRequest = new HTTPRequest(method, url);

		HTTPResponse httpResponse = httpRequest.send(new HTTPRequestSender() {
			@Override
			public ReadOnlyHTTPResponse send(ReadOnlyHTTPRequest httpRequest) {

				assertEquals(method, httpRequest.getMethod());
				assertEquals(url, httpRequest.getURL());
				assertTrue(httpRequest.getHeaderMap().isEmpty());
				assertNull(httpRequest.getBody());
				return new HTTPResponse(204);
			}
		});

		assertEquals(204, httpResponse.getStatusCode());
		assertNull(httpResponse.getStatusMessage());
		assertTrue(httpResponse.getHeaderMap().isEmpty());
		assertNull(httpResponse.getBody());
	}


	@Test
	public void testSendWithHTTPRequestSenderInterface_allSet()
		throws IOException {

		final HTTPRequest.Method method = HTTPRequest.Method.POST;
		final URL url = new URL("http://localhost:8080/path?query");
		final ContentType contentType = ContentType.APPLICATION_JSON;
		final String authoriztion = new BearerAccessToken().toAuthorizationHeader();
		final String body = "{'\"apples\":10}";

		HTTPRequest httpRequest = new HTTPRequest(method, url);
		httpRequest.setEntityContentType(contentType);
		httpRequest.setAuthorization(authoriztion);
		httpRequest.setBody(body);

		HTTPResponse httpResponse = httpRequest.send(new HTTPRequestSender() {
			@Override
			public ReadOnlyHTTPResponse send(ReadOnlyHTTPRequest httpRequest) {

				assertEquals(method, httpRequest.getMethod());
				assertEquals(url, httpRequest.getURL());
				assertEquals(Collections.singletonList(contentType.toString()), httpRequest.getHeaderMap().get("Content-Type"));
				assertEquals(Collections.singletonList(authoriztion), httpRequest.getHeaderMap().get("Authorization"));
				assertEquals(2, httpRequest.getHeaderMap().size());
				assertEquals(body, httpRequest.getBody());

				HTTPResponse out = new HTTPResponse(204);
				out.setStatusMessage("No Content");
				out.setEntityContentType(contentType);
				out.setHeader("X-Header", "Value-1", "Value-2");
				out.setBody("[1]");
				return out;
			}
		});

		assertEquals(204, httpResponse.getStatusCode());
		assertEquals("No Content", httpResponse.getStatusMessage());
		assertEquals(Collections.singletonList(contentType.toString()), httpResponse.getHeaderMap().get("Content-Type"));
		assertEquals(Arrays.asList("Value-1", "Value-2"), httpResponse.getHeaderMap().get("X-Header"));
		assertEquals(2, httpResponse.getHeaderMap().size());
		assertEquals("[1]", httpResponse.getBody());
	}


	@Before
	public void setUp() {
		initJadler();
	}


	@After
	public void tearDown() {
		closeJadler();
	}


	@Test
	public void test401Response()
		throws Exception {

		onRequest()
			.havingMethodEqualTo("POST")
			.havingHeaderEqualTo("Authorization", "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW")
			.havingHeaderEqualTo("Content-Type", ContentType.APPLICATION_URLENCODED.toString())
			.havingPathEqualTo("/c2id/token")
			.havingBodyEqualTo("grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA" +
				"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb")
			.respond()
			.withStatus(401)
			.withHeader("WWW-Authenticate", "Bearer");

		// Simulate token request with invalid token
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost:" + port() + "/c2id/token"));
		httpRequest.setAuthorization("Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW");
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb");

		HTTPResponse httpResponse = httpRequest.send();
		assertEquals(401, httpResponse.getStatusCode());
		assertEquals("Unauthorized", httpResponse.getStatusMessage());
		assertEquals("Bearer", httpResponse.getWWWAuthenticate());
	}


	@Test
	public void test401Response_deprecated()
		throws Exception {

		onRequest()
			.havingMethodEqualTo("POST")
			.havingHeaderEqualTo("Authorization", "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW")
			.havingHeaderEqualTo("Content-Type", ContentType.APPLICATION_URLENCODED.toString())
			.havingPathEqualTo("/c2id/token")
			.havingBodyEqualTo("grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA" +
				"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb")
			.respond()
			.withStatus(401)
			.withHeader("WWW-Authenticate", "Bearer");

		// Simulate token request with invalid token
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost:" + port() + "/c2id/token"));
		httpRequest.setAuthorization("Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW");
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setQuery("grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb");

		HTTPResponse httpResponse = httpRequest.send();
		assertEquals(401, httpResponse.getStatusCode());
		assertEquals("Unauthorized", httpResponse.getStatusMessage());
		assertEquals("Bearer", httpResponse.getWWWAuthenticate());
	}


	@Test
	public void test404Response()
		throws Exception {

		onRequest()
			.respond()
			.withStatus(404);

		// Simulate token request with invalid token
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost:" + port() + "/c2id/.well-known/openid"));

		HTTPResponse httpResponse = httpRequest.send();
		assertEquals(404, httpResponse.getStatusCode());
		assertEquals("Not Found", httpResponse.getStatusMessage());
	}


	@Test
	public void test405Response()
		throws Exception {

		onRequest()
			.respond()
			.withStatus(405);

		// Simulate token request with invalid token
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost:" + port() + "/c2id/.well-known/openid"));

		HTTPResponse httpResponse = httpRequest.send();
		assertEquals(405, httpResponse.getStatusCode());
		assertEquals("Method Not Allowed", httpResponse.getStatusMessage());
	}


	@Test
	public void testToHttpURLConnection()
		throws Exception {

		// Simulate token request with invalid token
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost:" + port() + "/c2id/token"));
		httpRequest.setAuthorization("Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW");
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setConnectTimeout(250);
		httpRequest.setReadTimeout(750);
		httpRequest.setBody("grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb");

		HttpURLConnection con = httpRequest.toHttpURLConnection();
		assertEquals("POST", con.getRequestMethod());
		assertEquals(250, con.getConnectTimeout());
		assertEquals(750, con.getReadTimeout());
		assertTrue(con.getInstanceFollowRedirects());
	}


	@Test
	public void testToHttpURLConnection_deprecated()
		throws Exception {

		// Simulate token request with invalid token
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost:" + port() + "/c2id/token"));
		httpRequest.setAuthorization("Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW");
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setConnectTimeout(250);
		httpRequest.setReadTimeout(750);
		httpRequest.setQuery("grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb");

		HttpURLConnection con = httpRequest.toHttpURLConnection();
		assertEquals("POST", con.getRequestMethod());
		assertEquals(250, con.getConnectTimeout());
		assertEquals(750, con.getReadTimeout());
		assertTrue(con.getInstanceFollowRedirects());
	}


	@Test
	public void testToHttpURLConnectionAlt()
		throws Exception {

		// Simulate token request with invalid token
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost:" + port() + "/c2id/token"));
		httpRequest.setAuthorization("Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW");
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setConnectTimeout(250);
		httpRequest.setReadTimeout(750);
		httpRequest.setFollowRedirects(false);
		httpRequest.setBody("grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb");

		HttpURLConnection con = httpRequest.toHttpURLConnection();
		assertEquals("POST", con.getRequestMethod());
		assertEquals(250, con.getConnectTimeout());
		assertEquals(750, con.getReadTimeout());
		assertFalse(con.getInstanceFollowRedirects());
	}


	@Test
	public void testSend_GET()
		throws Exception {

		onRequest()
			.havingMethodEqualTo("GET")
			.havingHeaderEqualTo("Authorization", "Bearer xyz")
			.havingHeaderEqualTo("Accept", ContentType.APPLICATION_JSON.toString())
			.havingPathEqualTo("/path")
			.havingQueryStringEqualTo("apples=10&pears=20")
			.respond()
			.withStatus(200)
			.withBody("[10, 20]")
			.withEncoding(StandardCharsets.UTF_8)
			.withContentType(ContentType.APPLICATION_JSON.toString());

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost:" + port() + "/path"));
		httpRequest.appendQueryString("apples=10&pears=20");
		httpRequest.setFragment("fragment");
		httpRequest.setAuthorization("Bearer xyz");
		httpRequest.setAccept(ContentType.APPLICATION_JSON.toString());

		HTTPResponse httpResponse = httpRequest.send();

		assertEquals(200, httpResponse.getStatusCode());
		assertEquals("OK", httpResponse.getStatusMessage());
		httpResponse.ensureEntityContentType(ContentType.APPLICATION_JSON);

		JSONArray jsonArray = httpResponse.getBodyAsJSONArray();
		assertEquals(10L, jsonArray.get(0));
		assertEquals(20L, jsonArray.get(1));
		assertEquals(2, jsonArray.size());
	}


	@Test
	public void testSend_GET_deprecated()
		throws Exception {

		onRequest()
			.havingMethodEqualTo("GET")
			.havingHeaderEqualTo("Authorization", "Bearer xyz")
			.havingHeaderEqualTo("Accept", ContentType.APPLICATION_JSON.toString())
			.havingPathEqualTo("/path")
			.havingQueryStringEqualTo("apples=10&pears=20")
			.respond()
			.withStatus(200)
			.withBody("[10, 20]")
			.withEncoding(StandardCharsets.UTF_8)
			.withContentType(ContentType.APPLICATION_JSON.toString());

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost:" + port() + "/path"));
		httpRequest.setQuery("apples=10&pears=20");
		httpRequest.setFragment("fragment");
		httpRequest.setAuthorization("Bearer xyz");
		httpRequest.setAccept(ContentType.APPLICATION_JSON.toString());

		HTTPResponse httpResponse = httpRequest.send();

		assertEquals(200, httpResponse.getStatusCode());
		assertEquals("OK", httpResponse.getStatusMessage());
		httpResponse.ensureEntityContentType(ContentType.APPLICATION_JSON);

		JSONArray jsonArray = httpResponse.getContentAsJSONArray();
		assertEquals(10L, jsonArray.get(0));
		assertEquals(20L, jsonArray.get(1));
		assertEquals(2, jsonArray.size());
	}


	@Test
	public void testSend_POST()
		throws Exception {

		onRequest()
			.havingMethodEqualTo("POST")
			.havingHeaderEqualTo("Authorization", "Bearer xyz")
			.havingHeaderEqualTo("Accept", ContentType.APPLICATION_JSON.toString())
			.havingPathEqualTo("/path")
			.havingQueryStringEqualTo(null)
			.respond()
			.withStatus(200)
			.withBody("[10, 20]")
			.withEncoding(StandardCharsets.UTF_8)
			.withContentType(ContentType.APPLICATION_JSON.toString());

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost:" + port() + "/path"));
		httpRequest.setFragment("fragment");
		httpRequest.setAuthorization("Bearer xyz");
		httpRequest.setAccept(ContentType.APPLICATION_JSON.toString());
		httpRequest.setBody("[10, 20]");

		HTTPResponse httpResponse = httpRequest.send();

		assertEquals(200, httpResponse.getStatusCode());
		assertEquals("OK", httpResponse.getStatusMessage());
		httpResponse.ensureEntityContentType(ContentType.APPLICATION_JSON);

		JSONArray jsonArray = httpResponse.getBodyAsJSONArray();
		assertEquals(10L, jsonArray.get(0));
		assertEquals(20L, jsonArray.get(1));
		assertEquals(2, jsonArray.size());
	}


	@Test
	public void testSend_POST_withQueryString()
		throws Exception {

		onRequest()
			.havingMethodEqualTo("POST")
			.havingHeaderEqualTo("Authorization", "Bearer xyz")
			.havingHeaderEqualTo("Accept", ContentType.APPLICATION_JSON.toString())
			.havingPathEqualTo("/path")
			.havingQueryStringEqualTo("apples=10&pears=20")
			.respond()
			.withStatus(200)
			.withBody("[10, 20]")
			.withEncoding(StandardCharsets.UTF_8)
			.withContentType(ContentType.APPLICATION_JSON.toString());

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost:" + port() + "/path"));
		httpRequest.appendQueryString("apples=10&pears=20");
		httpRequest.setFragment("fragment");
		httpRequest.setAuthorization("Bearer xyz");
		httpRequest.setAccept(ContentType.APPLICATION_JSON.toString());
		httpRequest.setBody("[10, 20]");

		HTTPResponse httpResponse = httpRequest.send();

		assertEquals(200, httpResponse.getStatusCode());
		assertEquals("OK", httpResponse.getStatusMessage());
		httpResponse.ensureEntityContentType(ContentType.APPLICATION_JSON);

		JSONArray jsonArray = httpResponse.getBodyAsJSONArray();
		assertEquals(10L, jsonArray.get(0));
		assertEquals(20L, jsonArray.get(1));
		assertEquals(2, jsonArray.size());
	}


	@Test
	public void testSend_POST_appendQueryString()
		throws Exception {

		onRequest()
			.havingMethodEqualTo("POST")
			.havingHeaderEqualTo("Authorization", "Bearer xyz")
			.havingHeaderEqualTo("Accept", ContentType.APPLICATION_JSON.toString())
			.havingPathEqualTo("/path")
			.havingQueryStringEqualTo("oranges=0&apples=10&pears=20")
			.respond()
			.withStatus(200)
			.withBody("[10, 20]")
			.withEncoding(StandardCharsets.UTF_8)
			.withContentType(ContentType.APPLICATION_JSON.toString());

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost:" + port() + "/path?oranges=0"));
		httpRequest.appendQueryString("apples=10&pears=20");
		httpRequest.setFragment("fragment");
		httpRequest.setAuthorization("Bearer xyz");
		httpRequest.setAccept(ContentType.APPLICATION_JSON.toString());
		httpRequest.setBody("[10, 20]");

		HTTPResponse httpResponse = httpRequest.send();

		assertEquals(200, httpResponse.getStatusCode());
		assertEquals("OK", httpResponse.getStatusMessage());
		httpResponse.ensureEntityContentType(ContentType.APPLICATION_JSON);

		JSONArray jsonArray = httpResponse.getBodyAsJSONArray();
		assertEquals(10L, jsonArray.get(0));
		assertEquals(20L, jsonArray.get(1));
		assertEquals(2, jsonArray.size());
	}


	@Test
	public void testWithOtherResponseHeaders()
		throws Exception {

		onRequest()
			.havingMethodEqualTo("GET")
			.havingHeaderEqualTo("Authorization", "Bearer xyz")
			.havingHeaderEqualTo("Accept", ContentType.APPLICATION_JSON.toString())
			.havingPathEqualTo("/path")
			.havingQueryStringEqualTo("apples=10&pears=20")
			.respond()
			.withStatus(200)
			.withHeader("SID", "abc")
			.withHeader("X-App", "123")
			.withBody("[10, 20]")
			.withEncoding(StandardCharsets.UTF_8)
			.withContentType(ContentType.APPLICATION_JSON.toString());

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost:" + port() + "/path"));
		httpRequest.appendQueryString("apples=10&pears=20");
		httpRequest.setFragment("fragment");
		httpRequest.setAuthorization("Bearer xyz");
		httpRequest.setAccept(ContentType.APPLICATION_JSON.toString());

		HTTPResponse httpResponse = httpRequest.send();

		assertEquals(200, httpResponse.getStatusCode());
		assertEquals("OK", httpResponse.getStatusMessage());
		httpResponse.ensureEntityContentType(ContentType.APPLICATION_JSON);
		assertEquals("abc", httpResponse.getHeaderValue("SID"));
		assertEquals("123", httpResponse.getHeaderValue("X-App"));

		JSONArray jsonArray = httpResponse.getBodyAsJSONArray();
		assertEquals(10L, jsonArray.get(0));
		assertEquals(20L, jsonArray.get(1));
		assertEquals(2, jsonArray.size());
	}


	@Test
	public void testSendMultiValuedHeader()
		throws Exception {

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/path")
			.respond()
			.withStatus(200)
			.withHeader("Set-Cookie", "cookie-1")
			.withHeader("Set-Cookie", "cookie-2")
			.withBody("Hello, world!")
			.withEncoding(StandardCharsets.UTF_8)
			.withContentType("text/plain");

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost:" + port() + "/path"));

		HTTPResponse httpResponse = httpRequest.send();

		assertEquals(200, httpResponse.getStatusCode());
		assertEquals("OK", httpResponse.getStatusMessage());
		assertEquals(new HashSet<>(Arrays.asList("cookie-1", "cookie-2")), new HashSet<>(httpResponse.getHeaderValues("Set-Cookie")));
		httpResponse.ensureEntityContentType(new ContentType("text", "plain"));
		assertEquals("Hello, world!" + LINE_SEPARATOR, httpResponse.getBody());
	}


	@Test
	public void testSendMultiValuedHeader_deprecated()
		throws Exception {

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/path")
			.respond()
			.withStatus(200)
			.withHeader("Set-Cookie", "cookie-1")
			.withHeader("Set-Cookie", "cookie-2")
			.withBody("Hello, world!")
			.withEncoding(StandardCharsets.UTF_8)
			.withContentType("text/plain");

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost:" + port() + "/path"));

		HTTPResponse httpResponse = httpRequest.send();

		assertEquals(200, httpResponse.getStatusCode());
		assertEquals("OK", httpResponse.getStatusMessage());
		assertEquals(new HashSet<>(Arrays.asList("cookie-1", "cookie-2")), new HashSet<>(httpResponse.getHeaderValues("Set-Cookie")));
		httpResponse.ensureEntityContentType(new ContentType("text", "plain"));
		assertEquals("Hello, world!" + LINE_SEPARATOR, httpResponse.getContent());
	}


	@Test
	public void testWithClientCertificate()
		throws Exception {

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();

		X509Certificate cert = X509CertificateGenerator.generateSelfSignedCertificate(
			new Issuer("123"),
			rsaPublicKey,
			rsaPrivateKey);

		cert.checkValidity();

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));

		assertNull(httpRequest.getClientX509Certificate());

		httpRequest.setClientX509Certificate(cert);

		assertEquals(cert, httpRequest.getClientX509Certificate());
	}


	@Test
	public void testGetAndSetDefaultHostnameVerifier() {

		HostnameVerifier mockHostnameVerifier = new HostnameVerifier() {
			@Override
			public boolean verify(String s, SSLSession sslSession) {
				return false;
			}
		};

		HostnameVerifier defaultHostnameVerifier = HTTPRequest.getDefaultHostnameVerifier();

		assertNotNull(defaultHostnameVerifier);

		HTTPRequest.setDefaultHostnameVerifier(mockHostnameVerifier);

		assertEquals(mockHostnameVerifier, HTTPRequest.getDefaultHostnameVerifier());
	}


	@Test
	public void testRejectNullDefaultHostnameVerifier() {

		try {
			HTTPRequest.setDefaultHostnameVerifier(null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The hostname verifier must not be null", e.getMessage());
		}
	}


	@Test
	public void testRejectNullDefaultSSLSocketFactory() {

		try {
			HTTPRequest.setDefaultSSLSocketFactory(null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The SSL socket factory must not be null", e.getMessage());
		}
	}


	@Test
	public void testGetAndSetSubjectDN()
		throws MalformedURLException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));

		assertNull(httpRequest.getClientX509CertificateSubjectDN());
		httpRequest.setClientX509CertificateSubjectDN("cn=subject");
		assertEquals("cn=subject", httpRequest.getClientX509CertificateSubjectDN());
	}


	@Test
	public void testGetAndSetRootDN()
		throws MalformedURLException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));

		assertNull(httpRequest.getClientX509CertificateRootDN());
		httpRequest.setClientX509CertificateRootDN("cn=root");
		assertEquals("cn=root", httpRequest.getClientX509CertificateRootDN());
	}


	@Test
	public void testClientIP()
		throws MalformedURLException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));

		assertNull(httpRequest.getClientIPAddress());

		String ip = "192.168.0.1";
		httpRequest.setClientIPAddress(ip);
		assertEquals(ip, httpRequest.getClientIPAddress());
	}
	
	
	@Test
	public void testMultivaluedHeader()
		throws MalformedURLException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		
		List<String> headerValues = Arrays.asList("V1", "V2");
		
		httpRequest.setHeader("X-Header", "V1", "V2");
		
		assertEquals(headerValues, httpRequest.getHeaderValues("X-Header"));
		
		assertEquals("V1", httpRequest.getHeaderValue("X-Header"));
	}
	

	@Test
	public void testProxy() throws IOException {
		onRequest()
				.havingMethodEqualTo("POST")
				.havingHeaderEqualTo("Host", "localhost:0")
				.respond()
				.withStatus(999);

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost:0/c2id/token"));

		assertNull(httpRequest.getProxy());

		// Set proxy to use on this request
		Proxy proxy = new Proxy(Type.HTTP, new InetSocketAddress("localhost", port()));
		httpRequest.setProxy(proxy);

		assertEquals(proxy, httpRequest.getProxy());

		HTTPResponse httpResponse = httpRequest.send();
		assertEquals(999, httpResponse.getStatusCode());
	}


	@Test
	public void testNoProxy() throws IOException{
		onRequest()
				.havingMethodEqualTo("POST")
				.havingHeaderEqualTo("Host","localhost:" + port())
				.respond()
				.withStatus(999);

		//No proxy set, default should be to not use a proxy (if none was set either via System properties or ProxySelector)
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost:" + port() + "/c2id/token"));

		HTTPResponse httpResponse = httpRequest.send();
		assertEquals(999, httpResponse.getStatusCode());
	}


	@Test
	public void testDPoP() throws MalformedURLException, JOSEException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));

		assertNull(httpRequest.getDPoP());

		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.generate();

		SignedJWT dPoP = new DefaultDPoPProofFactory(rsaJWK, JWSAlgorithm.RS256)
			.createDPoPJWT(httpRequest.getMethod().name(), httpRequest.getURI());

		httpRequest.setDPoP(dPoP);

		assertEquals(dPoP.serialize(), httpRequest.getHeaderValue("DPoP"));

		assertEquals(dPoP.serialize(), httpRequest.getDPoP().serialize());
	}
	
	
	@Test
	public void testDPoP_illegal() throws MalformedURLException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		
		httpRequest.setHeader("DPoP", "illegal-jwt");
		
		assertNull(httpRequest.getDPoP());
		
		try {
			httpRequest.getPoPWithException();
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid serialized unsecured/JWS/JWE object: Missing part delimiters", e.getMessage());
			java.text.ParseException cause = (java.text.ParseException) e.getCause();
			assertEquals("Invalid serialized unsecured/JWS/JWE object: Missing part delimiters", cause.getMessage());
		}
	}
	
	
	@Test
	public void testDPoP_setNull() throws MalformedURLException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setDPoP(null);
		assertNull(httpRequest.getDPoP());
	}


	@Test
	public void testURLWithFragment()
		throws MalformedURLException {

		String urlString = "http://localhost:8080/path/abc?query#fragment";
		URL url = new URL(urlString);

		assertEquals(urlString, url.toString());

		assertEquals("http", url.getProtocol());
		assertEquals("localhost:8080", url.getAuthority());
		assertEquals("/path/abc", url.getPath());
		assertEquals("query", url.getQuery());
		assertEquals("fragment", url.getRef());
	}

	@Test
	public void testSend_POST_debug_closeStreamsExceptions()
		throws Exception {

		onRequest()
			.havingMethodEqualTo("POST")
			.havingHeaderEqualTo("Authorization", "Bearer xyz")
			.havingHeaderEqualTo("Accept", ContentType.APPLICATION_JSON.toString())
			.havingPathEqualTo("/path")
			.havingQueryStringEqualTo(null)
			.respond()
			.withStatus(200)
			.withBody("[10, 20]")
			.withEncoding(StandardCharsets.UTF_8)
			.withContentType(ContentType.APPLICATION_JSON.toString());

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost:" + port() + "/path"));
		httpRequest.setFragment("fragment");
		httpRequest.setAuthorization("Bearer xyz");
		httpRequest.setAccept(ContentType.APPLICATION_JSON.toString());
		httpRequest.setBody("[10, 20]");
		httpRequest.setDebugCloseStreams(true);

		HTTPResponse httpResponse = httpRequest.send();

		assertEquals(200, httpResponse.getStatusCode());
		assertEquals("OK", httpResponse.getStatusMessage());
		httpResponse.ensureEntityContentType(ContentType.APPLICATION_JSON);

		JSONArray jsonArray = httpResponse.getBodyAsJSONArray();
		assertEquals(10L, jsonArray.get(0));
		assertEquals(20L, jsonArray.get(1));
		assertEquals(2, jsonArray.size());
	}
}
