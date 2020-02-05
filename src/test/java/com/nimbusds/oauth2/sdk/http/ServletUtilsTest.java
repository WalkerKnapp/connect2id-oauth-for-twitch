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


import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.X509CertificateUtilsTest;


/**
 * Tests the HTTP to / from servet request / response.
 */
public class ServletUtilsTest extends TestCase {


	public void testConstructFromServletRequestWithJSONEntityBody()
		throws Exception {

		MockServletRequest servletRequest = new MockServletRequest();
		servletRequest.setMethod("POST");
		servletRequest.setHeader("Content-Type", ContentType.APPLICATION_JSON.toString());
		servletRequest.setHeader("Accept", ContentType.APPLICATION_JSON.toString());
		servletRequest.setHeader("Authorization", "Bearer yoto9reech8AhP2eibieg1uix2ahg5Ve");
		servletRequest.setLocalAddr("c2id.com");
		servletRequest.setLocalPort(8080);
		servletRequest.setRequestURI("/clients");
		servletRequest.setQueryString(null);
		String entityBody = "{\"grant_types\":[\"code\"]}";
		servletRequest.setEntityBody(entityBody);

		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_JSON.toString(), httpRequest.getEntityContentType().toString());
		assertEquals(ContentType.APPLICATION_JSON.toString(), httpRequest.getAccept());
		assertEquals("Bearer yoto9reech8AhP2eibieg1uix2ahg5Ve", httpRequest.getAuthorization());
		assertNull(httpRequest.getClientIPAddress());
		assertEquals(entityBody, httpRequest.getQuery());
		JSONObject jsonObject = httpRequest.getQueryAsJSONObject();
		assertEquals("code", JSONObjectUtils.getStringArray(jsonObject, "grant_types")[0]);
		assertEquals(1, jsonObject.size());
	}


	public void testConstructFromServletRequestWithMultiValuedHeader()
		throws Exception {

		MockServletRequest servletRequest = new MockServletRequest();
		servletRequest.setMethod("POST");
		servletRequest.setHeader("Content-Type", ContentType.APPLICATION_JSON.toString());
		servletRequest.setHeader("Multivalued-Header", "A", "B", "C");
		servletRequest.setLocalAddr("c2id.com");
		servletRequest.setLocalPort(8080);
		servletRequest.setRequestURI("/clients");
		servletRequest.setQueryString(null);
		String entityBody = "{\"grant_types\":[\"code\"]}";
		servletRequest.setEntityBody(entityBody);

		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_JSON.toString(), httpRequest.getEntityContentType().toString());
		assertNull(httpRequest.getAccept());
		assertNull(httpRequest.getAuthorization());
		assertNull(httpRequest.getClientIPAddress());
		assertEquals(Arrays.asList("A", "B", "C"), httpRequest.getHeaderValues("Multivalued-Header"));
		assertEquals(entityBody, httpRequest.getQuery());
		JSONObject jsonObject = httpRequest.getQueryAsJSONObject();
		assertEquals("code", JSONObjectUtils.getStringArray(jsonObject, "grant_types")[0]);
		assertEquals(1, jsonObject.size());
	}

	
	public void testConstructFromServletRequestWithClientIPAddress()
		throws Exception {

		MockServletRequest servletRequest = new MockServletRequest();
		servletRequest.setMethod("GET");
		servletRequest.setLocalAddr("c2id.com");
		servletRequest.setLocalPort(8080);
		servletRequest.setRequestURI("/");
		servletRequest.setQueryString(null);
		servletRequest.setRemoteAddr("192.168.0.1");

		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertNull(httpRequest.getEntityContentType());
		assertNull(httpRequest.getAccept());
		assertNull(httpRequest.getAuthorization());
		assertNull(httpRequest.getQuery());
		assertEquals("192.168.0.1", httpRequest.getClientIPAddress());
	}


	public void testConstructWithSelfSignedClientCertificate()
		throws Exception {

		X509Certificate cert = X509CertificateGenerator.generateSampleClientCertificate();
		
		MockServletRequest servletRequest = new MockServletRequest();
		servletRequest.setMethod("POST");
		servletRequest.setHeader("Content-Type", ContentType.APPLICATION_JSON.toString());
		servletRequest.setLocalAddr("c2id.com");
		servletRequest.setLocalPort(8080);
		servletRequest.setRequestURI("/clients");
		servletRequest.setQueryString(null);
		String entityBody = "{\"grant_types\":[\"code\"]}";
		servletRequest.setEntityBody(entityBody);
		servletRequest.setAttribute("javax.servlet.request.X509Certificate", new X509Certificate[]{cert});
		

		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_JSON.toString(), httpRequest.getEntityContentType().toString());
		assertNull(httpRequest.getAccept());
		assertNull(httpRequest.getAuthorization());
		assertEquals(entityBody, httpRequest.getQuery());
		JSONObject jsonObject = httpRequest.getQueryAsJSONObject();
		assertEquals("code", JSONObjectUtils.getStringArray(jsonObject, "grant_types")[0]);
		assertEquals(1, jsonObject.size());
		assertEquals(cert, httpRequest.getClientX509Certificate());
		assertEquals("CN=123", httpRequest.getClientX509CertificateSubjectDN());
		assertEquals("CN=123", httpRequest.getClientX509CertificateRootDN());
	}


	public void testConstructWithClientCertificate()
		throws Exception {

		X509Certificate cert = X509CertificateGenerator.generateCertificate(
			new Issuer("123"),
			new Subject("456"),
			X509CertificateUtilsTest.PUBLIC_KEY,
			X509CertificateUtilsTest.PRIVATE_KEY
		);
		
		MockServletRequest servletRequest = new MockServletRequest();
		servletRequest.setMethod("POST");
		servletRequest.setHeader("Content-Type", ContentType.APPLICATION_JSON.toString());
		servletRequest.setLocalAddr("c2id.com");
		servletRequest.setLocalPort(8080);
		servletRequest.setRequestURI("/clients");
		servletRequest.setQueryString(null);
		String entityBody = "{\"grant_types\":[\"code\"]}";
		servletRequest.setEntityBody(entityBody);
		servletRequest.setAttribute("javax.servlet.request.X509Certificate", new X509Certificate[]{cert});
		

		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_JSON.toString(), httpRequest.getEntityContentType().toString());
		assertNull(httpRequest.getAccept());
		assertNull(httpRequest.getAuthorization());
		assertEquals(entityBody, httpRequest.getQuery());
		JSONObject jsonObject = httpRequest.getQueryAsJSONObject();
		assertEquals("code", JSONObjectUtils.getStringArray(jsonObject, "grant_types")[0]);
		assertEquals(1, jsonObject.size());
		assertEquals(cert, httpRequest.getClientX509Certificate());
		assertEquals("CN=456", httpRequest.getClientX509CertificateSubjectDN());
		assertNull("Root not recorded for non-self-signed cert", httpRequest.getClientX509CertificateRootDN());
	}


	public void testConstructFromServletRequestURLEncoded()
		throws Exception {

		MockServletRequest servletRequest = new MockServletRequest();
		servletRequest.setMethod("POST");
		servletRequest.setHeader("Content-Type", ContentType.APPLICATION_URLENCODED.toString());
		servletRequest.setLocalAddr("c2id.com");
		servletRequest.setLocalPort(8080);
		servletRequest.setRequestURI("/token");
		servletRequest.setQueryString(null);
		servletRequest.setEntityBody("");
		servletRequest.setParameter("token", "abc");
		servletRequest.setParameter("type", "bearer");

		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_URLENCODED.toString(), httpRequest.getEntityContentType().toString());
		assertNull(httpRequest.getAccept());
		assertNull(httpRequest.getAuthorization());
		Map<String, List<String>> queryParams = httpRequest.getQueryParameters();
		assertEquals(Collections.singletonList("abc"), queryParams.get("token"));
		assertEquals(Collections.singletonList("bearer"), queryParams.get("type"));
		assertEquals(2, queryParams.size());
	}


	public void testConstructFromServletRequestWithQueryString()
		throws Exception {

		MockServletRequest servletRequest = new MockServletRequest();
		servletRequest.setMethod("GET");
		servletRequest.setLocalAddr("c2id.com");
		servletRequest.setLocalPort(8080);
		servletRequest.setRequestURI("/token");
		servletRequest.setQueryString("token=abc&type=bearer");

		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
		assertEquals(HTTPRequest.Method.GET, httpRequest.getMethod());
		assertNull(httpRequest.getEntityContentType());
		assertNull(httpRequest.getAccept());
		assertNull(httpRequest.getAuthorization());
		Map<String,List<String>> queryParams = httpRequest.getQueryParameters();
		assertEquals(Collections.singletonList("abc"), queryParams.get("token"));
		assertEquals(Collections.singletonList("bearer"), queryParams.get("type"));
		assertEquals(2, queryParams.size());
	}


	public void testServletRequestWithExceededEntityLengthLimit() {

		MockServletRequest servletRequest = new MockServletRequest();
		servletRequest.setMethod("POST");
		servletRequest.setLocalAddr("c2id.com");
		servletRequest.setLocalPort(8080);
		servletRequest.setRequestURI("/token");
		servletRequest.setQueryString(null);

		StringBuilder sb = new StringBuilder();
		for (int i=0; i < 1001; i++) {
			sb.append("a");
		}

		servletRequest.setEntityBody(sb.toString());

		try {
			ServletUtils.createHTTPRequest(servletRequest, 1000);
			fail();
		} catch (IOException e) {
			assertEquals("Request entity body is too large, limit is 1000 chars", e.getMessage());
		}
	}


	public void testServletRequestWithinEntityLengthLimit()
		throws Exception {

		MockServletRequest servletRequest = new MockServletRequest();
		servletRequest.setMethod("POST");
		servletRequest.setHeader("Content-Type", ContentType.APPLICATION_URLENCODED.toString());
		servletRequest.setLocalAddr("c2id.com");
		servletRequest.setLocalPort(8080);
		servletRequest.setRequestURI("/token");
		servletRequest.setQueryString(null);

		StringBuilder sb = new StringBuilder();
		for (int i=0; i < 1000; i++) {
			sb.append("a");
		}

		servletRequest.setEntityBody(sb.toString());

		ServletUtils.createHTTPRequest(servletRequest, 1000);
	}


	public void testRedirectApplyToServletResponse()
		throws Exception {

		HTTPResponse response = new HTTPResponse(302);
		response.setLocation(new URI("https://client.com/cb"));

		MockServletResponse servletResponse = new MockServletResponse();

		ServletUtils.applyHTTPResponse(response, servletResponse);

		assertFalse(response.indicatesSuccess());
		assertEquals(302, servletResponse.getStatus());
		assertEquals("https://client.com/cb", servletResponse.getHeader("Location"));
	}


	public void testJSONContentApplyToServletResponse()
		throws Exception {

		HTTPResponse response = new HTTPResponse(200);
		response.setEntityContentType(ContentType.APPLICATION_JSON);
		response.setCacheControl("no-cache");
		response.setPragma("no-cache");
		response.setContent("{\"apples\":\"123\"}");

		MockServletResponse servletResponse = new MockServletResponse();

		ServletUtils.applyHTTPResponse(response, servletResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals(200, servletResponse.getStatus());
		assertEquals("application/json; charset=UTF-8", servletResponse.getContentType());
		assertEquals("no-cache", servletResponse.getHeader("Cache-Control"));
		assertEquals("no-cache", servletResponse.getHeader("Pragma"));
		assertEquals("{\"apples\":\"123\"}", servletResponse.getContent());
	}
	
	
	// iss #211
	public void testRequestWithNullLocalAddress()
		throws Exception {
		
		MockServletRequest servletRequest = new MockServletRequest();
		servletRequest.setMethod("POST");
		servletRequest.setHeader("Content-Type", ContentType.APPLICATION_JSON.toString());
		servletRequest.setLocalAddr(null);
		servletRequest.setLocalPort(8080);
		servletRequest.setRequestURI("/clients");
		servletRequest.setQueryString(null);
		String entityBody = "{\"grant_types\":[\"code\"]}";
		servletRequest.setEntityBody(entityBody);
		
		HTTPRequest httpRequest = ServletUtils.createHTTPRequest(servletRequest);
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_JSON.toString(), httpRequest.getEntityContentType().toString());
		assertNull(httpRequest.getAccept());
		assertNull(httpRequest.getAuthorization());
		assertEquals(entityBody, httpRequest.getQuery());
		JSONObject jsonObject = httpRequest.getQueryAsJSONObject();
		assertEquals("code", JSONObjectUtils.getStringArray(jsonObject, "grant_types")[0]);
		assertEquals(1, jsonObject.size());
	}
	
	
	public void testExtractClientCertificate_none() {
		
		assertNull(ServletUtils.extractClientX509Certificate(new MockServletRequest()));
	}
	
	
	public void testExtractClientCertificate_emptyArray() {
		
		MockServletRequest servletRequest = new MockServletRequest();
		servletRequest.setAttribute("javax.servlet.request.X509Certificate", new X509Certificate[]{});
		
		assertNull(ServletUtils.extractClientX509Certificate(servletRequest));
	}
	
	
	public void testExtractClientCertificate_onePresent()
		throws Exception {
		
		X509Certificate cert = X509CertificateGenerator.generateSampleClientCertificate();
		
		X509Certificate[] certArray = new X509Certificate[]{cert};
		
		MockServletRequest servletRequest = new MockServletRequest();
		servletRequest.setAttribute("javax.servlet.request.X509Certificate", certArray);
		
		assertEquals(cert, ServletUtils.extractClientX509Certificate(servletRequest));
	}
}
