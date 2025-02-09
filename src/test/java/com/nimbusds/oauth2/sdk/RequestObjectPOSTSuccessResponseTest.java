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


import java.net.URI;
import java.util.Date;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;


public class RequestObjectPOSTSuccessResponseTest extends TestCase {

	
	public void testLifeCycle() throws ParseException {
		
		Issuer issuer = new Issuer("https://c2id.com");
		Audience audience = new Audience("123");
		URI requestURI = URI.create("urn:requests:aashoo1Ooj6ahc5C");
		long expTs = DateUtils.toSecondsSinceEpoch(new Date());
		Date exp = DateUtils.fromSecondsSinceEpoch(expTs);
		
		RequestObjectPOSTSuccessResponse response = new RequestObjectPOSTSuccessResponse(issuer, audience, requestURI, exp);
		
		assertEquals(issuer, response.getIssuer());
		assertEquals(audience, response.getAudience());
		assertEquals(requestURI, response.getRequestURI());
		assertEquals(exp, response.getExpirationTime());
		
		assertTrue(response.indicatesSuccess());
		
		JSONObject jsonObject = response.toJSONObject();
		assertEquals(issuer.getValue(), jsonObject.get("iss"));
		assertEquals(audience.getValue(), jsonObject.get("aud"));
		assertEquals(requestURI.toString(), jsonObject.get("request_uri"));
		assertEquals(expTs, jsonObject.get("exp"));
		assertEquals(4, jsonObject.size());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertEquals(201, httpResponse.getStatusCode());
		assertEquals(ContentType.APPLICATION_JSON.toString(), httpResponse.getEntityContentType().toString());
		
		jsonObject = httpResponse.getContentAsJSONObject();
		assertEquals(issuer.getValue(), jsonObject.get("iss"));
		assertEquals(audience.getValue(), jsonObject.get("aud"));
		assertEquals(requestURI.toString(), jsonObject.get("request_uri"));
		assertEquals(expTs, jsonObject.get("exp"));
		assertEquals(4, jsonObject.size());
		
		response = RequestObjectPOSTSuccessResponse.parse(jsonObject);
		
		assertEquals(issuer, response.getIssuer());
		assertEquals(audience, response.getAudience());
		assertEquals(requestURI, response.getRequestURI());
		assertEquals(exp, response.getExpirationTime());
		
		response = RequestObjectPOSTSuccessResponse.parse(httpResponse);
		
		assertEquals(issuer, response.getIssuer());
		assertEquals(audience, response.getAudience());
		assertEquals(requestURI, response.getRequestURI());
		assertEquals(exp, response.getExpirationTime());
	}
	
	
	public void testRejectNullParams() {
		
		Issuer issuer = new Issuer("https://c2id.com");
		Audience audience = new Audience("123");
		URI requestURI = URI.create("urn:requests:aashoo1Ooj6ahc5C");
		long expTs = DateUtils.toSecondsSinceEpoch(new Date());
		Date exp = DateUtils.fromSecondsSinceEpoch(expTs);
		
		try {
			new RequestObjectPOSTSuccessResponse(null, audience, requestURI, exp);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
		
		try {
			new RequestObjectPOSTSuccessResponse(issuer, null, requestURI, exp);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
		
		try {
			new RequestObjectPOSTSuccessResponse(issuer, audience, null, exp);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
		
		try {
			new RequestObjectPOSTSuccessResponse(issuer, audience, requestURI, null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testParseJSONObject_missingParams() {
		
		Issuer issuer = new Issuer("https://c2id.com");
		Audience audience = new Audience("123");
		URI requestURI = URI.create("urn:requests:aashoo1Ooj6ahc5C");
		long expTs = DateUtils.toSecondsSinceEpoch(new Date());
		Date exp = DateUtils.fromSecondsSinceEpoch(expTs);
		
		RequestObjectPOSTSuccessResponse response = new RequestObjectPOSTSuccessResponse(issuer, audience, requestURI, exp);
		
		JSONObject jsonObject = response.toJSONObject();
		jsonObject.remove("iss");
		try {
			RequestObjectPOSTSuccessResponse.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key iss", e.getMessage());
		}
		
		jsonObject = response.toJSONObject();
		jsonObject.remove("aud");
		try {
			RequestObjectPOSTSuccessResponse.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key aud", e.getMessage());
		}
		
		jsonObject = response.toJSONObject();
		jsonObject.remove("request_uri");
		try {
			RequestObjectPOSTSuccessResponse.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key request_uri", e.getMessage());
		}
		
		jsonObject = response.toJSONObject();
		jsonObject.remove("exp");
		try {
			RequestObjectPOSTSuccessResponse.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key exp", e.getMessage());
		}
	}
	
	
	public void testParseHTTPResponse_unexpectedStatusCode() {
		
		try {
			RequestObjectPOSTSuccessResponse.parse(new HTTPResponse(HTTPResponse.SC_UNAUTHORIZED));
			fail();
		} catch (ParseException e) {
			assertEquals("Unexpected HTTP status code 401, must be [201, 200]", e.getMessage());
		}
	}
	
	
	public void testParseMissingContentTypeHeader() throws ParseException {
		
		Issuer issuer = new Issuer("https://c2id.com");
		Audience audience = new Audience("123");
		URI requestURI = URI.create("urn:requests:aashoo1Ooj6ahc5C");
		long expTs = DateUtils.toSecondsSinceEpoch(new Date());
		Date exp = DateUtils.fromSecondsSinceEpoch(expTs);
		
		RequestObjectPOSTSuccessResponse response = new RequestObjectPOSTSuccessResponse(issuer, audience, requestURI, exp);
		HTTPResponse httpResponse = response.toHTTPResponse();
		httpResponse.setContentType((String)null);
		
		try {
			RequestObjectPOSTSuccessResponse.parse(httpResponse);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing HTTP Content-Type header", e.getMessage());
		}
	}
	
	
	public void testParseInvalidJSON() {
		
		Issuer issuer = new Issuer("https://c2id.com");
		Audience audience = new Audience("123");
		URI requestURI = URI.create("urn:requests:aashoo1Ooj6ahc5C");
		long expTs = DateUtils.toSecondsSinceEpoch(new Date());
		Date exp = DateUtils.fromSecondsSinceEpoch(expTs);
		
		RequestObjectPOSTSuccessResponse response = new RequestObjectPOSTSuccessResponse(issuer, audience, requestURI, exp);
		HTTPResponse httpResponse = response.toHTTPResponse();
		httpResponse.setContent("text plain");
		
		try {
			RequestObjectPOSTSuccessResponse.parse(httpResponse);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JSON", e.getMessage());
		}
	}
	
	
	public void testParseMissingIssuer() {
		
		Issuer issuer = new Issuer("https://c2id.com");
		Audience audience = new Audience("123");
		URI requestURI = URI.create("urn:requests:aashoo1Ooj6ahc5C");
		long expTs = DateUtils.toSecondsSinceEpoch(new Date());
		Date exp = DateUtils.fromSecondsSinceEpoch(expTs);
		
		RequestObjectPOSTSuccessResponse response = new RequestObjectPOSTSuccessResponse(issuer, audience, requestURI, exp);
		HTTPResponse httpResponse = response.toHTTPResponse();
		
		JSONObject jsonObject = response.toJSONObject();
		jsonObject.remove("iss");
		httpResponse.setContent(jsonObject.toJSONString());
		
		try {
			RequestObjectPOSTSuccessResponse.parse(httpResponse);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key iss", e.getMessage());
		}
	}
}
