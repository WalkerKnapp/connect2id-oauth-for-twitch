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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertNotEquals;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


public class ErrorObjectTest extends TestCase {


	public void testConstructor1() {

		ErrorObject eo = new ErrorObject("access_denied");

		assertEquals("access_denied", eo.getCode());
		assertNull(eo.getDescription());
		assertNull(eo.getURI());
		assertEquals(0, eo.getHTTPStatusCode());
		assertTrue(eo.getCustomParams().isEmpty());

		assertEquals("access_denied", eo.toJSONObject().get("error"));
		assertEquals(1, eo.toJSONObject().size());
		
		assertEquals(Collections.singletonList("access_denied"), eo.toParameters().get("error"));
		assertEquals(1, eo.toParameters().size());
		
		assertEquals(eo.toJSONObject(), ErrorObject.parse(eo.toJSONObject()).toJSONObject());
		assertEquals(eo.toParameters(), ErrorObject.parse(eo.toParameters()).toParameters());
	}


	public void testConstructor2() {

		ErrorObject eo = new ErrorObject("access_denied", "Access denied");

		assertEquals("access_denied", eo.getCode());
		assertEquals("Access denied", eo.getDescription());
		assertNull(eo.getURI());
		assertEquals(0, eo.getHTTPStatusCode());
		assertTrue(eo.getCustomParams().isEmpty());

		assertEquals("access_denied", eo.toJSONObject().get("error"));
		assertEquals("Access denied", eo.toJSONObject().get("error_description"));
		assertEquals(2, eo.toJSONObject().size());
		
		assertEquals(Collections.singletonList("access_denied"), eo.toParameters().get("error"));
		assertEquals(Collections.singletonList("Access denied"), eo.toParameters().get("error_description"));
		assertEquals(2, eo.toParameters().size());
		
		assertEquals(eo.toJSONObject(), ErrorObject.parse(eo.toJSONObject()).toJSONObject());
		assertEquals(eo.toParameters(), ErrorObject.parse(eo.toParameters()).toParameters());
	}


	public void testConstructor3() {

		ErrorObject eo = new ErrorObject("access_denied", "Access denied", 403);

		assertEquals("access_denied", eo.getCode());
		assertEquals("Access denied", eo.getDescription());
		assertNull(eo.getURI());
		assertEquals(403, eo.getHTTPStatusCode());
		assertTrue(eo.getCustomParams().isEmpty());

		assertEquals("access_denied", eo.toJSONObject().get("error"));
		assertEquals("Access denied", eo.toJSONObject().get("error_description"));
		assertEquals(2, eo.toJSONObject().size());
		
		assertEquals(Collections.singletonList("access_denied"), eo.toParameters().get("error"));
		assertEquals(Collections.singletonList("Access denied"), eo.toParameters().get("error_description"));
		assertEquals(2, eo.toParameters().size());
		
		assertEquals(eo.toJSONObject(), ErrorObject.parse(eo.toJSONObject()).toJSONObject());
		assertEquals(eo.toParameters(), ErrorObject.parse(eo.toParameters()).toParameters());
	}


	public void testConstructor4()
		throws Exception {

		ErrorObject eo = new ErrorObject("access_denied", "Access denied", 403, new URI("https://c2id.com/errors/access_denied"));

		assertEquals("access_denied", eo.getCode());
		assertEquals("Access denied", eo.getDescription());
		assertEquals(new URI("https://c2id.com/errors/access_denied"), eo.getURI());
		assertEquals(403, eo.getHTTPStatusCode());
		assertTrue(eo.getCustomParams().isEmpty());

		assertEquals("access_denied", eo.toJSONObject().get("error"));
		assertEquals("Access denied", eo.toJSONObject().get("error_description"));
		assertEquals("https://c2id.com/errors/access_denied", eo.toJSONObject().get("error_uri"));
		assertEquals(3, eo.toJSONObject().size());
		
		assertEquals(Collections.singletonList("access_denied"), eo.toParameters().get("error"));
		assertEquals(Collections.singletonList("Access denied"), eo.toParameters().get("error_description"));
		assertEquals(Collections.singletonList("https://c2id.com/errors/access_denied"), eo.toParameters().get("error_uri"));
		assertEquals(3, eo.toParameters().size());
		
		assertEquals(eo.toJSONObject(), ErrorObject.parse(eo.toJSONObject()).toJSONObject());
		assertEquals(eo.toParameters(), ErrorObject.parse(eo.toParameters()).toParameters());
	}


	public void testConstructor5()
		throws Exception {

		Map<String,String> customParams = new HashMap<>();
		customParams.put("p1", "abc");
		customParams.put("p2", "def");
		customParams.put("p3", null);
		
		ErrorObject eo = new ErrorObject(
			"access_denied",
			"Access denied",
			403,
			new URI("https://c2id.com/errors/access_denied"),
			customParams
		);

		assertEquals("access_denied", eo.getCode());
		assertEquals("Access denied", eo.getDescription());
		assertEquals(new URI("https://c2id.com/errors/access_denied"), eo.getURI());
		assertEquals(403, eo.getHTTPStatusCode());
		assertEquals(customParams, eo.getCustomParams());

		assertEquals("access_denied", eo.toJSONObject().get("error"));
		assertEquals("Access denied", eo.toJSONObject().get("error_description"));
		assertEquals("https://c2id.com/errors/access_denied", eo.toJSONObject().get("error_uri"));
		assertEquals("abc", eo.toJSONObject().get("p1"));
		assertEquals("def", eo.toJSONObject().get("p2"));
		assertTrue(eo.toJSONObject().containsKey("p3"));
		assertNull(eo.toJSONObject().get("p3"));
		assertEquals(6, eo.toJSONObject().size());
		
		assertEquals(Collections.singletonList("access_denied"), eo.toParameters().get("error"));
		assertEquals(Collections.singletonList("Access denied"), eo.toParameters().get("error_description"));
		assertEquals(Collections.singletonList("https://c2id.com/errors/access_denied"), eo.toParameters().get("error_uri"));
		assertEquals(Collections.singletonList("abc"), eo.toParameters().get("p1"));
		assertEquals(Collections.singletonList("def"), eo.toParameters().get("p2"));
		assertEquals(Collections.singletonList(null), eo.toParameters().get("p3"));
		assertEquals(6, eo.toParameters().size());
		
		assertEquals(eo.toJSONObject(), ErrorObject.parse(eo.toJSONObject()).toJSONObject());
		assertEquals(eo.toParameters(), ErrorObject.parse(eo.toParameters()).toParameters());
	}


	public void testParseHTTPRequest_full() {

		HTTPResponse httpResponse = new HTTPResponse(403);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("error", "access_denied");
		jsonObject.put("error_description", "Access denied");
		jsonObject.put("error_uri", "https://c2id.com/errors/access_denied");
		jsonObject.put("custom-param-1", "value-1");

		httpResponse.setContent(jsonObject.toJSONString());

		ErrorObject errorObject = ErrorObject.parse(httpResponse);

		assertEquals(403, errorObject.getHTTPStatusCode());
		assertEquals("access_denied", errorObject.getCode());
		assertEquals("Access denied", errorObject.getDescription());
		assertEquals("https://c2id.com/errors/access_denied", errorObject.getURI().toString());
		assertEquals("value-1", errorObject.getCustomParams().get("custom-param-1"));
		assertEquals(1, errorObject.getCustomParams().size());
	}


	public void testParseHTTPRequest_withOmittedURI() {

		HTTPResponse httpResponse = new HTTPResponse(403);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("error", "access_denied");
		jsonObject.put("error_description", "Access denied");

		httpResponse.setContent(jsonObject.toJSONString());

		ErrorObject errorObject = ErrorObject.parse(httpResponse);

		assertEquals(403, errorObject.getHTTPStatusCode());
		assertEquals("access_denied", errorObject.getCode());
		assertEquals("Access denied", errorObject.getDescription());
		assertNull(errorObject.getURI());
	}


	public void testParseHTTPRequest_withCodeOnly() {

		HTTPResponse httpResponse = new HTTPResponse(403);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("error", "access_denied");

		httpResponse.setContent(jsonObject.toJSONString());

		ErrorObject errorObject = ErrorObject.parse(httpResponse);

		assertEquals(403, errorObject.getHTTPStatusCode());
		assertEquals("access_denied", errorObject.getCode());
		assertNull(errorObject.getDescription());
		assertNull(errorObject.getURI());
	}


	public void testParseHTTPRequest_errorDescriptionWithIllegalChars() {
		
		String errorDescription = "\"Access denied\"\r\nConsent denied by user";
		
		HTTPResponse httpResponse = new HTTPResponse(403);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("error", "access_denied");
		jsonObject.put("error_description", errorDescription);

		httpResponse.setContent(jsonObject.toJSONString());

		ErrorObject errorObject = ErrorObject.parse(httpResponse);

		assertEquals(403, errorObject.getHTTPStatusCode());
		assertEquals("access_denied", errorObject.getCode());
		assertEquals(ErrorObject.removeIllegalChars(errorDescription), errorObject.getDescription());
		assertNull(errorObject.getURI());
	}
	
	
	public void testParseHTTPRequest_none() {
		
		HTTPResponse httpResponse = new HTTPResponse(403);
		
		ErrorObject errorObject = ErrorObject.parse(httpResponse);
		
		assertEquals(403, errorObject.getHTTPStatusCode());
		assertNull(errorObject.getCode());
		assertNull(errorObject.getDescription());
		assertNull(errorObject.getURI());
	}


	public void testParseParams_full() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("error", Collections.singletonList("access_denied"));
		params.put("error_description", Collections.singletonList("Access denied"));
		params.put("error_uri", Collections.singletonList("https://c2id.com/errors/access_denied"));
		

		ErrorObject errorObject = ErrorObject.parse(params);

		assertEquals(0, errorObject.getHTTPStatusCode());
		assertEquals("access_denied", errorObject.getCode());
		assertEquals("Access denied", errorObject.getDescription());
		assertEquals("https://c2id.com/errors/access_denied", errorObject.getURI().toString());
	}


	public void testParseParams_withOmittedUR() {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("error", Collections.singletonList("access_denied"));
		params.put("error_description", Collections.singletonList("Access denied"));

		ErrorObject errorObject = ErrorObject.parse(params);

		assertEquals(0, errorObject.getHTTPStatusCode());
		assertEquals("access_denied", errorObject.getCode());
		assertEquals("Access denied", errorObject.getDescription());
		assertNull(errorObject.getURI());
	}


	public void testParseParams_withCodeOnly() {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("error", Collections.singletonList("access_denied"));

		ErrorObject errorObject = ErrorObject.parse(params);

		assertEquals(0, errorObject.getHTTPStatusCode());
		assertEquals("access_denied", errorObject.getCode());
		assertNull(errorObject.getDescription());
		assertNull(errorObject.getURI());
	}


	public void testParseParams_none() {
		
		ErrorObject errorObject = ErrorObject.parse(new HashMap<String, List<String>>());

		assertEquals(0, errorObject.getHTTPStatusCode());
		assertNull(errorObject.getCode());
		assertNull(errorObject.getDescription());
		assertNull(errorObject.getURI());
	}
	
	
	public void testParseParams_errorDescriptionWithIllegalChars() {
		
		String errorDescription = "\"Access denied\"\r\nConsent denied by user";
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("error", Collections.singletonList("access_denied"));
		params.put("error_description", Collections.singletonList(errorDescription));
		
		
		ErrorObject errorObject = ErrorObject.parse(params);
		
		assertEquals(0, errorObject.getHTTPStatusCode());
		assertEquals("access_denied", errorObject.getCode());
		assertEquals(ErrorObject.removeIllegalChars(errorDescription), errorObject.getDescription());
		assertNull(errorObject.getURI());
	}


	public void testEquality() {
		
		assertEquals(new ErrorObject("invalid_grant", null, 400), OAuth2Error.INVALID_GRANT);
		assertEquals(new ErrorObject("invalid_grant", null, 0), OAuth2Error.INVALID_GRANT);
		assertEquals(new ErrorObject(null, null, 0), new ErrorObject(null, null, 0));
	}


	public void testInequality() {
		
		assertNotEquals(new ErrorObject("bad_request", null, 400), OAuth2Error.INVALID_GRANT);
		assertNotEquals(new ErrorObject("bad_request", null, 0), OAuth2Error.INVALID_GRANT);
	}


	public void testSetDescription() {
		
		URI uri = URI.create("https://c2id.com/errors/access_denied");
		
		Map<String,String> customParams = new HashMap<>();
		customParams.put("p1", "abc");
		customParams.put("p2", "def");
		customParams.put("p3", null);
		
		ErrorObject error_1 = new ErrorObject("code", "description", 400, uri, customParams);
		
		ErrorObject error_2 = error_1.setDescription("new description");
		
		assertEquals("code", error_2.getCode());
		assertEquals("new description", error_2.getDescription());
		assertEquals(400, error_2.getHTTPStatusCode());
		assertEquals(uri, error_2.getURI());
		assertEquals(customParams, error_2.getCustomParams());
	}


	public void testAppendDescription() {
		
		URI uri = URI.create("https://c2id.com/errors/access_denied");
		
		Map<String,String> customParams = new HashMap<>();
		customParams.put("p1", "abc");
		customParams.put("p2", "def");
		customParams.put("p3", null);
		
		ErrorObject error_1 = new ErrorObject("code", "a", 400, uri, customParams);
		
		ErrorObject error_2 = error_1.appendDescription("b");
		
		assertEquals("code", error_2.getCode());
		assertEquals("ab", error_2.getDescription());
		assertEquals(400, error_2.getHTTPStatusCode());
		assertEquals(uri, error_2.getURI());
		assertEquals(customParams, error_2.getCustomParams());
	}


	public void testSetURI() {
		
		URI uri = URI.create("https://c2id.com/errors/access_denied");
		
		Map<String,String> customParams = new HashMap<>();
		customParams.put("p1", "abc");
		customParams.put("p2", "def");
		customParams.put("p3", null);
		
		ErrorObject error_1 = new ErrorObject("code", "description", 400, uri, customParams);
		
		URI otherURI = URI.create("https://errors.c2id.com/access_denied.html");
		
		ErrorObject error_2 = error_1.setURI(otherURI);
		
		assertEquals("code", error_2.getCode());
		assertEquals("description", error_2.getDescription());
		assertEquals(400, error_2.getHTTPStatusCode());
		assertEquals(otherURI, error_2.getURI());
		assertEquals(customParams, error_2.getCustomParams());
	}


	public void testSetHTTPStatusCode() {
		
		URI uri = URI.create("https://c2id.com/errors/access_denied");
		
		Map<String,String> customParams = new HashMap<>();
		customParams.put("p1", "abc");
		customParams.put("p2", "def");
		customParams.put("p3", null);
		
		ErrorObject error_1 = new ErrorObject("code", "description", 400, uri, customParams);
		
		ErrorObject error_2 = error_1.setHTTPStatusCode(440);
		
		assertEquals("code", error_2.getCode());
		assertEquals("description", error_2.getDescription());
		assertEquals(440, error_2.getHTTPStatusCode());
		assertEquals(uri, error_2.getURI());
		assertEquals(customParams, error_2.getCustomParams());
	}
	
	
	public void testSetCustomParams() {
		
		URI uri = URI.create("https://c2id.com/errors/access_denied");
		
		ErrorObject error_1 = new ErrorObject("code", "description", 400, uri);
		
		Map<String,String> customParams = new HashMap<>();
		customParams.put("p1", "abc");
		customParams.put("p2", "def");
		customParams.put("p3", null);
		
		ErrorObject error_2 = error_1.setCustomParams(customParams);
		
		assertEquals("code", error_2.getCode());
		assertEquals("description", error_2.getDescription());
		assertEquals(400, error_2.getHTTPStatusCode());
		assertEquals(uri, error_2.getURI());
		assertEquals(customParams, error_2.getCustomParams());
	}
	
	
	// Values for the "error" parameter MUST NOT include characters outside the
	// set %x20-21 / %x23-5B / %x5D-7E.
	//
	// Values for the "error_description" parameter MUST NOT include characters
	// outside the set %x20-21 / %x23-5B / %x5D-7E.
	public void testLegalCharsInCodeAndDescription() {
		
		for (char c=0; c < 128; c++) {
		
			if (c >= 0x20 && c <= 0x21) {
				assertTrue(ErrorObject.isLegal(c));
			} else if (c >= 0x23 && c <= 0x5B) {
				assertTrue(ErrorObject.isLegal(c));
			} else if (c >= 0x5D && c <= 0x7e) {
				assertTrue(ErrorObject.isLegal(c));
			} else {
				assertFalse(ErrorObject.isLegal(c));
			}
		}
		
		String alphaNum =
			"Aa" +
			"Bb" +
			"Cc" +
			"Dd" +
			"Ee" +
			"Ff" +
			"Gg" +
			"Hh" +
			"Ii" +
			"Jj" +
			"Kk" +
			"Ll" +
			"Mm" +
			"Nn" +
			"Oo" +
			"Pp" +
			"Qq" +
			"Rr" +
			"Ss" +
			"Tt" +
			"Uu" +
			"Vv" +
			"Ww" +
			"Xx" +
			"Yy" +
			"Zz" +
			"1234567890";
		
		assertTrue(ErrorObject.isLegal(alphaNum));
		
		assertTrue(ErrorObject.isLegal("`~!@#$%^&*()-_=+,./<>?|"));
		
		assertFalse(ErrorObject.isLegal('"'));
		assertFalse(ErrorObject.isLegal('\\'));
	}
	
	
	// Values for the "error" parameter MUST NOT include characters outside the
	// set %x20-21 / %x23-5B / %x5D-7E.
	//
	// Values for the "error_description" parameter MUST NOT include characters
	// outside the set %x20-21 / %x23-5B / %x5D-7E.
	public void testRemoveIllegalChars() {
		
		for (char c=0; c < 128; c++) {
		
			String in = c + "";
			if (c >= 0x20 && c <= 0x21) {
				assertTrue(ErrorObject.isLegal(c));
				assertEquals(in, ErrorObject.removeIllegalChars(in));
			} else if (c >= 0x23 && c <= 0x5B) {
				assertTrue(ErrorObject.isLegal(c));
				assertEquals(in, ErrorObject.removeIllegalChars(in));
			} else if (c >= 0x5D && c <= 0x7e) {
				assertTrue(ErrorObject.isLegal(c));
				assertEquals(in, ErrorObject.removeIllegalChars(in));
			} else {
				assertFalse(ErrorObject.isLegal(c));
				assertEquals("", ErrorObject.removeIllegalChars(in));
			}
		}
	}
	
	
	public void testRemoveIllegalChars_sample() {
		
		assertEquals("Invalid client: Invalid client_id", ErrorObject.removeIllegalChars("\"Invalid client\":\r\n Invalid client_id"));
	}
	
	
	public void testRemoveIllegalChars_null() {
		
		assertNull(ErrorObject.removeIllegalChars(null));
	}
}
