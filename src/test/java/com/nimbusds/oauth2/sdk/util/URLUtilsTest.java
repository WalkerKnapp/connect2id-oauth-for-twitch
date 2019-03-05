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

package com.nimbusds.oauth2.sdk.util;


import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.*;

import junit.framework.TestCase;



public class URLUtilsTest extends TestCase {
	
	
	public void testGetBaseURLSame()
		throws MalformedURLException {
	
		URL url = new URL("http://client.example.com:8080/endpoints/openid/connect/cb");
		
		URL baseURL = URLUtils.getBaseURL(url);
		
		assertEquals("http://client.example.com:8080/endpoints/openid/connect/cb", baseURL.toString());
	}
	
	
	public void testGetBaseURLTrim()
		throws MalformedURLException {
	
		URL url = new URL("http://client.example.com:8080/endpoints/openid/connect/cb?param1=one&param2=two");
		
		URL baseURL = URLUtils.getBaseURL(url);
		
		assertEquals("http://client.example.com:8080/endpoints/openid/connect/cb", baseURL.toString());
	}
	
	
	public void testJavaURLDecoder()
		throws Exception {
	
		final String decodedPlus = URLDecoder.decode("abc+def", "utf-8");
		final String decodedPerCent20 = URLDecoder.decode("abc%20def", "utf-8");
		
		assertEquals("abc def", decodedPlus);
		assertEquals("abc def", decodedPerCent20);
	}
	
	
	public void testSerializeParameters() {
	
		Map<String,List<String>> params = new LinkedHashMap<>();
		
		params.put("response_type", Collections.singletonList("code id_token"));
		params.put("client_id", Collections.singletonList("s6BhdRkqt3"));
		params.put("redirect_uri", Collections.singletonList("https://client.example.com/cb"));
		params.put("scope", Collections.singletonList("openid"));
		params.put("nonce", Collections.singletonList("n-0S6_WzA2Mj"));
		params.put("state", Collections.singletonList("af0ifjsldkj"));
		
		String query = URLUtils.serializeParameters(params);
		
		assertEquals("response_type=code+id_token" +
		             "&client_id=s6BhdRkqt3" +
			     "&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb" +
			     "&scope=openid" +
			     "&nonce=n-0S6_WzA2Mj" +
			     "&state=af0ifjsldkj", query);
	}


	public void testSerializeParameters_nullValue() {

		Map<String,List<String>> params = new LinkedHashMap<>();

		params.put("response_type", Collections.singletonList("code"));
		params.put("display", null);

		String query = URLUtils.serializeParameters(params);

		assertEquals("response_type=code", query);
	}
	
	
	public void testSerializeParametersNull() {
	
		String query = URLUtils.serializeParameters(null);
		
		assertTrue(query.isEmpty());
	}
	
	
	public void testSerializeParameters_multiValued() {
		
		Map<String,List<String>> params = new LinkedHashMap<>();
		
		params.put("key-1", Collections.singletonList("val-1"));
		params.put("key-2", Arrays.asList("val-2a", "val-2b"));
		
		String query = URLUtils.serializeParameters(params);
		
		assertEquals("key-1=val-1&key-2=val-2a&key-2=val-2b", query);
	}
	
	
	public void testParseParameters() {
	
		String query = "response_type=code%20id_token" +
				"&client_id=s6BhdRkqt3" +
				"&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb" +
				"&scope=openid" +
				"&nonce=n-0S6_WzA2Mj" +
				"&state=af0ifjsldkj";
	
		Map<String,List<String>> params = URLUtils.parseParameters(query);

		assertEquals(Collections.singletonList("code id_token"), params.get("response_type"));
		assertEquals(Collections.singletonList("s6BhdRkqt3"), params.get("client_id"));
		assertEquals(Collections.singletonList("https://client.example.com/cb"), params.get("redirect_uri"));
		assertEquals(Collections.singletonList("openid"), params.get("scope"));
		assertEquals(Collections.singletonList("n-0S6_WzA2Mj"), params.get("nonce"));
		assertEquals(Collections.singletonList("af0ifjsldkj"), params.get("state"));
	}


	public void testParseParametersNull() {
	
		assertTrue(URLUtils.parseParameters(null).isEmpty());
	}


	public void testParseParametersEmpty() {

		assertTrue(URLUtils.parseParameters(" ").isEmpty());
	}


	public void testParseParametersEnsureTrim() {

		String query = "\np1=abc&p2=def  \n";

		Map<String,List<String>> params = URLUtils.parseParameters(query);

		assertEquals(Collections.singletonList("abc"), params.get("p1"));
		assertEquals(Collections.singletonList("def"), params.get("p2"));
		assertEquals(2, params.size());
	}


	// See https://bitbucket.org/connect2id/openid-connect-dev-client/issues/5/stripping-equal-sign-from-access_code-in
	public void testDecodeQueryStringWithEscapedChars() {

		String fragment = "scope=openid+email+profile" +
			"&state=cVIe4g4D1J3tYtZgnTL-Po9QpozQJdikDCBp7KJorIQ" +
			"&code=1nf1ljB0JkPIbhMcYMeoT9Q5oGt28ggDsUiWLvCL81YTqCZMzAbVCGLUPrDHouda4cELZRujcS7d8rUNcZVl7HxUXdDsOUtc65s2knGbxSo%3D";

		Map<String,List<String>> params = URLUtils.parseParameters(fragment);

		assertEquals(Collections.singletonList("openid email profile"), params.get("scope"));
		assertEquals(Collections.singletonList("cVIe4g4D1J3tYtZgnTL-Po9QpozQJdikDCBp7KJorIQ"), params.get("state"));
		assertEquals(Collections.singletonList("1nf1ljB0JkPIbhMcYMeoT9Q5oGt28ggDsUiWLvCL81YTqCZMzAbVCGLUPrDHouda4cELZRujcS7d8rUNcZVl7HxUXdDsOUtc65s2knGbxSo="), params.get("code"));
	}


	// See iss #169
	public void testAllowEqualsCharInParamValue() {

		String query = "key0=value&key1=value=&key2=value==&key3=value===";

		Map<String,List<String>> params = URLUtils.parseParameters(query);
		assertEquals(Collections.singletonList("value"), params.get("key0"));
		assertEquals(Collections.singletonList("value="), params.get("key1"));
		assertEquals(Collections.singletonList("value=="), params.get("key2"));
		assertEquals(Collections.singletonList("value==="), params.get("key3"));
		assertEquals(4, params.size());
	}


	public void testSerializeAlt_duplicateKeys() {

		Map<String,String[]> params = new LinkedHashMap<>();

		params.put("fruit", new String[]{"apple", "orange"});
		params.put("veg", new String[]{"lettuce"});

		String s = URLUtils.serializeParametersAlt(params);

		assertEquals("fruit=apple&fruit=orange&veg=lettuce", s);
	}


	public void testSerializeAlt_nullValue() {

		Map<String,String[]> params = new LinkedHashMap<>();

		params.put("fruit", null);
		params.put("veg", new String[]{"lettuce"});

		String s = URLUtils.serializeParametersAlt(params);

		assertEquals("veg=lettuce", s);
	}


	public void testSerializeAlt_nullValueInArray() {

		Map<String,String[]> params = new LinkedHashMap<>();

		params.put("fruit", new String[]{"apple", null});
		params.put("veg", new String[]{"lettuce"});

		String s = URLUtils.serializeParametersAlt(params);

		assertEquals("fruit=apple&fruit=&veg=lettuce", s);
	}
}
