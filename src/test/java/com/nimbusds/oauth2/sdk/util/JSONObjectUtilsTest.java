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


import java.util.Arrays;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

import com.nimbusds.oauth2.sdk.client.ClientType;
import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Tests the JSON object utility methods.
 */
public class JSONObjectUtilsTest extends TestCase {
	
	
	public static JSONObject getTestJSONObject() {
	
		JSONObject o = new JSONObject();
		
		o.put("bool", true);
		o.put("int", 100);
		o.put("long", 500l);
		o.put("float", 3.14f);
		o.put("double", 3.1415d);
		o.put("string", "Alice");
		o.put("url", "http://server.example.com/cb/");
		o.put("email", "alice@wonderland.net");
		o.put("client_type", "public");
		o.put("aud", Arrays.asList("client-1", "client-2"));
		
		JSONParser parser = new JSONParser(JSONParser.USE_HI_PRECISION_FLOAT);
		
		try {
			o = (JSONObject)parser.parse(o.toString());
			
		} catch (net.minidev.json.parser.ParseException e) {
		
			fail(e.getMessage());
		}
		
		return o;
	}
	
	
	public void testJSONObjectParse()
		throws Exception {
	
		String s = "{\"apples\":3, \"pears\":\"none\"}";
		
		JSONObject o = JSONObjectUtils.parse(s);

		assertEquals(new Long(3), (Long)o.get("apples"));
		assertEquals("none", (String)o.get("pears"));
		assertEquals(2, o.size());
	}


	public void testParseWithTrailingWhiteSpace()
		throws Exception {

		assertEquals(0, JSONObjectUtils.parse("{} ").size());
		assertEquals(0, JSONObjectUtils.parse("{}\n").size());
		assertEquals(0, JSONObjectUtils.parse("{}\r\n").size());
	}
	
	
	public void testJSONObjectParseException() {
	
		try {
			JSONObjectUtils.parse("{\"apples\":3, ");
			fail();
			
		} catch (ParseException e) {
			// ok
		}
	}
	
	
	public void testJSONObjectObjectParseExceptionNull() {
	
		try {
			JSONObjectUtils.parse(null);
			fail();
			
		} catch (ParseException e) {
		
			fail();
		
		} catch (NullPointerException e) {
		
			// ok
		}
	}
	
	
	public void testJSONObjectObjectParseExceptionNullEntity() {
	
		try {
			JSONObjectUtils.parse("null");
			fail();
		
		} catch (ParseException e) {
		
			// ok
		}
	}
	
	
	public void testJSONObjectObjectParseExceptionEmptyString() {
	
		try {
			JSONObjectUtils.parse("");
			
			fail("Failed to raise exception");
		
		} catch (ParseException e) {
		
			// ok
		}
	}
	
	
	public void testJSONObjectObjectParseExceptionWhitespaceString() {
	
		try {
			JSONObjectUtils.parse(" ");
			fail();
		
		} catch (ParseException e) {
		
			// ok
		}
	}
	
	
	public void testGetters()
		throws Exception {

		JSONObject o = getTestJSONObject();

		assertEquals(true, JSONObjectUtils.getBoolean(o, "bool"));
		assertEquals(100, JSONObjectUtils.getInt(o, "int"));
		assertEquals(500l, JSONObjectUtils.getLong(o, "long"));
		assertEquals(3.14f, JSONObjectUtils.getFloat(o, "float"));
		assertEquals(3.1415d, JSONObjectUtils.getDouble(o, "double"));
		assertEquals("Alice", JSONObjectUtils.getString(o, "string"));
		assertEquals("http://server.example.com/cb/", JSONObjectUtils.getURL(o, "url").toString());
		assertEquals("http://server.example.com/cb/", JSONObjectUtils.getURI(o, "url").toString());
		assertEquals("alice@wonderland.net", JSONObjectUtils.getEmail(o, "email").toString());
		assertEquals(ClientType.PUBLIC, JSONObjectUtils.getEnum(o, "client_type", ClientType.class));

		assertTrue(Arrays.asList("client-1", "client-2").containsAll(JSONObjectUtils.getList(o, "aud")));
		assertTrue(Arrays.asList("client-1", "client-2").containsAll(JSONObjectUtils.getJSONArray(o, "aud")));
	}


	public void testNumberGetter()
		throws Exception {

		JSONObject o = getTestJSONObject();

		assertEquals(100, JSONObjectUtils.getNumber(o, "int").intValue());
		assertEquals(500l, JSONObjectUtils.getNumber(o, "long").longValue());
		assertEquals(3.14f, JSONObjectUtils.getNumber(o, "float").floatValue());
		assertEquals(3.1415d, JSONObjectUtils.getNumber(o, "double").doubleValue());
	}


	public void testParseBadStringArray() {

		JSONObject o = new JSONObject();
		o.put("array", Arrays.asList("apples", 10, true));

		try {
			JSONObjectUtils.getStringArray(o, "array");
			fail();
		} catch (ParseException e) {
			// ok
		}
	}


	public void testParseStringList()
		throws Exception {

		JSONObject o = new JSONObject();
		o.put("fruit", Arrays.asList("apples", "pears", "plums"));

		String json = o.toJSONString();

		List<String> fruit = JSONObjectUtils.getStringList(JSONObjectUtils.parse(json), "fruit");

		assertEquals("apples", fruit.get(0));
		assertEquals("pears", fruit.get(1));
		assertEquals("plums", fruit.get(2));
		assertEquals(3, fruit.size());
	}


	public void testParseBadStringList() {

		JSONObject o = new JSONObject();
		o.put("array", Arrays.asList("apples", 10, true));

		try {
			JSONObjectUtils.getStringList(o, "array");
			fail();
		} catch (ParseException e) {
			// ok
		}
	}


	public void testParseStringSet()
		throws Exception {

		JSONObject o = new JSONObject();
		o.put("fruit", Arrays.asList("apples", "pears", "plums"));

		String json = o.toJSONString();

		Set<String> fruit = JSONObjectUtils.getStringSet(JSONObjectUtils.parse(json), "fruit");

		assertTrue(fruit.contains("apples"));
		assertTrue(fruit.contains("pears"));
		assertTrue(fruit.contains("plums"));
		assertEquals(3, fruit.size());
	}


	public void testParseBadStringSet()
		throws Exception {

		JSONObject o = new JSONObject();
		o.put("fruit", Arrays.asList("apples", 10, true));

		String json = o.toJSONString();

		o = JSONObjectUtils.parse(json);

		try {
			JSONObjectUtils.getStringSet(o, "fruit");
			fail();
		} catch (ParseException e) {
			// ok
		}
	}
}
