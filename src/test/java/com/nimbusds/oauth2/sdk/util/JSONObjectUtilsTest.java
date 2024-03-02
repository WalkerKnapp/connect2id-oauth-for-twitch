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


import java.io.UnsupportedEncodingException;
import java.net.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;

import junit.framework.TestCase;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.junit.Assert;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.client.ClientType;
import com.nimbusds.oauth2.sdk.id.Actor;


public class JSONObjectUtilsTest extends TestCase {
	
	
	public static JSONObject getTestJSONObject() {
	
		JSONObject o = new JSONObject();
		
		o.put("bool", true);
		o.put("int", 100);
		o.put("long", 500L);
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

		assertEquals(Long.valueOf(3), (Long)o.get("apples"));
		assertEquals("none", (String)o.get("pears"));
		assertEquals(2, o.size());
	}
	
	
	public void testJSONObjectParseOrdered()
		throws Exception {
		
		Map<String,String> orderedMap = new LinkedHashMap<>();
		for (int i=0; i < 10; i++) {
			orderedMap.put(i+"-"+UUID.randomUUID().toString(), "v" + i);
		}
		
		String json = JSONObject.toJSONString(orderedMap);
		
		LinkedHashMap<String,Object> parsedJSONObject = JSONObjectUtils.parseKeepingOrder(json);
		
		Iterator<String> it = parsedJSONObject.keySet().iterator();
		
		for (int i=0; i < 10; i++) {
			assertTrue(it.next().startsWith(i+"-"));
		}
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
			assertEquals("The JSON string must not be null", e.getMessage());
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
		
		assertTrue(JSONObjectUtils.getBoolean(o, "bool"));
		assertEquals(100, JSONObjectUtils.getInt(o, "int"));
		assertEquals(500L, JSONObjectUtils.getLong(o, "long"));
		assertEquals(3.14f, JSONObjectUtils.getFloat(o, "float"));
		assertEquals(3.1415d, JSONObjectUtils.getDouble(o, "double"));
		assertEquals("Alice", JSONObjectUtils.getString(o, "string"));
		assertEquals("http://server.example.com/cb/", JSONObjectUtils.getURL(o, "url").toString());
		assertEquals("http://server.example.com/cb/", JSONObjectUtils.getURI(o, "url").toString());
		assertEquals("alice@wonderland.net", JSONObjectUtils.getString(o, "email"));
		assertEquals(ClientType.PUBLIC, JSONObjectUtils.getEnum(o, "client_type", ClientType.class));

		assertTrue(Arrays.asList("client-1", "client-2").containsAll(JSONObjectUtils.getList(o, "aud")));
		assertTrue(Arrays.asList("client-1", "client-2").containsAll(JSONObjectUtils.getJSONArray(o, "aud")));
	}


	public void testNumberGetter()
		throws Exception {

		JSONObject o = getTestJSONObject();

		assertEquals(100, JSONObjectUtils.getNumber(o, "int").intValue());
		assertEquals(500L, JSONObjectUtils.getNumber(o, "long").longValue());
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
	
	
	public void testGetBoolean_defaultValue()
		throws ParseException {
		
		JSONObject o = new JSONObject();
		
		boolean def = false;
		assertEquals(def, JSONObjectUtils.getBoolean(o, "key", def));
		
		o.put("value", null);
		assertFalse(JSONObjectUtils.getBoolean(o, "key", def));
		
		boolean value = true;
		o.put("key", value);
		assertEquals(value, JSONObjectUtils.getBoolean(o, "key", def));
	}
	
	
	public void testGetInt_defaultValue()
		throws ParseException {
		
		JSONObject o = new JSONObject();
		
		int def = 0;
		assertEquals(def, JSONObjectUtils.getInt(o, "key", def));
		
		o.put("key", null);
		assertEquals(def, JSONObjectUtils.getInt(o, "key", def));
		
		int value = 10;
		o.put("key", value);
		assertEquals(value, JSONObjectUtils.getInt(o, "key", def));
	}
	
	
	public void testGetLong_defaultValue()
		throws ParseException {
		
		JSONObject o = new JSONObject();
		
		long def = 0;
		assertEquals(def, JSONObjectUtils.getLong(o, "key", def));
		
		o.put("key", null);
		assertEquals(def, JSONObjectUtils.getLong(o, "key", def));
		
		long value = 10;
		o.put("key", value);
		assertEquals(value, JSONObjectUtils.getLong(o, "key", def));
	}
	
	
	public void testGetFloat_defaultValue()
		throws ParseException {
		
		JSONObject o = new JSONObject();
		
		float def = 0.0f;
		assertEquals(def, JSONObjectUtils.getFloat(o, "key", def));
		
		o.put("key", null);
		assertEquals(def, JSONObjectUtils.getFloat(o, "key", def));
		
		float value = 10.0f;
		o.put("key", value);
		assertEquals(value, JSONObjectUtils.getFloat(o, "key", def));
	}
	
	
	public void testGetDouble_defaultValue()
		throws ParseException {
		
		JSONObject o = new JSONObject();
		
		double def = 0.0d;
		assertEquals(def, JSONObjectUtils.getDouble(o, "key", def));
		
		o.put("key", null);
		assertEquals(def, JSONObjectUtils.getDouble(o, "key", def));
		
		double value = 10.0d;
		o.put("key", value);
		assertEquals(value, JSONObjectUtils.getDouble(o, "key", def));
	}
	
	
	public void testGetNumber_defaultValue()
		throws ParseException {
		
		JSONObject o = new JSONObject();
		assertNull(JSONObjectUtils.getNumber(o, "key", null));
		
		Number def = 0L;
		assertEquals(def, JSONObjectUtils.getNumber(o, "key", def));
		
		o.put("key", null);
		assertEquals(def, JSONObjectUtils.getNumber(o, "key", def));
		
		Number value = 10L;
		o.put("key", value);
		assertEquals(value, JSONObjectUtils.getNumber(o, "key", null));
		
		assertEquals(value, JSONObjectUtils.getNumber(o, "key", def));
	}
	
	
	public void testGetString_defaultValue()
		throws ParseException {
		
		JSONObject o = new JSONObject();
		assertNull(JSONObjectUtils.getString(o, "key", null));
		
		String def = "";
		assertEquals(def, JSONObjectUtils.getString(o, "key", def));
		
		o.put("key", null);
		assertEquals(def, JSONObjectUtils.getString(o, "key", def));
		
		String value = "test";
		o.put("key", value);
		assertEquals(value, JSONObjectUtils.getString(o, "key", null));
		
		assertEquals(value, JSONObjectUtils.getString(o, "key", def));
	}
	
	
	public void testGetEnum_defaultValue()
		throws ParseException {
		
		JSONObject o = new JSONObject();
		assertNull(JSONObjectUtils.getEnum(o, "key", ClientType.class, null));
		
		ClientType def = null;
		assertEquals(def, JSONObjectUtils.getEnum(o, "key", ClientType.class, def));
		
		o.put("key", null);
		assertEquals(def, JSONObjectUtils.getEnum(o, "key", ClientType.class, def));
		
		ClientType value = ClientType.CONFIDENTIAL;
		o.put("key", value.toString());
		assertEquals(value, JSONObjectUtils.getEnum(o, "key", ClientType.class, null));
		
		assertEquals(value, JSONObjectUtils.getEnum(o, "key", ClientType.class, def));
	}
	
	
	public void testGetURI_defaultValue()
		throws ParseException {
		
		JSONObject o = new JSONObject();
		assertNull(JSONObjectUtils.getURI(o, "key", null));
		
		URI def = URI.create("https://c2id.com");
		assertEquals(def, JSONObjectUtils.getURI(o, "key", def));
		
		o.put("key", null);
		assertEquals(def, JSONObjectUtils.getURI(o, "key", def));
		
		URI value = URI.create("https://example.com");
		o.put("key", value.toString());
		assertEquals(value, JSONObjectUtils.getURI(o, "key", null));
		
		assertEquals(value, JSONObjectUtils.getURI(o, "key", def));
	}
	
	
	public void testGetURL_defaultValue()
		throws ParseException, MalformedURLException {
		
		JSONObject o = new JSONObject();
		assertNull(JSONObjectUtils.getURL(o, "key", null));
		
		URL def = new URL("https://c2id.com");
		assertEquals(def, JSONObjectUtils.getURL(o, "key", def));
		
		o.put("key", null);
		assertEquals(def, JSONObjectUtils.getURL(o, "key", def));
		
		URL value = new URL("https://example.com");
		o.put("key", value.toString());
		assertEquals(value, JSONObjectUtils.getURL(o, "key", null));
		
		assertEquals(value, JSONObjectUtils.getURL(o, "key", def));
	}


	// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/460/
	// Java URI implements https://www.rfc-editor.org/rfc/rfc2396#section-2.4.3
	public void testGetURI_withUnencodedCurlyBrackets() {

		JSONObject o = new JSONObject();
		o.put("some_uri", "https://login.microsoftonline.com/{tenantid}/v2.0");

		try {
			JSONObjectUtils.getURI(o, "some_uri");
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal character in path at index 34: https://login.microsoftonline.com/{tenantid}/v2.0", e.getMessage());
		}
	}


	// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/460/
	// Java URI implements https://www.rfc-editor.org/rfc/rfc2396#section-2.4.3
	public void testGetURI_withEncodedCurlyBrackets() throws ParseException, UnsupportedEncodingException {

		JSONObject o = new JSONObject();
		o.put("some_uri", "https://login.microsoftonline.com/%7Btenantid%7D/v2.0");

		URI uri = JSONObjectUtils.getURI(o, "some_uri");
		assertEquals("https://login.microsoftonline.com/%7Btenantid%7D/v2.0", uri.toString());

		String decodePath = URLDecoder.decode(uri.getPath(), "UTF-8");
		assertEquals("/{tenantid}/v2.0", decodePath);
	}
	
	
	public void testGetStringArray_defaultValue()
		throws ParseException {
		
		JSONObject o = new JSONObject();
		assertNull(JSONObjectUtils.getStringArray(o, "key", null));
		
		String[] def = {};
		Assert.assertArrayEquals(def, JSONObjectUtils.getStringArray(o, "key", def));
		
		o.put("key", null);
		Assert.assertArrayEquals(def, JSONObjectUtils.getStringArray(o, "key", def));
		
		JSONArray value = new JSONArray();
		value.add("a");
		value.add("b");
		o.put("key", value);
		Assert.assertArrayEquals(new String[]{"a", "b"}, JSONObjectUtils.getStringArray(o, "key", null));
		
		Assert.assertArrayEquals(new String[]{"a", "b"}, JSONObjectUtils.getStringArray(o, "key", def));
	}
	
	
	public void testGetJSONArray_defaultValue()
		throws ParseException {
		
		JSONObject o = new JSONObject();
		assertNull(JSONObjectUtils.getJSONArray(o, "key", null));
		
		JSONArray def = new JSONArray();
		assertEquals(def, JSONObjectUtils.getJSONArray(o, "key", def));
		
		o.put("key", null);
		assertEquals(def, JSONObjectUtils.getJSONArray(o, "key", def));
		
		JSONArray value = new JSONArray();
		value.add("a");
		value.add("b");
		o.put("key", value);
		assertEquals(value, JSONObjectUtils.getJSONArray(o, "key", null));
		
		assertEquals(value, JSONObjectUtils.getJSONArray(o, "key", def));
	}
	
	
	public void testGetList_defaultValue()
		throws ParseException {
		
		JSONObject o = new JSONObject();
		assertNull(JSONObjectUtils.getList(o, "key", null));
		
		List<Object> def = Collections.emptyList();
		assertEquals(def, JSONObjectUtils.getList(o, "key", def));
		
		o.put("key", null);
		assertEquals(def, JSONObjectUtils.getList(o, "key", def));
		
		JSONArray value = new JSONArray();
		value.add("a");
		value.add("b");
		o.put("key", value);
		assertEquals(Arrays.asList("a", "b"), JSONObjectUtils.getList(o, "key", null));
		
		assertEquals(Arrays.asList("a", "b"), JSONObjectUtils.getList(o, "key", def));
	}
	
	
	public void testGetStringList_defaultValue()
		throws ParseException {
		
		JSONObject o = new JSONObject();
		assertNull(JSONObjectUtils.getStringList(o, "key", null));
		
		List<String> def = Collections.emptyList();
		assertEquals(def, JSONObjectUtils.getStringList(o, "key", def));
		
		o.put("key", null);
		assertEquals(def, JSONObjectUtils.getStringList(o, "key", def));
		
		JSONArray value = new JSONArray();
		value.add("a");
		value.add("b");
		o.put("key", value);
		assertEquals(Arrays.asList("a", "b"), JSONObjectUtils.getStringList(o, "key", null));
		
		assertEquals(Arrays.asList("a", "b"), JSONObjectUtils.getStringList(o, "key", def));
	}
	
	
	public void testGetStringSet_defaultValue()
		throws ParseException {
		
		JSONObject o = new JSONObject();
		assertNull(JSONObjectUtils.getStringSet(o, "key", null));
		
		Set<String> def = Collections.emptySet();
		assertEquals(def, JSONObjectUtils.getStringSet(o, "key", def));
		
		o.put("key", null);
		assertEquals(def, JSONObjectUtils.getStringSet(o, "key", def));
		
		JSONArray value = new JSONArray();
		value.add("a");
		value.add("b");
		o.put("key", value);
		assertEquals(new HashSet<>(Arrays.asList("a", "b")), JSONObjectUtils.getStringSet(o, "key", null));
		
		assertEquals(new HashSet<>(Arrays.asList("a", "b")), JSONObjectUtils.getStringSet(o, "key", def));
	}
	
	
	public void testGetJSONObject_defaultValue()
		throws ParseException {
		
		JSONObject o = new JSONObject();
		assertNull(JSONObjectUtils.getJSONObject(o, "key", null));
		
		JSONObject def = new JSONObject();
		assertEquals(def, JSONObjectUtils.getJSONObject(o, "key", def));
		
		o.put("key", null);
		assertEquals(def, JSONObjectUtils.getJSONObject(o, "key", def));
		
		JSONObject value = new JSONObject();
		o.put("key", value);
		assertEquals(value, JSONObjectUtils.getJSONObject(o, "key", null));
		
		assertEquals(value, JSONObjectUtils.getJSONObject(o, "key", def));
	}
	
	
	public void testJWTClaimsSetToJSONObject_null() {
		
		assertNull(JSONObjectUtils.toJSONObject((JWTClaimsSet) null));
	}
	
	
	public void testJWTClaimsSetToJSONObject_empty() {
		
		assertTrue(JSONObjectUtils.toJSONObject(new JWTClaimsSet.Builder().build()).isEmpty());
	}
	
	
	public void testJWTClaimsSetToJSONObject_convert()
		throws ParseException, java.text.ParseException {
		
		// Date with second resolution
		Date iat = DateUtils.fromSecondsSinceEpoch(DateUtils.toSecondsSinceEpoch(new Date()));
		
		Map<String, Object> jsonObject = new HashMap<>();
		jsonObject.put("key-1", "value-1");
		
		JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.issueTime(iat)
			.claim("obj", jsonObject)
			.build();
		
		JSONObject out = JSONObjectUtils.toJSONObject(jwtClaimsSet);
		
		assertEquals(jwtClaimsSet.getSubject(), JSONObjectUtils.getString(out, "sub"));
		assertEquals(DateUtils.toSecondsSinceEpoch(jwtClaimsSet.getIssueTime()), JSONObjectUtils.getLong(out, "iat"));
		
		JSONObject obj = JSONObjectUtils.getJSONObject(out, "obj");
		assertEquals(jwtClaimsSet.getJSONObjectClaim("obj"), obj);
	}
	
	
	public void testJWTClaimsSetToJSONObjectScenario()
		throws ParseException, java.text.ParseException {
		
		Map<String,Object> actObject = new HashMap<>();
		actObject.put("sub", "bob");
		
		actObject = com.nimbusds.jose.util.JSONObjectUtils.parse(JSONObject.toJSONString(actObject));
		
		JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.claim("act", actObject)
			.claim("scope", Arrays.asList("read", "write"))
			.build();
		
		JSONObject jsonObject = new JSONObject(jwtClaimsSet.toJSONObject());
		
		// sub
		assertEquals("alice", JSONObjectUtils.getString(jsonObject, "sub"));
		
		// act
		Actor actor = Actor.parseTopLevel(jsonObject);
		assertEquals("bob", actor.getSubject().getValue());
		
		JSONObject actJSONObject = JSONObjectUtils.getJSONObject(jsonObject, "act");
		assertEquals("bob", JSONObjectUtils.getString(actJSONObject, "sub"));
		assertEquals(1, actJSONObject.size());
		
		// scope
		JSONArray jsonArray = JSONObjectUtils.getJSONArray(jsonObject, "scope");
		assertEquals(Arrays.asList("read", "write"), JSONArrayUtils.toStringList(jsonArray));
	}
	
	
	public void testJWKSetToJSONObject_null() {
		
		assertNull(JSONObjectUtils.toJSONObject((JWKSet) null));
	}
	
	
	public void testJWKSetToJSONObject_convert()
		throws JOSEException {
		
		OctetSequenceKey oct = new OctetSequenceKeyGenerator(256)
			.keyIDFromThumbprint(true)
			.generate();
		
		JWKSet jwkSet = new JWKSet(oct);
		
		JSONObject o = JSONObjectUtils.toJSONObject(jwkSet);
		
		assertEquals(jwkSet.toString(false), o.toJSONString());
	}
}
