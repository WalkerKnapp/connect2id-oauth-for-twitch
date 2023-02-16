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

package com.nimbusds.openid.connect.sdk.federation.policy.operations;


import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.federation.policy.language.OperationName;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;


public class ValueOperationTest extends TestCase {
	
	
	public void testOperationName() {
		
		ValueOperation valueOperation = new ValueOperation();
		assertEquals(new OperationName("value"), valueOperation.getOperationName());
	}
	
	
	public void testBooleanParam() {
		
		ValueOperation valueOperation = new ValueOperation();
		valueOperation.configure(true);
		assertTrue(valueOperation.getBooleanConfiguration());
		
		assertEquals(valueOperation.getOperationName().getValue(), valueOperation.toJSONObjectEntry().getKey());
		assertEquals(true, valueOperation.toJSONObjectEntry().getValue());
		
		assertTrue((Boolean) valueOperation.apply(null));
		assertTrue((Boolean) valueOperation.apply(true));
		assertTrue((Boolean) valueOperation.apply(false));
	}
	

	public void testNumberParam() {
		
		ValueOperation valueOperation = new ValueOperation();
		valueOperation.configure(200);
		assertEquals(200, valueOperation.getNumberConfiguration());
		
		assertEquals(valueOperation.getOperationName().getValue(), valueOperation.toJSONObjectEntry().getKey());
		assertEquals(200, valueOperation.toJSONObjectEntry().getValue());
		
		assertEquals(200, valueOperation.apply(null));
		assertEquals(200, valueOperation.apply("abc"));
	}
	

	public void testStringParam() {
		
		ValueOperation valueOperation = new ValueOperation();
		String stringParam = "support@federation.example.com";
		valueOperation.configure(stringParam);
		assertEquals(stringParam, valueOperation.getStringConfiguration());
		
		assertEquals(valueOperation.getOperationName().getValue(), valueOperation.toJSONObjectEntry().getKey());
		assertEquals("support@federation.example.com", valueOperation.toJSONObjectEntry().getValue());
		
		assertEquals(stringParam, valueOperation.apply(null));
		assertEquals(stringParam, valueOperation.apply("abc"));
	}
	

	public void testStringListParam() {
		
		ValueOperation valueOperation = new ValueOperation();
		List<String> stringListParam = Arrays.asList("support@federation.example.com", "admin@federation.example.com");
		valueOperation.configure(stringListParam);
		assertEquals(stringListParam, valueOperation.getStringListConfiguration());
		
		assertEquals(valueOperation.getOperationName().getValue(), valueOperation.toJSONObjectEntry().getKey());
		assertEquals(stringListParam, valueOperation.toJSONObjectEntry().getValue());
		
		assertEquals(stringListParam, valueOperation.apply(null));
		assertEquals(stringListParam, valueOperation.apply(Collections.singletonList("abc")));
	}
	
	
	public void testJSONObjectParam() {
		
		ValueOperation valueOperation = new ValueOperation();
		JSONObject jsonObjectParam = new JSONObject();
		jsonObjectParam.put("key-1", "value-1");
		valueOperation.configure(jsonObjectParam);
		assertEquals(jsonObjectParam, valueOperation.getJSONObjectConfiguration());
		
		assertEquals(valueOperation.getOperationName().getValue(), valueOperation.toJSONObjectEntry().getKey());
		assertEquals(jsonObjectParam, valueOperation.toJSONObjectEntry().getValue());
		
		assertEquals(jsonObjectParam, valueOperation.apply(null));
		assertEquals(jsonObjectParam, valueOperation.apply(Collections.singletonList("abc")));
	}
	
	
	public void testIllegalState() {
		
		try {
			new ValueOperation().apply(null);
			fail();
		} catch (IllegalStateException e) {
			assertEquals("The policy is not initialized", e.getMessage());
		}
	}
	
	
	public void testParseBooleanParam() throws ParseException {
		
		ValueOperation valueOperation = new ValueOperation();
		valueOperation.parseConfiguration((Object)true);
		assertTrue(valueOperation.getBooleanConfiguration());
	}
	
	
	public void testParseStringParam() throws ParseException {
		
		ValueOperation valueOperation = new ValueOperation();
		String stringParam = "support@federation.example.com";
		valueOperation.parseConfiguration((Object)stringParam);
		assertEquals(stringParam, valueOperation.getStringConfiguration());
	}
	
	
	public void testParseStringListParam() throws ParseException {
		
		ValueOperation valueOperation = new ValueOperation();
		List<String> stringListParam = Arrays.asList("support@federation.example.com", "admin@federation.example.com");
		valueOperation.parseConfiguration((Object)stringListParam);
		assertEquals(stringListParam, valueOperation.getStringListConfiguration());
	}
	
	
	public void testParseJSONObjectParam() throws ParseException {
		
		JSONObject jsonObjectParam = new JSONObject();
		jsonObjectParam.put("key-1", "value-1");
		
		ValueOperation valueOperation = new ValueOperation();
		
		valueOperation.parseConfiguration((Object)jsonObjectParam);
		assertEquals(jsonObjectParam, valueOperation.getJSONObjectConfiguration());
	}
	
	
	public void testMerge_boolean() throws PolicyViolationException {
	
		ValueOperation o1 = new ValueOperation();
		o1.configure(true);
		
		ValueOperation o2 = new ValueOperation();
		o2.configure(true);
		
		assertTrue(((ValueOperation)o1.merge(o2)).getBooleanConfiguration());
		
		ValueOperation o3 = new ValueOperation();
		o3.configure(false);
		
		try {
			o1.merge(o3);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Value mismatch", e.getMessage());
		}
	}
	
	
	public void testMerge_number() throws PolicyViolationException {
	
		ValueOperation o1 = new ValueOperation();
		o1.configure(400);
		assertEquals(400, o1.getNumberConfiguration());
		
		ValueOperation o2 = new ValueOperation();
		o2.configure(400);
		assertEquals(400, o2.getNumberConfiguration());
		
		assertEquals(o1.getNumberConfiguration(), o2.getNumberConfiguration());
		
		ValueOperation merged = (ValueOperation)o1.merge(o2);
		
		assertEquals(400, merged.getNumberConfiguration());
		
		ValueOperation o3 = new ValueOperation();
		o3.configure(100);
		
		try {
			o1.merge(o3);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Value mismatch", e.getMessage());
		}
	}
	
	
	public void testMerge_string() throws PolicyViolationException {
	
		ValueOperation o1 = new ValueOperation();
		o1.configure("a");
		
		ValueOperation o2 = new ValueOperation();
		o2.configure("a");
		
		assertEquals("a", ((ValueOperation)o1.merge(o2)).getStringConfiguration());
		
		ValueOperation o3 = new ValueOperation();
		o3.configure("b");
		
		try {
			o1.merge(o3);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Value mismatch", e.getMessage());
		}
	}
	
	
	public void testMerge_stringList() throws PolicyViolationException {
	
		ValueOperation o1 = new ValueOperation();
		o1.configure(Arrays.asList("a", "b"));
		
		ValueOperation o2 = new ValueOperation();
		o2.configure(Arrays.asList("a", "b"));
		
		assertEquals(Arrays.asList("a", "b"), ((ValueOperation)o1.merge(o2)).getStringListConfiguration());
		
		ValueOperation o3 = new ValueOperation();
		o3.configure(Arrays.asList("c", "d"));
		
		try {
			o1.merge(o3);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Value mismatch", e.getMessage());
		}
	}
	
	
	public void testMerge_jsonObject() throws PolicyViolationException {
		
		JSONObject jsonObject_1 = new JSONObject();
		jsonObject_1.put("key-1", "value-1");
		
		JSONObject jsonObject_2 = new JSONObject();
		jsonObject_2.put("key-2", "value-2");
		
		ValueOperation o1 = new ValueOperation();
		o1.configure(jsonObject_1);
		
		ValueOperation o2 = new ValueOperation();
		o2.configure(jsonObject_1);
		
		assertEquals(jsonObject_1, ((ValueOperation)o1.merge(o2)).getJSONObjectConfiguration());
		
		ValueOperation o3 = new ValueOperation();
		o3.configure(jsonObject_2);
		
		try {
			o1.merge(o3);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Value mismatch", e.getMessage());
		}
	}
}
