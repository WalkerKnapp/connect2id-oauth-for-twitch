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

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import com.nimbusds.openid.connect.sdk.federation.policy.language.OperationName;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;


public class AddOperationTest extends TestCase {
	

	public void testStringParam() {
		
		AddOperation addOperation = new AddOperation();
		assertEquals(new OperationName("add"), addOperation.getOperationName());
		
		String stringParam = "support@federation.example.com";
		
		addOperation.configure(stringParam);
		
		assertEquals(addOperation.getOperationName().getValue(), addOperation.toJSONObjectEntry().getKey());
		assertEquals(stringParam, addOperation.toJSONObjectEntry().getValue());
		
		assertEquals(Collections.singletonList(stringParam), addOperation.apply(null));
		assertEquals(Collections.singletonList(stringParam), addOperation.apply(Collections.<String>emptyList()));
		assertEquals(Arrays.asList("support@example.com", stringParam), addOperation.apply(Collections.singletonList("support@example.com")));
		assertEquals(Arrays.asList("admin@example.com", "support@example.com", stringParam), addOperation.apply(Arrays.asList("admin@example.com", "support@example.com")));

		// Must not add value already present
		assertEquals(Collections.singletonList(stringParam), addOperation.apply(Collections.singletonList(stringParam)));
	}
	

	public void testStringListParam() {
		
		AddOperation addOperation = new AddOperation();
		assertEquals(new OperationName("add"), addOperation.getOperationName());
		
		List<String> stringListParam = Arrays.asList("support@federation.example.com", "admin@federation.example.com");
		
		addOperation.configure(stringListParam);
		
		assertEquals(addOperation.getOperationName().getValue(), addOperation.toJSONObjectEntry().getKey());
		assertEquals(stringListParam, addOperation.toJSONObjectEntry().getValue());
		
		assertEquals(stringListParam, addOperation.apply(null));
		assertEquals(stringListParam, addOperation.apply(Collections.<String>emptyList()));
		assertEquals(Arrays.asList("support@example.com", stringListParam.get(0), stringListParam.get(1)), addOperation.apply(Collections.singletonList("support@example.com")));
		assertEquals(Arrays.asList("admin@example.com", "support@example.com", stringListParam.get(0), stringListParam.get(1)), addOperation.apply(Arrays.asList("admin@example.com", "support@example.com")));

		// Must not add value already present
		assertEquals(stringListParam, addOperation.apply(Collections.singletonList("support@federation.example.com")));
	}


	public void testResultImmutable() {

		AddOperation addOperation = new AddOperation();
		addOperation.configure("c");

		List<String> result = addOperation.apply(Arrays.asList("a", "b"));

		try {
			result.add("d");
			fail();
		} catch (UnsupportedOperationException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testIllegalState() {
		
		try {
			new AddOperation().apply(null);
			fail();
		} catch (IllegalStateException e) {
			assertEquals("The policy is not initialized", e.getMessage());
		}
	}
	
	
	public void testParseConfig_string()
		throws ParseException {
		
		AddOperation addOperation = new AddOperation();
		addOperation.parseConfiguration("support@federation.example.com");
		assertEquals("support@federation.example.com", addOperation.getStringConfiguration());
	}
	
	
	public void testParseConfig_stringList()
		throws ParseException {
		
		AddOperation addOperation = new AddOperation();
		String json = "[\"support@federation.example.com\", \"admin@federation.example.com\"]";
		addOperation.parseConfiguration(JSONArrayUtils.parse(json));
		assertEquals(Arrays.asList("support@federation.example.com", "admin@federation.example.com"), addOperation.getStringListConfiguration());
	}
	
	
	public void testParseConfig_stringList_itemNotString() {
		
		AddOperation addOperation = new AddOperation();
		String json = "[\"support@federation.example.com\", 1]";
		try {
			addOperation.parseConfiguration(JSONArrayUtils.parse(json));
			fail();
		} catch (ParseException e) {
			assertEquals("Item not a string", e.getMessage());
		}
	}
	
	
	public void testMerge_string_string() throws PolicyViolationException {
		
		AddOperation o1 = new AddOperation();
		o1.configure("a");
		
		AddOperation o2 = new AddOperation();
		o2.configure("b");
		
		assertEquals(Arrays.asList("a", "b"), ((AddOperation)o1.merge(o2)).getStringListConfiguration());
	}
	
	
	public void testMerge_string_stringList() throws PolicyViolationException {
		
		AddOperation o1 = new AddOperation();
		o1.configure("a");
		
		AddOperation o2 = new AddOperation();
		o2.configure(Arrays.asList("b", "c"));
		
		assertEquals(Arrays.asList("a", "b", "c"), ((AddOperation)o1.merge(o2)).getStringListConfiguration());
	}
	
	
	public void testMerge_stringList_stringList() throws PolicyViolationException {
		
		AddOperation o1 = new AddOperation();
		o1.configure(Arrays.asList("a", "b"));
		
		AddOperation o2 = new AddOperation();
		o2.configure(Arrays.asList("c", "d"));
		
		assertEquals(Arrays.asList("a", "b", "c", "d"), ((AddOperation)o1.merge(o2)).getStringListConfiguration());
	}
}
