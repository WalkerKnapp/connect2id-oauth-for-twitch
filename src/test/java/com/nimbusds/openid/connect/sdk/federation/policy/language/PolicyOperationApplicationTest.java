/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.federation.policy.language;


import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.sdk.federation.policy.operations.*;


public class PolicyOperationApplicationTest extends TestCase {
	
	
	public void testApply_subsetOf() throws PolicyViolationException {
		
		List<String> param = Arrays.asList("code", "code token", "code id_token");
		SubsetOfOperation operation = new SubsetOfOperation();
		operation.configure(param);
		
		List<String> out = (List<String>)PolicyOperationApplication.apply(operation, Collections.singletonList("code"));
		assertEquals(Collections.singletonList("code"), out);
	}
	
	
	public void testApply_subsetOf_empty() throws PolicyViolationException {
		
		List<String> param = Arrays.asList("code", "code token", "code id_token");
		SubsetOfOperation operation = new SubsetOfOperation();
		operation.configure(param);
		
		List<String> out = (List<String>)PolicyOperationApplication.apply(operation, Collections.singletonList("id_token"));
		assertEquals(Collections.emptyList(), out);
	}
	
	
	public void testApply_subsetOf_badType() {
		
		List<String> param = Arrays.asList("code", "code token", "code id_token");
		SubsetOfOperation operation = new SubsetOfOperation();
		operation.configure(param);
		
		try {
			PolicyOperationApplication.apply(operation, true);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("The value must be a string list", e.getMessage());
		}
	}
	
	
	public void testApply_oneOf() throws PolicyViolationException {
		
		List<String> param = Arrays.asList("ES256", "ES384", "ES512");
		
		OneOfOperation operation = new OneOfOperation();
		operation.configure(param);
		
		String out = (String)PolicyOperationApplication.apply(operation, "ES256");
		assertEquals("ES256", out);
	}
	
	
	public void testApply_oneOf_violation() {
		
		List<String> param = Arrays.asList("ES256", "ES384", "ES512");
		
		OneOfOperation operation = new OneOfOperation();
		operation.configure(param);
		
		try {
			PolicyOperationApplication.apply(operation, "RS256");
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Value RS256 not in policy list: [ES256, ES384, ES512]", e.getMessage());
		}
	}
	
	
	public void testApply_oneOf_badType() {
		
		List<String> param = Arrays.asList("ES256", "ES384", "ES512");
		
		OneOfOperation operation = new OneOfOperation();
		operation.configure(param);
		
		try {
			PolicyOperationApplication.apply(operation, true);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("The value must be a string", e.getMessage());
		}
	}
	
	
	public void testApply_oneOf_badTypeAlt() {
		
		List<String> param = Arrays.asList("ES256", "ES384", "ES512");
		
		OneOfOperation operation = new OneOfOperation();
		operation.configure(param);
		
		try {
			PolicyOperationApplication.apply(operation, Collections.singletonList("ES256"));
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("The value must be a string", e.getMessage());
		}
	}
	
	
	public void testApply_supersetOf() throws PolicyViolationException {
		
		List<String> param = Arrays.asList("ES256", "RS256");
		
		SupersetOfOperation operation = new SupersetOfOperation();
		operation.configure(param);
		
		List<String> out = (List<String>)PolicyOperationApplication.apply(operation, Arrays.asList("ES256", "RS256", "HS256"));
		assertEquals(Arrays.asList("ES256", "RS256", "HS256"), out);
	}
	
	
	public void testApply_supersetOf_violation() {
		
		List<String> param = Arrays.asList("ES256", "RS256");
		
		SupersetOfOperation operation = new SupersetOfOperation();
		operation.configure(param);
		
		try {
			PolicyOperationApplication.apply(operation, Arrays.asList("RS256", "HS256"));
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Missing values: [ES256]", e.getMessage());
		}
	}
	
	
	public void testApply_add() throws PolicyViolationException {
		
		AddOperation operation = new AddOperation();
		String stringParam = "support@federation.example.com";
		operation.configure(stringParam);
		
		List<String> out = (List<String>)PolicyOperationApplication.apply(operation, Collections.singletonList("support@example.com"));
		assertEquals(Arrays.asList("support@example.com", "support@federation.example.com"), out);
	}
	
	
	public void testApply_add_badType() {
		
		AddOperation operation = new AddOperation();
		String stringParam = "support@federation.example.com";
		operation.configure(stringParam);
		
		try {
			PolicyOperationApplication.apply(operation, true);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("The value must be a string list", e.getMessage());
		}
	}
	
	
	public void testApply_value_booleanConfig() throws PolicyViolationException {
		
		ValueOperation operation = new ValueOperation();
		operation.configure(true);
		
		assertTrue((Boolean)PolicyOperationApplication.apply(operation, Boolean.TRUE));
		assertTrue((Boolean)PolicyOperationApplication.apply(operation, Boolean.FALSE));
		assertTrue((Boolean)PolicyOperationApplication.apply(operation, null));
		assertTrue((Boolean)PolicyOperationApplication.apply(operation, "some-string"));
		assertTrue((Boolean)PolicyOperationApplication.apply(operation, Collections.singletonList("some-value")));
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("key-1", "value-1");
		assertTrue((Boolean)PolicyOperationApplication.apply(operation, jsonObject));
	}
	
	
	public void testApply_value_jsonObjectConfig() throws PolicyViolationException {
		
		JSONObject jsonObjectParam = new JSONObject();
		jsonObjectParam.put("key-1", "value-1");
		
		ValueOperation operation = new ValueOperation();
		operation.configure(jsonObjectParam);
		
		assertEquals(jsonObjectParam, PolicyOperationApplication.apply(operation, Boolean.TRUE));
		assertEquals(jsonObjectParam, PolicyOperationApplication.apply(operation, Boolean.FALSE));
		assertEquals(jsonObjectParam, PolicyOperationApplication.apply(operation, null));
		assertEquals(jsonObjectParam, PolicyOperationApplication.apply(operation, "some-string"));
		assertEquals(jsonObjectParam, PolicyOperationApplication.apply(operation, Collections.singletonList("some-value")));
		assertEquals(jsonObjectParam, PolicyOperationApplication.apply(operation, jsonObjectParam));
	}
	
	
	public void testApply_default() throws PolicyViolationException {
		
		DefaultOperation operation = new DefaultOperation();
		operation.configure(true);
		
		assertTrue((Boolean) PolicyOperationApplication.apply(operation, null));
		assertTrue((Boolean) PolicyOperationApplication.apply(operation, true));
		assertFalse((Boolean) PolicyOperationApplication.apply(operation, false));
	}
	
	
	public void testApply_essential_boolean() throws PolicyViolationException {
		
		EssentialOperation operation = new EssentialOperation();
		operation.configure(true);
		
		assertTrue((Boolean) PolicyOperationApplication.apply(operation, true));
	}
	
	
	public void testApply_essential_boolean_violation() {
		
		EssentialOperation operation = new EssentialOperation();
		operation.configure(true);
		
		try {
			PolicyOperationApplication.apply(operation, null);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Essential parameter not present", e.getMessage());
		}
	}
}
