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


import java.util.*;

import junit.framework.TestCase;


public class MultivaluedMapUtilsTest extends TestCase {
	
	
	public void testToSingleValuedMap_null() {
		
		assertNull(MultivaluedMapUtils.toSingleValuedMap(null));
	}
	
	
	public void testToSingleValuedMap_oneEntry_singleValued_null() {
		
		Map<String,List<String>> in = new HashMap<>();
		in.put("a", Collections.singletonList((String)null));
		
		Map<String,String> out = MultivaluedMapUtils.toSingleValuedMap(in);
		assertNull(out.get("a"));
		assertEquals(1, out.size());
	}
	
	
	public void testToSingleValuedMap_oneEntry_singleValued() {
		
		Map<String,List<String>> in = new HashMap<>();
		in.put("a", Collections.singletonList("1"));
		
		Map<String,String> out = MultivaluedMapUtils.toSingleValuedMap(in);
		assertEquals("1", out.get("a"));
		assertEquals(1, out.size());
	}
	
	
	public void testToSingleValuedMap_oneEntry_twoValues() {
		
		Map<String,List<String>> in = new HashMap<>();
		in.put("a", Arrays.asList("1", "2"));
		
		Map<String,String> out = MultivaluedMapUtils.toSingleValuedMap(in);
		assertEquals("1", out.get("a"));
		assertEquals(1, out.size());
	}
	
	
	public void testToSingleValuedMap_oneEntry_threeValues() {
		
		Map<String,List<String>> in = new HashMap<>();
		in.put("a", Arrays.asList("1", "2", "3"));
		
		Map<String,String> out = MultivaluedMapUtils.toSingleValuedMap(in);
		assertEquals("1", out.get("a"));
		assertEquals(1, out.size());
	}
	
	
	public void testGetKeysWithMoreThanOneValue_null() {
		
		assertTrue(MultivaluedMapUtils.getKeysWithMoreThanOneValue(null, null).isEmpty());
	}
	
	
	public void testGetKeysWithMoreThanOneValue_empty() {
		
		assertTrue(MultivaluedMapUtils.getKeysWithMoreThanOneValue(new HashMap<String,List<String>>(), null).isEmpty());
	}
	
	
	public void testGetKeysWithMoreThanOneValue_none() {
		
		Map<String,List<String>> params = new HashMap<>();
		params.put("client_id", Collections.singletonList("123"));
		params.put("response_type", Collections.singletonList("code"));
		params.put("scope", Collections.singletonList("read"));
		
		assertTrue(MultivaluedMapUtils.getKeysWithMoreThanOneValue(params, null).isEmpty());
	}
	
	
	public void testGetKeysWithMoreThanOneValue_one() {
		
		Map<String,List<String>> params = new HashMap<>();
		params.put("client_id", Arrays.asList("123", "456"));
		params.put("response_type", Collections.singletonList("code"));
		params.put("scope", Collections.singletonList("read"));
		
		Set<String> found = MultivaluedMapUtils.getKeysWithMoreThanOneValue(params, null);
		assertEquals(Collections.singleton("client_id"), found);
	}

	
	public void testGetKeysWithMoreThanOneValue_two() {
		
		Map<String,List<String>> params = new HashMap<>();
		params.put("client_id", Arrays.asList("123", "456"));
		params.put("response_type", Arrays.asList("code", "token"));
		params.put("scope", Collections.singletonList("read"));
		
		Set<String> found = MultivaluedMapUtils.getKeysWithMoreThanOneValue(params, null);
		assertEquals(new HashSet<>(Arrays.asList("client_id", "response_type")), found);
	}

	public void testGetKeysWithMoreThanOneValue_duplicates() {

		Map<String,List<String>> params = new HashMap<>();
		params.put("client_id", Arrays.asList("123", "123"));
		params.put("response_type", Arrays.asList("code", "code"));
		params.put("redirect_uri", Arrays.asList("http://localhost", "http://localhost"));
		params.put("scope", Collections.singletonList("read"));

		assertTrue(MultivaluedMapUtils.getKeysWithMoreThanOneValue(params, null).isEmpty());
	}

	public void testGetKeysWithMoreThanOneValue_exception() {
		
		Map<String,List<String>> params = new HashMap<>();
		params.put("client_id", Collections.singletonList("123"));
		params.put("response_type", Collections.singletonList("code"));
		params.put("scope", Collections.singletonList("read"));
		params.put("resource", Arrays.asList("a", "b"));
		
		assertTrue(MultivaluedMapUtils.getKeysWithMoreThanOneValue(params, Collections.singleton("resource")).isEmpty());
	}
	
	
	public void testGetKeysWithMoreThanOneValue_one_exception() {
		
		Map<String,List<String>> params = new HashMap<>();
		params.put("client_id", Arrays.asList("123", "456"));
		params.put("response_type", Collections.singletonList("code"));
		params.put("scope", Collections.singletonList("read"));
		params.put("resource", Arrays.asList("a", "b"));
		
		Set<String> found = MultivaluedMapUtils.getKeysWithMoreThanOneValue(params, Collections.singleton("resource"));
		assertEquals(Collections.singleton("client_id"), found);
	}
}
