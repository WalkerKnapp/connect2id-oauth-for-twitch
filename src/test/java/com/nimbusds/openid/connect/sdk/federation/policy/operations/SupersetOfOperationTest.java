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
import com.nimbusds.openid.connect.sdk.federation.policy.language.OperationName;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;


public class SupersetOfOperationTest extends TestCase {
	
	
	public void testSuperset() throws PolicyViolationException {
		
		List<String> param = Arrays.asList("ES256", "RS256");
		
		SupersetOfOperation operation = new SupersetOfOperation();
		assertEquals(new OperationName("superset_of"), operation.getOperationName());
		operation.configure(param);
		assertEquals(param, operation.getStringListConfiguration());
		
		List<String> stringList = Arrays.asList("ES256", "ES384", "RS256", "RS512");
		
		assertEquals(stringList, operation.apply(stringList));
	}


	public void testSupersetOneValue() throws PolicyViolationException {

		List<String> param = Collections.singletonList("ES256");

		SupersetOfOperation operation = new SupersetOfOperation();
		assertEquals(new OperationName("superset_of"), operation.getOperationName());
		operation.configure(param);
		assertEquals(param, operation.getStringListConfiguration());

		List<String> stringList = Collections.singletonList("ES256");

		assertEquals(stringList, operation.apply(stringList));
	}


	public void testSupersetOneValue_1() throws PolicyViolationException {

		List<String> param = Collections.singletonList("ES256");

		SupersetOfOperation operation = new SupersetOfOperation();
		assertEquals(new OperationName("superset_of"), operation.getOperationName());
		operation.configure(param);
		assertEquals(param, operation.getStringListConfiguration());

		List<String> stringList = Arrays.asList("ES256", "ES384", "ES512");

		assertEquals(stringList, operation.apply(stringList));
	}


	public void testSupersetEmptyValue() {

		List<String> param = Arrays.asList("ES256", "RS256");

		SupersetOfOperation operation = new SupersetOfOperation();
		assertEquals(new OperationName("superset_of"), operation.getOperationName());
		operation.configure(param);
		assertEquals(param, operation.getStringListConfiguration());

		try {
			operation.apply(Collections.<String>emptyList());
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Missing values: [ES256, RS256]", e.getMessage());
		}
	}

	public void testSuperset_missingValue() {

		List<String> param = Arrays.asList("ES256", "RS256");

		SupersetOfOperation operation = new SupersetOfOperation();
		assertEquals(new OperationName("superset_of"), operation.getOperationName());
		operation.configure(param);
		assertEquals(param, operation.getStringListConfiguration());

		List<String> stringList = Collections.singletonList("ES256");

		try {
			assertEquals(stringList, operation.apply(stringList));
		} catch (PolicyViolationException e) {
			assertEquals("Missing values: [RS256]", e.getMessage());
		}
	}

	public void testSuperset_missingTwoValues() {

		List<String> param = Arrays.asList("ES256", "RS256");

		SupersetOfOperation operation = new SupersetOfOperation();
		assertEquals(new OperationName("superset_of"), operation.getOperationName());
		operation.configure(param);
		assertEquals(param, operation.getStringListConfiguration());

		List<String> stringList = Collections.singletonList("PS256");

		try {
			assertEquals(stringList, operation.apply(stringList));
		} catch (PolicyViolationException e) {
			assertEquals("Missing values: [ES256, RS256]", e.getMessage());
		}
	}

	
	public void testSupersetNullValue() {
		
		List<String> param = Arrays.asList("ES256", "RS256");
		
		SupersetOfOperation operation = new SupersetOfOperation();
		assertEquals(new OperationName("superset_of"), operation.getOperationName());
		operation.configure(param);
		assertEquals(param, operation.getStringListConfiguration());
		
		try {
			operation.apply(null);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Value not specified", e.getMessage());
		}
	}
	
	
	public void testNotInit()
		throws PolicyViolationException{
		
		try {
			new SupersetOfOperation().apply(null);
			fail();
		} catch (IllegalStateException e) {
			assertEquals("The policy is not initialized", e.getMessage());
		}
	}
	
	
	public void testParseConfiguration()
		throws ParseException {
		
		List<String> param = Arrays.asList("ES256", "RS256");
		
		SupersetOfOperation operation = new SupersetOfOperation();
		operation.parseConfiguration((Object)param);
		assertEquals(param, operation.getStringListConfiguration());
		
		assertEquals(operation.getOperationName().getValue(), operation.toJSONObjectEntry().getKey());
		assertEquals(param, operation.toJSONObjectEntry().getValue());
	}
	
	
	public void testMerge() throws PolicyViolationException {
		
		List<String> p1 = Arrays.asList("openid", "eduperson", "phone");
		List<String> p2 = Arrays.asList("openid", "eduperson", "address");
		
		SupersetOfOperation o1 = new SupersetOfOperation();
		o1.configure(p1);
		SupersetOfOperation o2 = new SupersetOfOperation();
		o2.configure(p2);
		
		assertEquals(Arrays.asList("openid", "eduperson"), ((SupersetOfOperation)o1.merge(o2)).getStringListConfiguration());
	}
	
	
	public void testMerge_noIntersection() throws PolicyViolationException {
		
		List<String> p1 = Arrays.asList("openid", "eduperson", "phone");
		List<String> p2 = Arrays.asList("email", "address");
		
		SupersetOfOperation o1 = new SupersetOfOperation();
		o1.configure(p1);
		SupersetOfOperation o2 = new SupersetOfOperation();
		o2.configure(p2);
		
		assertEquals(Collections.emptyList(), ((SupersetOfOperation)o1.merge(o2)).getStringListConfiguration());
	}
}
