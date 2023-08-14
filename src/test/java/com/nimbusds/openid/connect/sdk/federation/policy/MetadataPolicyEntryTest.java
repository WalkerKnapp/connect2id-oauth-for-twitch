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

package com.nimbusds.openid.connect.sdk.federation.policy;


import java.util.*;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.federation.policy.language.OperationName;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.*;


public class MetadataPolicyEntryTest extends TestCase {
	
	
	public void testConstructor() throws PolicyViolationException {
		
		String paramName = "scope";
		SubsetOfOperation op1 = new SubsetOfOperation();
		op1.configure(Arrays.asList("openid", "eduperson", "phone"));
		List<PolicyOperation> ops = Collections.singletonList((PolicyOperation)op1);
		
		MetadataPolicyEntry entry = new MetadataPolicyEntry("scope", ops);
		
		assertEquals(paramName, entry.getKey());
		assertEquals(paramName, entry.getParameterName());
		
		assertEquals(ops, entry.getValue());
		assertEquals(ops, entry.getPolicyOperations());
		
		Map<OperationName,PolicyOperation> map = entry.getOperationsMap();
		assertEquals(op1, map.get(op1.getOperationName()));
		assertEquals(1, map.size());
		
		List<String> input = Arrays.asList("openid", "email");
		List<String> output = (List<String>)entry.apply(input);
		assertEquals(Collections.singletonList("openid"), output);
	}
	
	
	public void testEmpty() {
		
		MetadataPolicyEntry entry = new MetadataPolicyEntry("scope", null);
		
		assertEquals("scope", entry.getKey());
		assertEquals("scope", entry.getParameterName());
		
		assertNull(entry.getValue());
		assertNull(entry.getPolicyOperations());
		
		assertTrue(entry.getOperationsMap().isEmpty());
	}


	public void testSubsetOfSuperSetOfCombinationCannotEmulateEquality() throws ParseException, PolicyViolationException {

		String json =
			"{" +
			"\"subset_of\": [\"a\",\"b\"]," +
			"\"superset_of\": [\"a\",\"b\"]" +
			"}";

		JSONObject spec = JSONObjectUtils.parse(json);

		MetadataPolicyEntry policyEntry = MetadataPolicyEntry.parse("some_param", spec);

		// ok
		assertEquals(Arrays.asList("a", "b"), policyEntry.apply(Arrays.asList("a", "b")));

		// ok
		try {
			policyEntry.apply(Collections.singletonList("a"));
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Missing values: [b]", e.getMessage());
		}

		// input modified!
		assertEquals(Arrays.asList("a", "b"), policyEntry.apply(Arrays.asList("a", "b", "c")));
	}


	public void testValueOperation() throws ParseException, PolicyViolationException {

		String json =
			"{" +
			"\"value\": \"a\"" +
			"}";

		JSONObject spec = JSONObjectUtils.parse(json);

		MetadataPolicyEntry policyEntry = MetadataPolicyEntry.parse("some_param", spec);

		assertEquals("a", policyEntry.apply("b"));
		assertEquals("a", policyEntry.apply(null));
		assertEquals("a", policyEntry.apply("a"));
	}


	public void testValueOperation_ignoreOtherOps() throws PolicyViolationException {

		ValueOperation valueOperation = new ValueOperation();
		valueOperation.configure("a");

		DefaultOperation defaultOperation = new DefaultOperation();
		defaultOperation.configure("a");

		MetadataPolicyEntry policyEntry = new MetadataPolicyEntry(
			"some_param",
			Arrays.asList((PolicyOperation)valueOperation, (PolicyOperation)defaultOperation)
		);

		assertEquals("a", policyEntry.apply("b"));
		assertEquals("a", policyEntry.apply(null));
		assertEquals("a", policyEntry.apply("a"));
	}


	public void testEssentialOperation_voluntary_ignoreFollowingOpsWhenParamIsNull() throws PolicyViolationException {

		EssentialOperation essentialOperation = new EssentialOperation();
		essentialOperation.configure(false); // explicit voluntary

		// one_of
		OneOfOperation oneOfOperation = new OneOfOperation();
		oneOfOperation.configure(Arrays.asList("a", "b"));
		MetadataPolicyEntry policyEntry = new MetadataPolicyEntry(
			"some_param",
			Arrays.asList((PolicyOperation)essentialOperation, (PolicyOperation)oneOfOperation)
		);
		assertNull(policyEntry.apply(null));

		// superset_of
		SupersetOfOperation supersetOfOperation = new SupersetOfOperation();
		supersetOfOperation.configure(Arrays.asList("a", "b"));
		policyEntry = new MetadataPolicyEntry(
			"some_param",
			Arrays.asList((PolicyOperation)essentialOperation, (PolicyOperation)supersetOfOperation)
		);
		assertNull(policyEntry.apply(null));

		// subset_of
		SubsetOfOperation subsetOfOperation = new SubsetOfOperation();
		subsetOfOperation.configure(Arrays.asList("a", "b"));
		policyEntry = new MetadataPolicyEntry(
			"some_param",
			Arrays.asList((PolicyOperation)essentialOperation, (PolicyOperation)subsetOfOperation)
		);
		assertNull(policyEntry.apply(null));
	}


	public void testVoluntary_ignoreFollowingOpsWhenParamIsNull() throws PolicyViolationException {

		// one_of
		OneOfOperation oneOfOperation = new OneOfOperation();
		oneOfOperation.configure(Arrays.asList("a", "b"));
		MetadataPolicyEntry policyEntry = new MetadataPolicyEntry(
			"some_param",
			Collections.singletonList((PolicyOperation) oneOfOperation)
		);
		assertNull(policyEntry.apply(null));

		// superset_of
		SupersetOfOperation supersetOfOperation = new SupersetOfOperation();
		supersetOfOperation.configure(Arrays.asList("a", "b"));
		policyEntry = new MetadataPolicyEntry(
			"some_param",
			Collections.singletonList((PolicyOperation) supersetOfOperation)
		);
		assertNull(policyEntry.apply(null));

		// subset_of
		SubsetOfOperation subsetOfOperation = new SubsetOfOperation();
		subsetOfOperation.configure(Arrays.asList("a", "b"));
		policyEntry = new MetadataPolicyEntry(
			"some_param",
			Collections.singletonList((PolicyOperation) subsetOfOperation)
		);
		assertNull(policyEntry.apply(null));
	}


	public void testEssentialOperation() throws PolicyViolationException {

		ValueOperation valueOperation = new ValueOperation();
		valueOperation.configure("a");

		DefaultOperation defaultOperation = new DefaultOperation();
		defaultOperation.configure("a");

		MetadataPolicyEntry policyEntry = new MetadataPolicyEntry(
			"some_param",
			Arrays.asList((PolicyOperation)valueOperation, (PolicyOperation)defaultOperation)
		);

		assertEquals("a", policyEntry.apply("b"));
		assertEquals("a", policyEntry.apply(null));
		assertEquals("a", policyEntry.apply("a"));
	}


	public void testPolicyViolationExceptionOnEssentialSubsetOfReturningNull() {

		// essential
		EssentialOperation essentialOperation = new EssentialOperation();
		essentialOperation.configure(true);

		// subset_of
		SubsetOfOperation subsetOfOperation = new SubsetOfOperation();
		subsetOfOperation.configure(Arrays.asList("a", "b"));
		MetadataPolicyEntry policyEntry = new MetadataPolicyEntry(
			"some_param",
			Arrays.asList((PolicyOperation) essentialOperation, (PolicyOperation) subsetOfOperation)
		);

		try {
			policyEntry.apply(Arrays.asList("c", "d"));
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Essential parameter failed subset_of check", e.getMessage());
		}
	}
	
	
	public void testScopesExample() throws ParseException, PolicyViolationException {
		
		String json =
			"{\"subset_of\": [\"openid\", \"eduperson\", \"phone\"]," +
			 "\"superset_of\": [\"openid\"]," +
			 "\"default\": [\"openid\", \"eduperson\"]}";
		
		JSONObject spec = JSONObjectUtils.parse(json);
		
		MetadataPolicyEntry policyEntry = MetadataPolicyEntry.parse("scope", spec);
		
		assertEquals("scope", policyEntry.getKey());
		
		for (PolicyOperation op: policyEntry.getPolicyOperations()) {
			
			if (op instanceof SubsetOfOperation) {
				SubsetOfOperation subsetOfOperation = (SubsetOfOperation) op;
				assertEquals(Arrays.asList("openid", "eduperson", "phone"), subsetOfOperation.getStringListConfiguration());
			} else if (op instanceof SupersetOfOperation) {
				SupersetOfOperation supersetOfOperation = (SupersetOfOperation) op;
				assertEquals(Collections.singletonList("openid"), supersetOfOperation.getStringListConfiguration());
			} else if (op instanceof DefaultOperation) {
				DefaultOperation defaultOperation = (DefaultOperation) op;
				assertEquals(Arrays.asList("openid", "eduperson"), defaultOperation.getStringListConfiguration());
			} else {
				fail();
			}
		}
		
		assertEquals(3, policyEntry.getValue().size());
	}
	
	
	// https://openid.net/specs/openid-connect-federation-1_0.html#rfc.section.4.1.3.1
	public void testExampleCombineScope() throws ParseException, PolicyViolationException {
		
		MetadataPolicyEntry entry = MetadataPolicyEntry.parse(
			"scopes",
			JSONObjectUtils.parse(
				"{" +
				"    \"subset_of\": [" +
				"      \"openid\"," +
				"      \"eduperson\"," +
				"      \"phone\"" +
				"    ]," +
				"    \"superset_of\": [" +
				"      \"openid\"" +
				"    ]," +
				"    \"default\": [" +
				"      \"openid\"," +
				"      \"eduperson\"" +
				"    ]" +
				"}"
			)
		);
		
		MetadataPolicyEntry other = MetadataPolicyEntry.parse(
			"scopes",
			JSONObjectUtils.parse(
				"{" +
				"    \"subset_of\": [" +
				"      \"openid\"," +
				"      \"eduperson\"," +
				"      \"address\"" +
				"    ]," +
				"    \"default\": [" +
				"      \"openid\"," +
				"      \"eduperson\"" +
				"    ]" +
				"}"
			)
		);
		
		MetadataPolicyEntry combined = entry.combine(other);
		
		assertEquals("scopes", combined.getParameterName());
		
		SubsetOfOperation subsetOfOperation = (SubsetOfOperation) combined.getOperationsMap().get(SubsetOfOperation.NAME);
		assertEquals(Arrays.asList("openid", "eduperson"), subsetOfOperation.getStringListConfiguration());
		
		SupersetOfOperation supersetOfOperation = (SupersetOfOperation) combined.getOperationsMap().get(SupersetOfOperation.NAME);
		assertEquals(Collections.singletonList("openid"), supersetOfOperation.getStringListConfiguration());
		
		DefaultOperation defaultOperation = (DefaultOperation) combined.getOperationsMap().get(DefaultOperation.NAME);
		assertEquals(Arrays.asList("openid", "eduperson"), defaultOperation.getStringListConfiguration());
		
		assertEquals(3, combined.getPolicyOperations().size());
	}
	
	
	// https://openid.net/specs/openid-connect-federation-1_0.html#rfc.section.4.1.3.1
	public void testExampleCombineIDTokenJWSAlg() throws ParseException, PolicyViolationException {
		
		MetadataPolicyEntry entry = MetadataPolicyEntry.parse(
			"id_token_signed_response_alg",
			JSONObjectUtils.parse(
				"{" +
				"    \"one_of\": [" +
				"      \"ES256\"," +
				"      \"ES384\"," +
				"      \"ES512\"" +
				"    ]" +
				"}"
			)
		);
		
		MetadataPolicyEntry other = MetadataPolicyEntry.parse(
			"id_token_signed_response_alg",
			JSONObjectUtils.parse(
				"{" +
				"    \"one_of\": [" +
				"      \"ES256\"," +
				"      \"ES384\"" +
				"    ]," +
				"    \"default\": \"ES256\"" +
				"}"
			)
		);
		
		MetadataPolicyEntry combined = entry.combine(other);
		
		assertEquals("id_token_signed_response_alg", combined.getParameterName());
		
		OneOfOperation oneOfOperation = (OneOfOperation) combined.getOperationsMap().get(OneOfOperation.NAME);
		assertEquals(Arrays.asList("ES256", "ES384"), oneOfOperation.getStringListConfiguration());
		
		DefaultOperation defaultOperation = (DefaultOperation) combined.getOperationsMap().get(DefaultOperation.NAME);
		assertEquals("ES256", defaultOperation.getStringConfiguration());
		
		assertEquals(2, combined.getPolicyOperations().size());
	}
	
	
	// https://openid.net/specs/openid-connect-federation-1_0.html#rfc.section.4.1.3.1
	public void testExampleCombineContacts() throws ParseException, PolicyViolationException {
		
		MetadataPolicyEntry entry = MetadataPolicyEntry.parse(
			"contacts",
			JSONObjectUtils.parse(
				"{" +
				"    \"add\": \"helpdesk@federation.example.org\"" +
				"}"
			)
		);
		
		MetadataPolicyEntry other = MetadataPolicyEntry.parse(
			"contacts",
			JSONObjectUtils.parse(
				"{" +
				"    \"add\": \"helpdesk@org.example.org\"" +
				"}"
			)
		);
		
		MetadataPolicyEntry combined = entry.combine(other);
		
		assertEquals("contacts", combined.getParameterName());
		
		AddOperation addOperation = (AddOperation) combined.getOperationsMap().get(AddOperation.NAME);
		assertEquals(Arrays.asList("helpdesk@federation.example.org", "helpdesk@org.example.org"), addOperation.getStringListConfiguration());
		
		assertEquals(1, combined.getPolicyOperations().size());
	}
	
	
	public void testCombine_paramNamesMismatch() {
		
		try {
			new MetadataPolicyEntry("scopes", null)
				.combine(new MetadataPolicyEntry("contacts", null));
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("The parameter name of the other policy doesn't match: contacts", e.getMessage());
		}
	}
	
	
	public void testParse_entrySpecMustNotBeNull()
		throws ParseException, PolicyViolationException {
		
		try {
			MetadataPolicyEntry.parse("scope", null, MetadataPolicyEntry.DEFAULT_POLICY_OPERATION_FACTORY, MetadataPolicyEntry.DEFAULT_POLICY_COMBINATION_VALIDATOR);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The entry spec must not be null", e.getMessage());
		}
	}
	
	
	public void testParse_entryUnsupportedPolicyName()
		throws ParseException {
		
		String unsupportedPolicyName = "policy-abc";
		
		JSONObject entrySpec = new JSONObject();
		entrySpec.put(unsupportedPolicyName, "123");
		
		try {
			MetadataPolicyEntry.parse("scope", entrySpec, MetadataPolicyEntry.DEFAULT_POLICY_OPERATION_FACTORY, MetadataPolicyEntry.DEFAULT_POLICY_COMBINATION_VALIDATOR);
			fail();
		} catch (PolicyViolationException e) {
			assertEquals("Unsupported policy operation: " + unsupportedPolicyName, e.getMessage());
		}
	}
}
