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

package com.nimbusds.openid.connect.sdk.federation.trust.constraints;


import java.util.*;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;


public class TrustChainConstraintsTest extends TestCase {
	
	
	public void testNoConstraintsConstant() {
		
		assertEquals(-1, TrustChainConstraints.NO_CONSTRAINTS.getMaxPathLength());
		assertTrue(TrustChainConstraints.NO_CONSTRAINTS.getPermittedEntityIDs().isEmpty());
		assertTrue(TrustChainConstraints.NO_CONSTRAINTS.getExcludedEntityIDs().isEmpty());
		assertTrue(TrustChainConstraints.NO_CONSTRAINTS.getLeafEntityTypeConstraint().allowsAny());
	}
	
	
	public void testDefaultConstructorSameAsEmpty() throws ParseException {
		
		for (TrustChainConstraints c: Arrays.asList(
			new TrustChainConstraints(),
			new TrustChainConstraints(-1, null,  null, null))) {
			
			assertEquals(-1, c.getMaxPathLength());
			assertTrue(c.getPermittedEntityIDs().isEmpty());
			assertTrue(c.getExcludedEntityIDs().isEmpty());
			assertTrue(c.getLeafEntityTypeConstraint().allowsAny());
			
			JSONObject jsonObject = c.toJSONObject();
			assertTrue(jsonObject.isEmpty());
			String json = c.toJSONString();
			assertEquals("{}", json);
			
			c = TrustChainConstraints.parse(jsonObject);
			assertEquals(-1, c.getMaxPathLength());
			assertTrue(c.getPermittedEntityIDs().isEmpty());
			assertTrue(c.getExcludedEntityIDs().isEmpty());
			assertTrue(c.getLeafEntityTypeConstraint().allowsAny());
		}
	}
	
	
	public void testFullySpecified() throws ParseException {
		
		int maxPathLength = 3;
		List<EntityIDConstraint> permitted = new LinkedList<>();
		permitted.add(new ExactMatchEntityIDConstraint(new EntityID("https://example.com")));
		permitted.add(new ExactMatchEntityIDConstraint(new EntityID("https://example.org")));
		
		List<EntityIDConstraint> excluded = new LinkedList<>();
		excluded.add(new SubtreeEntityIDConstraint("https://.abc.example.org"));
		excluded.add(new SubtreeEntityIDConstraint("https://.xyz.example.org"));
		
		Set<EntityType> leafTypes = new HashSet<>(Arrays.asList(EntityType.OPENID_PROVIDER, EntityType.OPENID_RELYING_PARTY));
		LeafEntityTypeConstraint leafEntityTypeConstraint = new LeafEntityTypeConstraint(leafTypes);
		
		TrustChainConstraints c = new TrustChainConstraints(3, permitted, excluded, leafEntityTypeConstraint);
		assertEquals(maxPathLength, c.getMaxPathLength());
		assertEquals(permitted, c.getPermittedEntityIDs());
		assertEquals(excluded, c.getExcludedEntityIDs());
		assertEquals(leafEntityTypeConstraint, c.getLeafEntityTypeConstraint());
		
		JSONObject jsonObject = c.toJSONObject();
		assertEquals(3, JSONObjectUtils.getInt(jsonObject, "max_path_length"));
		
		JSONObject namingConstraints = JSONObjectUtils.getJSONObject(jsonObject, "naming_constraints");
		assertEquals(Arrays.asList(permitted.get(0).toString(), permitted.get(1).toString()), JSONObjectUtils.getStringList(namingConstraints, "permitted"));
		assertEquals(Arrays.asList(excluded.get(0).toString(), excluded.get(1).toString()), JSONObjectUtils.getStringList(namingConstraints, "excluded"));
		assertEquals(2, namingConstraints.size());
		
		assertEquals(leafEntityTypeConstraint.getAllowedAsStringList(), JSONObjectUtils.getStringList(jsonObject, "allowed_leaf_entity_types"));
		
		assertEquals(3, jsonObject.size());
		
		c = TrustChainConstraints.parse(jsonObject);
		
		assertEquals(maxPathLength, c.getMaxPathLength());
		assertEquals(permitted, c.getPermittedEntityIDs());
		assertEquals(excluded, c.getExcludedEntityIDs());
		assertEquals(leafEntityTypeConstraint, c.getLeafEntityTypeConstraint());
	}
	
	
	public void testParse_emptyNamingConstraints() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("max_path_length", 10);
		jsonObject.put("naming_constraints", new JSONObject());
		
		TrustChainConstraints c = TrustChainConstraints.parse(jsonObject);
		assertEquals(10, c.getMaxPathLength());
		assertTrue(c.getPermittedEntityIDs().isEmpty());
		assertTrue(c.getExcludedEntityIDs().isEmpty());
		assertEquals(LeafEntityTypeConstraint.ANY, c.getLeafEntityTypeConstraint());
	}
	
	
	public void testParse_nullNamingConstraints() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("max_path_length", 10);
		jsonObject.put("naming_constraints", null);
		
		TrustChainConstraints c = TrustChainConstraints.parse(jsonObject);
		assertEquals(10, c.getMaxPathLength());
		assertTrue(c.getPermittedEntityIDs().isEmpty());
		assertTrue(c.getExcludedEntityIDs().isEmpty());
		assertEquals(LeafEntityTypeConstraint.ANY, c.getLeafEntityTypeConstraint());
	}
	
	
	public void testParse_nullNamingConstraintsMembers() throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("max_path_length", 10);
		
		JSONObject namingConstraints = new JSONObject();
		namingConstraints.put("permitted", null);
		namingConstraints.put("excluded", null);
		jsonObject.put("naming_constraints", namingConstraints);
		
		TrustChainConstraints c = TrustChainConstraints.parse(jsonObject);
		assertEquals(10, c.getMaxPathLength());
		assertTrue(c.getPermittedEntityIDs().isEmpty());
		assertTrue(c.getExcludedEntityIDs().isEmpty());
		assertEquals(LeafEntityTypeConstraint.ANY, c.getLeafEntityTypeConstraint());
	}
	
	
	public void testEquality() {
		
		assertEquals(
			new TrustChainConstraints(10, null, null, null),
			new TrustChainConstraints(10, null, null, null)
		);
		
		assertEquals(
			new TrustChainConstraints(
			10,
				Collections.singletonList((EntityIDConstraint) new ExactMatchEntityIDConstraint(new EntityID("https://example.com"))),
				Collections.singletonList((EntityIDConstraint) new SubtreeEntityIDConstraint("https://.abc.example.com")),
				null
			),
			new TrustChainConstraints(
				10,
				Collections.singletonList((EntityIDConstraint) new ExactMatchEntityIDConstraint(new EntityID("https://example.com"))),
				Collections.singletonList((EntityIDConstraint) new SubtreeEntityIDConstraint("https://.abc.example.com")),
			null
			)
		);
		
		assertEquals(
			new TrustChainConstraints(
			10,
				Collections.singletonList((EntityIDConstraint) new ExactMatchEntityIDConstraint(new EntityID("https://example.com"))),
				Collections.singletonList((EntityIDConstraint) new SubtreeEntityIDConstraint("https://.abc.example.com")),
				new LeafEntityTypeConstraint(Collections.singleton(EntityType.OPENID_RELYING_PARTY))
			),
			new TrustChainConstraints(
				10,
				Collections.singletonList((EntityIDConstraint) new ExactMatchEntityIDConstraint(new EntityID("https://example.com"))),
				Collections.singletonList((EntityIDConstraint) new SubtreeEntityIDConstraint("https://.abc.example.com")),
				new LeafEntityTypeConstraint(Collections.singleton(EntityType.OPENID_RELYING_PARTY))
			)
		);
	}
	
	
	public void testIsPermitted_rejectNegativePathLength() {
		
		try {
			new TrustChainConstraints().isPermitted(-1);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The path length must not be negative", e.getMessage());
		}
		
		try {
			new TrustChainConstraints().isPermitted(-1, new EntityID("https://rp.example.com"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The path length must not be negative", e.getMessage());
		}
	}
	
	
	public void testIsPermitted_numIntermediatesInPath_0() {
		
		TrustChainConstraints c = new TrustChainConstraints(0);
		assertEquals(0, c.getMaxPathLength());
		
		assertTrue(c.isPermitted(0));
		assertFalse(c.isPermitted(1));
		assertFalse(c.isPermitted(2));
		assertFalse(c.isPermitted(3));
	}
	
	
	public void testIsPermitted_numIntermediatesInPath_5() {
		
		TrustChainConstraints c = new TrustChainConstraints(5);
		assertEquals(5, c.getMaxPathLength());
		
		assertTrue(c.isPermitted(0));
		assertTrue(c.isPermitted(1));
		assertTrue(c.isPermitted(2));
		assertTrue(c.isPermitted(3));
		assertTrue(c.isPermitted(4));
		assertTrue(c.isPermitted(5));
		assertFalse(c.isPermitted(6));
	}
	
	
	public void testIsPermitted_default() {
		
		TrustChainConstraints c = new TrustChainConstraints();
		
		assertTrue(c.isPermitted(0, new EntityID("https://rp.example.com")));
		assertTrue(c.isPermitted(1, new EntityID("https://rp.example.com")));
		assertTrue(c.isPermitted(2, new EntityID("https://rp.example.com")));
	}
	
	
	public void testIsPermitted_pathLength() {
		
		TrustChainConstraints c = new TrustChainConstraints(0, null, null, null);
		
		assertTrue(c.isPermitted(0, new EntityID("https://rp.example.com")));
		assertFalse(c.isPermitted(1, new EntityID("https://rp.example.com")));
		assertFalse(c.isPermitted(2, new EntityID("https://rp.example.com")));
		
		c = new TrustChainConstraints(1, null, null, null);
		
		assertTrue(c.isPermitted(0, new EntityID("https://rp.example.com")));
		assertTrue(c.isPermitted(1, new EntityID("https://rp.example.com")));
		assertFalse(c.isPermitted(2, new EntityID("https://rp.example.com")));
		
		c = new TrustChainConstraints(2, null, null, null);
		
		assertTrue(c.isPermitted(0, new EntityID("https://rp.example.com")));
		assertTrue(c.isPermitted(1, new EntityID("https://rp.example.com")));
		assertTrue(c.isPermitted(2, new EntityID("https://rp.example.com")));
	}
	
	
	public void testIsPermitted_permitted() throws ParseException {
		
		List<EntityIDConstraint> permitted = Arrays.asList(
			EntityIDConstraint.parse("https://.example.com"),
			EntityIDConstraint.parse("https://rp.example.org")
		);
		
		TrustChainConstraints c = new TrustChainConstraints(5, permitted, null, null);
		
		assertTrue(c.isPermitted(1, new EntityID("https://rp.example.com")));
		assertTrue(c.isPermitted(1, new EntityID("https://a.example.com")));
		assertTrue(c.isPermitted(1, new EntityID("https://b.example.com")));
		assertTrue(c.isPermitted(1, new EntityID("https://c.example.com")));
		assertFalse(c.isPermitted(1, new EntityID("https://example.com")));
		assertFalse(c.isPermitted(1, new EntityID("https://example.net")));
	}
	
	
	public void testIsPermitted_excluded() throws ParseException {
		
		List<EntityIDConstraint> excluded = Arrays.asList(
			EntityIDConstraint.parse("https://.example.com"),
			EntityIDConstraint.parse("https://rp.example.org")
		);
		
		TrustChainConstraints c = new TrustChainConstraints(5, null, excluded, null);
		
		assertFalse(c.isPermitted(1, new EntityID("https://rp.example.com")));
		assertFalse(c.isPermitted(1, new EntityID("https://a.example.com")));
		assertFalse(c.isPermitted(1, new EntityID("https://b.example.com")));
		assertFalse(c.isPermitted(1, new EntityID("https://c.example.com")));
		assertTrue(c.isPermitted(1, new EntityID("https://example.com")));
		assertTrue(c.isPermitted(1, new EntityID("https://example.net")));
	}
	
	
	public void testIsPermitted_permitted_excluded() throws ParseException {
		
		List<EntityIDConstraint> permitted = Arrays.asList(
			EntityIDConstraint.parse("https://rp.example.org"),
			EntityIDConstraint.parse("https://.example.com"),
			EntityIDConstraint.parse("https://.example.net")
		);
		
		List<EntityIDConstraint> excluded = Collections.singletonList(EntityIDConstraint.parse("https://op.example.net")); // override
		
		TrustChainConstraints c = new TrustChainConstraints(5, permitted, excluded, null);
		
		assertTrue(c.isPermitted(1, new EntityID("https://rp.example.com")));
		assertTrue(c.isPermitted(1, new EntityID("https://a.example.com")));
		assertTrue(c.isPermitted(1, new EntityID("https://b.example.com")));
		assertTrue(c.isPermitted(1, new EntityID("https://c.example.com")));
		assertFalse(c.isPermitted(1, new EntityID("https://example.com")));
		assertFalse(c.isPermitted(1, new EntityID("https://example.net")));
		assertFalse(c.isPermitted(1, new EntityID("https://op.example.net")));
		assertTrue(c.isPermitted(1, new EntityID("https://a.example.net")));
		assertTrue(c.isPermitted(1, new EntityID("https://b.example.net")));
		assertTrue(c.isPermitted(1, new EntityID("https://c.example.net")));
		assertFalse(c.isPermitted(1, new EntityID("https://some.host.com")));
	}
	
	
	public void testParseExample() throws ParseException {
	
		String json = "" +
			"{" +
			"  \"naming_constraints\": {" +
			"    \"permitted\": [" +
			"      \"https://.example.com\"" +
			"    ]," +
			"    \"excluded\": [" +
			"      \"https://east.example.com\"" +
			"    ]" +
			"  }," +
			"  \"max_path_length\": 2," +
			"  \"allowed_leaf_entity_types\": [\"openid_provider\", \"openid_relying_party\"]" +
			"}";
		
		TrustChainConstraints c = TrustChainConstraints.parse(JSONObjectUtils.parse(json));
		
		assertEquals(2, c.getMaxPathLength());
		
		assertEquals(Collections.singletonList(new SubtreeEntityIDConstraint("https://.example.com")), c.getPermittedEntityIDs());
		assertEquals(Collections.singletonList(new ExactMatchEntityIDConstraint(new EntityID("https://east.example.com"))), c.getExcludedEntityIDs());
		
		assertEquals(new HashSet<>(Arrays.asList(EntityType.OPENID_PROVIDER, EntityType.OPENID_RELYING_PARTY)), c.getLeafEntityTypeConstraint().getAllowed());
	}
}
