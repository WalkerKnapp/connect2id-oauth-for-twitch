/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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


import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;


public class LeafEntityTypeConstraintTest extends TestCase {
	
	
	public void testAnyConstant() throws ParseException {
		
		assertTrue(LeafEntityTypeConstraint.ANY.allowsAny());
		assertNull(LeafEntityTypeConstraint.ANY.getAllowed());
		assertNull(LeafEntityTypeConstraint.ANY.getAllowedAsStringList());
		
		assertTrue(LeafEntityTypeConstraint.ANY.isAllowed(EntityType.OPENID_PROVIDER));
		assertTrue(LeafEntityTypeConstraint.ANY.isAllowed(EntityType.OPENID_RELYING_PARTY));
		
		assertEquals(LeafEntityTypeConstraint.ANY, new LeafEntityTypeConstraint(null));
		assertEquals(LeafEntityTypeConstraint.ANY.hashCode(), new LeafEntityTypeConstraint(null).hashCode());
		assertEquals("null", LeafEntityTypeConstraint.ANY.toString());
		
		assertEquals(LeafEntityTypeConstraint.ANY, LeafEntityTypeConstraint.parse(null));
	}
	
	
	public void testAllowAny() throws ParseException {
		
		LeafEntityTypeConstraint constraint = new LeafEntityTypeConstraint(null);
		
		assertTrue(constraint.allowsAny());
		assertNull(constraint.getAllowed());
		assertNull(constraint.getAllowedAsStringList());
		
		assertTrue(constraint.isAllowed(EntityType.OPENID_PROVIDER));
		assertTrue(constraint.isAllowed(EntityType.OPENID_RELYING_PARTY));
		
		assertEquals(constraint, new LeafEntityTypeConstraint(null));
		assertEquals(constraint.hashCode(), new LeafEntityTypeConstraint(null).hashCode());
		assertEquals("null", LeafEntityTypeConstraint.ANY.toString());
		
		assertEquals(constraint, LeafEntityTypeConstraint.parse(constraint.getAllowedAsStringList()));
		
		assertEquals(LeafEntityTypeConstraint.ANY, constraint);
	}
	
	
	public void testAllowAny_emptySet() throws ParseException {
		
		LeafEntityTypeConstraint constraint = new LeafEntityTypeConstraint(Collections.<EntityType>emptySet());
		
		assertTrue(constraint.allowsAny());
		assertNull(constraint.getAllowed());
		assertNull(constraint.getAllowedAsStringList());
		
		assertTrue(constraint.isAllowed(EntityType.OPENID_PROVIDER));
		assertTrue(constraint.isAllowed(EntityType.OPENID_RELYING_PARTY));
		
		assertEquals(constraint, new LeafEntityTypeConstraint(Collections.<EntityType>emptySet()));
		assertEquals(constraint.hashCode(), new LeafEntityTypeConstraint(null).hashCode());
		assertEquals("null", LeafEntityTypeConstraint.ANY.toString());
		
		assertEquals(constraint, LeafEntityTypeConstraint.parse(constraint.getAllowedAsStringList()));
		
		assertEquals(LeafEntityTypeConstraint.ANY, constraint);
	}
	
	
	public void testAllowSpecified_one() throws ParseException {
		
		EntityType entityType = EntityType.OPENID_PROVIDER;
		
		LeafEntityTypeConstraint constraint = new LeafEntityTypeConstraint(Collections.singleton(entityType));
		
		assertFalse(constraint.allowsAny());
		
		assertEquals(Collections.singleton(entityType), constraint.getAllowed());
		
		assertEquals(Identifier.toStringList(Collections.singleton(entityType)), constraint.getAllowedAsStringList());
		
		assertTrue(constraint.isAllowed(entityType));
		assertFalse(constraint.isAllowed(EntityType.OPENID_RELYING_PARTY));
		assertFalse(constraint.isAllowed(EntityType.OAUTH_AUTHORIZATION_SERVER));
		assertFalse(constraint.isAllowed(EntityType.OAUTH_CLIENT));
		assertFalse(constraint.isAllowed(EntityType.OAUTH_RESOURCE));
		
		assertEquals(constraint, new LeafEntityTypeConstraint(Collections.singleton(entityType)));
		assertEquals(constraint.hashCode(), new LeafEntityTypeConstraint(Collections.singleton(entityType)).hashCode());
		assertEquals(constraint.getAllowed().toString(), constraint.toString());
		
		assertEquals(constraint, LeafEntityTypeConstraint.parse(constraint.getAllowedAsStringList()));
	}
	
	
	public void testAllowSpecified_two() throws ParseException {
		
		Set<EntityType> allowed = new HashSet<>(Arrays.asList(EntityType.OPENID_PROVIDER, EntityType.OPENID_RELYING_PARTY));
		
		LeafEntityTypeConstraint constraint = new LeafEntityTypeConstraint(allowed);
		
		assertFalse(constraint.allowsAny());
		
		assertEquals(allowed, constraint.getAllowed());
		
		assertEquals(Identifier.toStringList(allowed), constraint.getAllowedAsStringList());
		
		assertTrue(constraint.isAllowed(EntityType.OPENID_PROVIDER));
		assertTrue(constraint.isAllowed(EntityType.OPENID_RELYING_PARTY));;
		assertFalse(constraint.isAllowed(EntityType.OAUTH_AUTHORIZATION_SERVER));
		assertFalse(constraint.isAllowed(EntityType.OAUTH_CLIENT));
		assertFalse(constraint.isAllowed(EntityType.OAUTH_RESOURCE));
		
		assertEquals(constraint, new LeafEntityTypeConstraint(allowed));
		assertEquals(constraint.hashCode(), new LeafEntityTypeConstraint(allowed).hashCode());
		assertEquals(constraint.getAllowed().toString(), constraint.toString());
		
		assertEquals(constraint, LeafEntityTypeConstraint.parse(constraint.getAllowedAsStringList()));
	}
}
