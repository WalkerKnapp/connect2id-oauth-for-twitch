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

package com.nimbusds.openid.connect.sdk.federation.entities;


import static org.junit.Assert.assertNotEquals;

import junit.framework.TestCase;


public class EntityTypeTest extends TestCase {
	
	
	public void testConstants() {
		
		assertEquals("openid_relying_party", EntityType.OPENID_RELYING_PARTY.getValue());
		assertEquals("openid_provider", EntityType.OPENID_PROVIDER.getValue());
		assertEquals("oauth_authorization_server", EntityType.OAUTH_AUTHORIZATION_SERVER.getValue());
		assertEquals("oauth_client", EntityType.OAUTH_CLIENT.getValue());
		assertEquals("oauth_resource", EntityType.OAUTH_RESOURCE.getValue());
		assertEquals("federation_entity", EntityType.FEDERATION_ENTITY.getValue());
		assertEquals("trust_mark_issuer", EntityType.TRUST_MARK_ISSUER.getValue());
	}
	
	public void testConstructor() {
		
		EntityType type = new EntityType("some-value");
		assertEquals("some-value", type.getValue());
		
		assertEquals(type, new EntityType("some-value"));
		assertEquals(type.hashCode(), new EntityType("some-value").hashCode());
	}
	
	
	public void testInequality() {
		
		assertNotEquals(new EntityType("a"), new EntityType("b"));
	}
}
