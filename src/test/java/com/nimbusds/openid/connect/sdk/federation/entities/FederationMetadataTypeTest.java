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


public class FederationMetadataTypeTest extends TestCase {
	
	
	public void testConstants() {
		
		assertEquals("openid_relying_party", FederationMetadataType.OPENID_RELYING_PARTY.getValue());
		assertEquals("openid_provider", FederationMetadataType.OPENID_PROVIDER.getValue());
		assertEquals("oauth_authorization_server", FederationMetadataType.OAUTH_AUTHORIZATION_SERVER.getValue());
		assertEquals("oauth_client", FederationMetadataType.OAUTH_CLIENT.getValue());
		assertEquals("oauth_resource", FederationMetadataType.OAUTH_RESOURCE.getValue());
		assertEquals("federation_entity", FederationMetadataType.FEDERATION_ENTITY.getValue());
		assertEquals("trust_mark_issuer", FederationMetadataType.TRUST_MARK_ISSUER.getValue());
	}
	
	public void testConstructor() {
		
		FederationMetadataType type = new FederationMetadataType("some-value");
		assertEquals("some-value", type.getValue());
		
		assertEquals(type, new FederationMetadataType("some-value"));
		assertEquals(type.hashCode(), new FederationMetadataType("some-value").hashCode());
	}
	
	
	public void testInequality() {
		
		assertNotEquals(new FederationMetadataType("a"), new FederationMetadataType("b"));
	}
}
