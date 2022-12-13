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

package com.nimbusds.openid.connect.sdk.federation.trust;


import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementClaimsSet;
import com.nimbusds.openid.connect.sdk.federation.entities.FederationEntityMetadata;
import com.nimbusds.openid.connect.sdk.federation.trust.constraints.TrustChainConstraints;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;


public class TrustChainResolver_constructorTest extends TestCase {
	
	// Anchor
	private static final Issuer ANCHOR_ISSUER = new Issuer("https://federation.com");
	
	private static final JWKSet ANCHOR_JWK_SET;
	
	
	static {
		try {
			ANCHOR_JWK_SET = new JWKSet(
				new RSAKeyGenerator(2048)
					.keyUse(KeyUse.SIGNATURE)
					.keyID("a1")
					.generate());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public void testMinimalConstructor() {
		
		TrustChainResolver resolver = new TrustChainResolver(new EntityID(ANCHOR_ISSUER));
		
		Map<EntityID,JWKSet> anchors = resolver.getTrustAnchors();
		assertNull(anchors.get(new EntityID(ANCHOR_ISSUER)));
		assertTrue(anchors.keySet().contains(new EntityID(ANCHOR_ISSUER)));
		assertEquals(1, anchors.size());
		
		DefaultEntityStatementRetriever retriever = (DefaultEntityStatementRetriever)resolver.getEntityStatementRetriever();
		assertEquals(DefaultEntityStatementRetriever.DEFAULT_HTTP_CONNECT_TIMEOUT_MS, retriever.getHTTPConnectTimeout());
		assertEquals(DefaultEntityStatementRetriever.DEFAULT_HTTP_READ_TIMEOUT_MS, retriever.getHTTPReadTimeout());
	}
	
	
	public void testAnchorWithJWKSetConstructor() {
		
		TrustChainResolver resolver = new TrustChainResolver(new EntityID(ANCHOR_ISSUER), ANCHOR_JWK_SET);
		
		Map<EntityID,JWKSet> anchors = resolver.getTrustAnchors();
		assertEquals(ANCHOR_JWK_SET, anchors.get(new EntityID(ANCHOR_ISSUER)));
		assertEquals(1, anchors.size());
		
		DefaultEntityStatementRetriever retriever = (DefaultEntityStatementRetriever)resolver.getEntityStatementRetriever();
		assertEquals(DefaultEntityStatementRetriever.DEFAULT_HTTP_CONNECT_TIMEOUT_MS, retriever.getHTTPConnectTimeout());
		assertEquals(DefaultEntityStatementRetriever.DEFAULT_HTTP_READ_TIMEOUT_MS, retriever.getHTTPReadTimeout());
	}
	
	
	public void testMapWithTimeoutsConstructor() {
		
		Map<EntityID,JWKSet> anchors = Collections.singletonMap(new EntityID(ANCHOR_ISSUER), ANCHOR_JWK_SET);
		
		TrustChainResolver resolver = new TrustChainResolver(anchors, 250, 100);
		
		assertEquals(anchors, resolver.getTrustAnchors());
		
		DefaultEntityStatementRetriever retriever = (DefaultEntityStatementRetriever)resolver.getEntityStatementRetriever();
		assertEquals(250, retriever.getHTTPConnectTimeout());
		assertEquals(100, retriever.getHTTPReadTimeout());
	}
	
	
	public void testActualConstructor() {
		
		EntityStatementRetriever statementRetriever = new EntityStatementRetriever() {
			@Override
			public EntityStatement fetchEntityConfiguration(EntityID target) throws ResolveException {
				throw new ResolveException("Invalid target");
			}
			
			
			@Override
			public EntityStatement fetchEntityStatement(URI federationAPIEndpoint, EntityID issuer, EntityID subject) throws ResolveException {
				throw new ResolveException("Exception");
			}
		};
		
		Map<EntityID,JWKSet> anchors = Collections.singletonMap(new EntityID(ANCHOR_ISSUER), ANCHOR_JWK_SET);
		TrustChainResolver resolver = new TrustChainResolver(anchors, TrustChainConstraints.NO_CONSTRAINTS, statementRetriever);
		assertEquals(anchors, resolver.getTrustAnchors());
		assertEquals(statementRetriever, resolver.getEntityStatementRetriever());
	}
}
