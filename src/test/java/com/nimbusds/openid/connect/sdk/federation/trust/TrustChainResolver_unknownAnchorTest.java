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

import junit.framework.TestCase;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementClaimsSet;
import com.nimbusds.openid.connect.sdk.federation.entities.FederationEntityMetadata;
import com.nimbusds.openid.connect.sdk.federation.trust.constraints.TrustChainConstraints;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;


public class TrustChainResolver_unknownAnchorTest extends TestCase {
	
	// Anchor
	private static final Issuer ANCHOR_ISSUER = new Issuer("https://unknown.federation.com");
	
	private static final URI ANCHOR_FEDERATION_API_URI = URI.create(ANCHOR_ISSUER + "/api");
	
	private static final JWKSet ANCHOR_JWK_SET;
	
	private static final EntityStatementClaimsSet ANCHOR_SELF_STMT_CLAIMS;
	
	private static final EntityStatement ANCHOR_SELF_STMT;
	
	// Leaf
	private static final Issuer OP_ISSUER = new Issuer("https://c2id.com");
	
	private static final JWKSet OP_JWK_SET;
	
	private static final OIDCProviderMetadata OP_METADATA;
	
	private static final EntityStatementClaimsSet OP_SELF_STMT_CLAIMS;
	
	private static final EntityStatement OP_SELF_STMT;
	
	private static final EntityStatementClaimsSet ANCHOR_STMT_ABOUT_OP_CLAIMS;
	
	private static final EntityStatement ANCHOR_STMT_ABOUT_OP;
	
	
	static {
		try {
			long nowTs = DateUtils.toSecondsSinceEpoch(new Date());
			
			ANCHOR_JWK_SET = new JWKSet(
				new RSAKeyGenerator(2048)
					.keyUse(KeyUse.SIGNATURE)
					.keyID("a1")
					.generate()
			);
			
			OP_JWK_SET = new JWKSet(
				new RSAKeyGenerator(2048)
					.keyUse(KeyUse.SIGNATURE)
					.keyID("op1")
					.generate()
			);
			
			OP_METADATA = new OIDCProviderMetadata(OP_ISSUER, Collections.singletonList(SubjectType.PAIRWISE), URI.create(OP_ISSUER + "/jwks.json"));
			OP_METADATA.applyDefaults();
			
			OP_SELF_STMT_CLAIMS = new EntityStatementClaimsSet(
				OP_ISSUER,
				new Subject(OP_ISSUER.getValue()),
				DateUtils.fromSecondsSinceEpoch(nowTs),
				DateUtils.fromSecondsSinceEpoch(nowTs + 3600),
				OP_JWK_SET.toPublicJWKSet());
			OP_SELF_STMT_CLAIMS.setOPMetadata(OP_METADATA);
			OP_SELF_STMT_CLAIMS.setAuthorityHints(Collections.singletonList(new EntityID(ANCHOR_ISSUER.getValue())));
			
			OP_SELF_STMT = EntityStatement.sign(OP_SELF_STMT_CLAIMS, OP_JWK_SET.getKeyByKeyId("op1"));
			
			ANCHOR_SELF_STMT_CLAIMS = new EntityStatementClaimsSet(
				ANCHOR_ISSUER,
				new Subject(ANCHOR_ISSUER.getValue()),
				DateUtils.fromSecondsSinceEpoch(nowTs),
				DateUtils.fromSecondsSinceEpoch(nowTs + 3600),
				ANCHOR_JWK_SET.toPublicJWKSet());
			ANCHOR_SELF_STMT_CLAIMS.setFederationEntityMetadata(new FederationEntityMetadata(ANCHOR_FEDERATION_API_URI));
			
			ANCHOR_SELF_STMT = EntityStatement.sign(ANCHOR_SELF_STMT_CLAIMS, ANCHOR_JWK_SET.getKeyByKeyId("a1"));
			
			ANCHOR_STMT_ABOUT_OP_CLAIMS = new EntityStatementClaimsSet(
				ANCHOR_ISSUER,
				new Subject(OP_ISSUER.getValue()),
				DateUtils.fromSecondsSinceEpoch(nowTs),
				DateUtils.fromSecondsSinceEpoch(nowTs + 3600),
				OP_JWK_SET.toPublicJWKSet());
			
			ANCHOR_STMT_ABOUT_OP = EntityStatement.sign(ANCHOR_STMT_ABOUT_OP_CLAIMS, ANCHOR_JWK_SET.getKeyByKeyId("a1"));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public void testResolve() throws InvalidEntityMetadataException {
		
		EntityStatementRetriever statementRetriever = new EntityStatementRetriever() {
			@Override
			public EntityStatement fetchEntityConfiguration(EntityID target) throws ResolveException {
				if (OP_ISSUER.getValue().equals(target.getValue())) {
					return OP_SELF_STMT;
				} else if (ANCHOR_ISSUER.getValue().equals(target.getValue())) {
					return ANCHOR_SELF_STMT;
				} else {
					throw new ResolveException("Invalid target");
				}
			}
			
			
			@Override
			public EntityStatement fetchEntityStatement(URI federationAPIEndpoint, EntityID issuer, EntityID subject) throws ResolveException {
				if (ANCHOR_FEDERATION_API_URI.equals(federationAPIEndpoint)) {
					if (ANCHOR_ISSUER.getValue().equals(issuer.getValue()) && OP_ISSUER.getValue().equals(subject.getValue())) {
						return ANCHOR_STMT_ABOUT_OP;
					}
					throw new ResolveException("Unknown subject: " + subject);
				}
				throw new ResolveException("Exception");
			}
		};
		
		// Test the retriever
		DefaultTrustChainRetriever retriever = new DefaultTrustChainRetriever(statementRetriever);
		TrustChainSet trustChains = retriever.retrieve(new EntityID(OP_ISSUER), null, Collections.singleton(new EntityID("https://federation.com")));
		assertTrue(trustChains.isEmpty());
		assertTrue(retriever.getAccumulatedExceptions().isEmpty());
		
		// Test the resolver
		TrustChainResolver resolver = new TrustChainResolver(Collections.singletonMap(new EntityID("https://federation.com"), new JWKSet()), TrustChainConstraints.NO_CONSTRAINTS, statementRetriever);
		
		try {
			resolver.resolveTrustChains(new EntityID(OP_ISSUER));
			fail();
		} catch (ResolveException e) {
			assertEquals("No trust chain leading up to a trust anchor", e.getMessage());
			assertEquals(0, e.getCauses().size());
		}
	}
}
