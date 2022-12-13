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
import java.util.List;

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
import com.nimbusds.openid.connect.sdk.federation.trust.constraints.EntityIDConstraint;
import com.nimbusds.openid.connect.sdk.federation.trust.constraints.ExactMatchEntityIDConstraint;
import com.nimbusds.openid.connect.sdk.federation.trust.constraints.TrustChainConstraints;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;


public class TrustChainResolver_withIntermediateTest extends TestCase {
	
	// Anchor
	private static final Issuer ANCHOR_ISSUER = new Issuer("https://federation.com");
	
	private static final URI ANCHOR_FEDERATION_API_URI = URI.create(ANCHOR_ISSUER + "/api");
	
	private static final JWKSet ANCHOR_JWK_SET;
	
	private static final EntityStatementClaimsSet ANCHOR_SELF_STMT_CLAIMS;
	
	private static final EntityStatement ANCHOR_SELF_STMT;
	
	// Intermediate
	private static final Issuer INTERMEDIATE_ISSUER = new Issuer("https://intermediate.com");
	
	private static final URI INTERMEDIATE_FEDERATION_API_URI = URI.create(INTERMEDIATE_ISSUER + "/api");
	
	private static final JWKSet INTERMEDIATE_JWK_SET;
	
	private static final EntityStatementClaimsSet INTERMEDIATE_SELF_STMT_CLAIMS;
	
	private static final EntityStatement INTERMEDIATE_SELF_STMT;
	
	private static final EntityStatementClaimsSet ANCHOR_STMT_ABOUT_INTERMEDIATE_CLAIMS;
	
	private static final EntityStatement ANCHOR_STMT_ABOUT_INTERMEDIATE;
	
	// Leaf
	private static final Issuer OP_ISSUER = new Issuer("https://c2id.com");
	
	private static final JWKSet OP_JWK_SET;
	
	private static final OIDCProviderMetadata OP_METADATA;
	
	private static final EntityStatementClaimsSet OP_SELF_STMT_CLAIMS;
	
	private static final EntityStatement OP_SELF_STMT;
	
	private static final EntityStatementClaimsSet INTERMEDIATE_STMT_ABOUT_OP_CLAIMS;
	
	private static final EntityStatement INTERMEDIATE_STMT_ABOUT_OP;
	
	
	static {
		try {
			long nowTs = DateUtils.toSecondsSinceEpoch(new Date());
			
			ANCHOR_JWK_SET = new JWKSet(
				new RSAKeyGenerator(2048)
					.keyUse(KeyUse.SIGNATURE)
					.keyID("a1")
					.generate()
			);
			
			INTERMEDIATE_JWK_SET = new JWKSet(
				new RSAKeyGenerator(2048)
					.keyUse(KeyUse.SIGNATURE)
					.keyID("i1")
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
			OP_SELF_STMT_CLAIMS.setAuthorityHints(Collections.singletonList(new EntityID(INTERMEDIATE_ISSUER.getValue())));
			
			OP_SELF_STMT = EntityStatement.sign(OP_SELF_STMT_CLAIMS, OP_JWK_SET.getKeyByKeyId("op1"));
			
			INTERMEDIATE_SELF_STMT_CLAIMS = new EntityStatementClaimsSet(
				INTERMEDIATE_ISSUER,
				new Subject(INTERMEDIATE_ISSUER.getValue()),
				DateUtils.fromSecondsSinceEpoch(nowTs),
				DateUtils.fromSecondsSinceEpoch(nowTs + 3600),
				INTERMEDIATE_JWK_SET.toPublicJWKSet());
			INTERMEDIATE_SELF_STMT_CLAIMS.setFederationEntityMetadata(new FederationEntityMetadata(INTERMEDIATE_FEDERATION_API_URI));
			INTERMEDIATE_SELF_STMT_CLAIMS.setAuthorityHints(Collections.singletonList(new EntityID(ANCHOR_ISSUER.getValue())));
			
			INTERMEDIATE_SELF_STMT = EntityStatement.sign(INTERMEDIATE_SELF_STMT_CLAIMS, INTERMEDIATE_JWK_SET.getKeyByKeyId("i1"));
			
			INTERMEDIATE_STMT_ABOUT_OP_CLAIMS = new EntityStatementClaimsSet(
				INTERMEDIATE_ISSUER,
				new Subject(OP_ISSUER.getValue()),
				DateUtils.fromSecondsSinceEpoch(nowTs),
				DateUtils.fromSecondsSinceEpoch(nowTs + 3600),
				OP_JWK_SET.toPublicJWKSet());
			INTERMEDIATE_STMT_ABOUT_OP_CLAIMS.setAuthorityHints(Collections.singletonList(new EntityID(INTERMEDIATE_ISSUER.getValue())));
			
			INTERMEDIATE_STMT_ABOUT_OP = EntityStatement.sign(INTERMEDIATE_STMT_ABOUT_OP_CLAIMS, INTERMEDIATE_JWK_SET.getKeyByKeyId("i1"));
			
			ANCHOR_SELF_STMT_CLAIMS = new EntityStatementClaimsSet(
				ANCHOR_ISSUER,
				new Subject(ANCHOR_ISSUER.getValue()),
				DateUtils.fromSecondsSinceEpoch(nowTs),
				DateUtils.fromSecondsSinceEpoch(nowTs + 3600),
				ANCHOR_JWK_SET.toPublicJWKSet());
			ANCHOR_SELF_STMT_CLAIMS.setFederationEntityMetadata(new FederationEntityMetadata(ANCHOR_FEDERATION_API_URI));
			
			ANCHOR_SELF_STMT = EntityStatement.sign(ANCHOR_SELF_STMT_CLAIMS, ANCHOR_JWK_SET.getKeyByKeyId("a1"));
			
			ANCHOR_STMT_ABOUT_INTERMEDIATE_CLAIMS = new EntityStatementClaimsSet(
				ANCHOR_ISSUER,
				new Subject(INTERMEDIATE_ISSUER.getValue()),
				DateUtils.fromSecondsSinceEpoch(nowTs),
				DateUtils.fromSecondsSinceEpoch(nowTs + 3600),
				INTERMEDIATE_JWK_SET.toPublicJWKSet());
			ANCHOR_STMT_ABOUT_INTERMEDIATE_CLAIMS.setAuthorityHints(Collections.singletonList(new EntityID(ANCHOR_ISSUER.getValue())));
			
			ANCHOR_STMT_ABOUT_INTERMEDIATE = EntityStatement.sign(ANCHOR_STMT_ABOUT_INTERMEDIATE_CLAIMS, ANCHOR_JWK_SET.getKeyByKeyId("a1"));
			
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public void testResolve_fetchLeafStatement() throws ResolveException, InvalidEntityMetadataException {
		
		EntityStatementRetriever statementRetriever = new EntityStatementRetriever() {
			@Override
			public EntityStatement fetchEntityConfiguration(EntityID target) throws ResolveException {
				if (OP_ISSUER.getValue().equals(target.getValue())) {
					return OP_SELF_STMT;
				} else if (INTERMEDIATE_ISSUER.getValue().equals(target.getValue())) {
					return INTERMEDIATE_SELF_STMT;
				} else if (ANCHOR_ISSUER.getValue().equals(target.getValue())) {
					return ANCHOR_SELF_STMT;
				} else {
					throw new ResolveException("Invalid target");
				}
			}
			
			
			@Override
			public EntityStatement fetchEntityStatement(URI federationAPIEndpoint, EntityID issuer, EntityID subject) throws ResolveException {
				if (ANCHOR_FEDERATION_API_URI.equals(federationAPIEndpoint)) {
					if (ANCHOR_ISSUER.getValue().equals(issuer.getValue()) && INTERMEDIATE_ISSUER.getValue().equals(subject.getValue())) {
						return ANCHOR_STMT_ABOUT_INTERMEDIATE;
					}
					throw new ResolveException("Unknown subject: " + subject);
				} else if (INTERMEDIATE_FEDERATION_API_URI.equals(federationAPIEndpoint)) {
					if (INTERMEDIATE_ISSUER.getValue().equals(issuer.getValue()) && OP_ISSUER.getValue().equals(subject.getValue())) {
						return INTERMEDIATE_STMT_ABOUT_OP;
					}
					throw new ResolveException("Unknown subject: " + subject);
				} else {
					throw new ResolveException("Exception");
				}
			}
		};
		
		// Test the chain retriever
		DefaultTrustChainRetriever chainRetriever = new DefaultTrustChainRetriever(statementRetriever);
		
		TrustChainSet trustChains = chainRetriever.retrieve(new EntityID(OP_ISSUER), null, Collections.singleton(new EntityID(ANCHOR_ISSUER)));
		
		assertTrue(chainRetriever.getAccumulatedExceptions().isEmpty());
		
		assertEquals(1, trustChains.size());
		
		TrustChain chain = trustChains.iterator().next();
		
		assertEquals(OP_SELF_STMT, chain.getLeafConfiguration());
		assertEquals(INTERMEDIATE_STMT_ABOUT_OP, chain.getSuperiorStatements().get(0));
		assertEquals(ANCHOR_STMT_ABOUT_INTERMEDIATE, chain.getSuperiorStatements().get(1));
		assertEquals(2, chain.getSuperiorStatements().size());
		
		// Test the chain resolver
		TrustChainResolver resolver = new TrustChainResolver(Collections.singletonMap(new EntityID(ANCHOR_ISSUER), ANCHOR_JWK_SET), TrustChainConstraints.NO_CONSTRAINTS, statementRetriever);
		
		TrustChainSet resolvedChains = resolver.resolveTrustChains(new EntityID(OP_ISSUER));
		
		assertEquals(1, resolvedChains.size());
		
		chain = resolvedChains.iterator().next();
		
		assertEquals(OP_SELF_STMT, chain.getLeafConfiguration());
		assertEquals(INTERMEDIATE_STMT_ABOUT_OP, chain.getSuperiorStatements().get(0));
		assertEquals(ANCHOR_STMT_ABOUT_INTERMEDIATE, chain.getSuperiorStatements().get(1));
		assertEquals(2, chain.getSuperiorStatements().size());
	}
	
	
	public void testResolve_suppliedLeafStatement() throws ResolveException {
		
		EntityStatementRetriever statementRetriever = new EntityStatementRetriever() {
			@Override
			public EntityStatement fetchEntityConfiguration(EntityID target) throws ResolveException {
				if (OP_ISSUER.getValue().equals(target.getValue())) {
					fail();
					return null;
				} else if (INTERMEDIATE_ISSUER.getValue().equals(target.getValue())) {
					return INTERMEDIATE_SELF_STMT;
				} else if (ANCHOR_ISSUER.getValue().equals(target.getValue())) {
					return ANCHOR_SELF_STMT;
				} else {
					throw new ResolveException("Invalid target");
				}
			}
			
			
			@Override
			public EntityStatement fetchEntityStatement(URI federationAPIEndpoint, EntityID issuer, EntityID subject) throws ResolveException {
				if (ANCHOR_FEDERATION_API_URI.equals(federationAPIEndpoint)) {
					if (ANCHOR_ISSUER.getValue().equals(issuer.getValue()) && INTERMEDIATE_ISSUER.getValue().equals(subject.getValue())) {
						return ANCHOR_STMT_ABOUT_INTERMEDIATE;
					}
					throw new ResolveException("Unknown subject: " + subject);
				} else if (INTERMEDIATE_FEDERATION_API_URI.equals(federationAPIEndpoint)) {
					if (INTERMEDIATE_ISSUER.getValue().equals(issuer.getValue()) && OP_ISSUER.getValue().equals(subject.getValue())) {
						return INTERMEDIATE_STMT_ABOUT_OP;
					}
					throw new ResolveException("Unknown subject: " + subject);
				} else {
					throw new ResolveException("Exception");
				}
			}
		};
		
		// Test the chain retriever
		DefaultTrustChainRetriever chainRetriever = new DefaultTrustChainRetriever(statementRetriever);
		
		TrustChainSet trustChains = chainRetriever.retrieve(OP_SELF_STMT, Collections.singleton(new EntityID(ANCHOR_ISSUER)));
		
		assertTrue(chainRetriever.getAccumulatedExceptions().isEmpty());
		
		assertEquals(1, trustChains.size());
		
		TrustChain chain = trustChains.iterator().next();
		
		assertEquals(OP_SELF_STMT, chain.getLeafConfiguration());
		assertEquals(INTERMEDIATE_STMT_ABOUT_OP, chain.getSuperiorStatements().get(0));
		assertEquals(ANCHOR_STMT_ABOUT_INTERMEDIATE, chain.getSuperiorStatements().get(1));
		assertEquals(2, chain.getSuperiorStatements().size());
		
		// Test the chain resolver
		TrustChainResolver resolver = new TrustChainResolver(Collections.singletonMap(new EntityID(ANCHOR_ISSUER), ANCHOR_JWK_SET), TrustChainConstraints.NO_CONSTRAINTS, statementRetriever);
		
		TrustChainSet resolvedChains = resolver.resolveTrustChains(OP_SELF_STMT);
		
		assertEquals(1, resolvedChains.size());
		
		chain = resolvedChains.iterator().next();
		
		assertEquals(OP_SELF_STMT, chain.getLeafConfiguration());
		assertEquals(INTERMEDIATE_STMT_ABOUT_OP, chain.getSuperiorStatements().get(0));
		assertEquals(ANCHOR_STMT_ABOUT_INTERMEDIATE, chain.getSuperiorStatements().get(1));
		assertEquals(2, chain.getSuperiorStatements().size());
	}
	
	
	public void testResolve_withMaxPathLengthConstraint() throws InvalidEntityMetadataException {
		
		EntityStatementRetriever statementRetriever = new EntityStatementRetriever() {
			@Override
			public EntityStatement fetchEntityConfiguration(EntityID target) throws ResolveException {
				if (OP_ISSUER.getValue().equals(target.getValue())) {
					return OP_SELF_STMT;
				} else if (INTERMEDIATE_ISSUER.getValue().equals(target.getValue())) {
					return INTERMEDIATE_SELF_STMT;
				} else if (ANCHOR_ISSUER.getValue().equals(target.getValue())) {
					return ANCHOR_SELF_STMT;
				} else {
					throw new ResolveException("Invalid target");
				}
			}
			
			
			@Override
			public EntityStatement fetchEntityStatement(URI federationAPIEndpoint, EntityID issuer, EntityID subject) throws ResolveException {
				if (ANCHOR_FEDERATION_API_URI.equals(federationAPIEndpoint)) {
					if (ANCHOR_ISSUER.getValue().equals(issuer.getValue()) && INTERMEDIATE_ISSUER.getValue().equals(subject.getValue())) {
						return ANCHOR_STMT_ABOUT_INTERMEDIATE;
					}
					throw new ResolveException("Unknown subject: " + subject);
				} else if (INTERMEDIATE_FEDERATION_API_URI.equals(federationAPIEndpoint)) {
					if (INTERMEDIATE_ISSUER.getValue().equals(issuer.getValue()) && OP_ISSUER.getValue().equals(subject.getValue())) {
						return INTERMEDIATE_STMT_ABOUT_OP;
					}
					throw new ResolveException("Unknown subject: " + subject);
				} else {
					throw new ResolveException("Exception");
				}
			}
		};
		
		// Test the chain retriever
		TrustChainConstraints constraints = new TrustChainConstraints(0);
		assertEquals(0, constraints.getMaxPathLength());
		
		DefaultTrustChainRetriever chainRetriever = new DefaultTrustChainRetriever(statementRetriever, constraints);
		assertEquals(constraints, chainRetriever.getConstraints());
		
		TrustChainSet trustChains = chainRetriever.retrieve(new EntityID(OP_ISSUER), null, Collections.singleton(new EntityID(ANCHOR_ISSUER)));
		assertTrue(trustChains.isEmpty());
		
		ResolveException resolveException = (ResolveException)chainRetriever.getAccumulatedExceptions().get(0);
		assertEquals("Reached max number of intermediates in chain at " + INTERMEDIATE_ISSUER, resolveException.getMessage());
		assertEquals(1, chainRetriever.getAccumulatedExceptions().size());
	}
	
	
	public void testResolve_withExcludedConstraint() throws InvalidEntityMetadataException {
		
		EntityStatementRetriever statementRetriever = new EntityStatementRetriever() {
			@Override
			public EntityStatement fetchEntityConfiguration(EntityID target) throws ResolveException {
				if (OP_ISSUER.getValue().equals(target.getValue())) {
					return OP_SELF_STMT;
				} else if (INTERMEDIATE_ISSUER.getValue().equals(target.getValue())) {
					return INTERMEDIATE_SELF_STMT;
				} else if (ANCHOR_ISSUER.getValue().equals(target.getValue())) {
					return ANCHOR_SELF_STMT;
				} else {
					throw new ResolveException("Invalid target");
				}
			}
			
			
			@Override
			public EntityStatement fetchEntityStatement(URI federationAPIEndpoint, EntityID issuer, EntityID subject) throws ResolveException {
				if (ANCHOR_FEDERATION_API_URI.equals(federationAPIEndpoint)) {
					if (ANCHOR_ISSUER.getValue().equals(issuer.getValue()) && INTERMEDIATE_ISSUER.getValue().equals(subject.getValue())) {
						return ANCHOR_STMT_ABOUT_INTERMEDIATE;
					}
					throw new ResolveException("Unknown subject: " + subject);
				} else if (INTERMEDIATE_FEDERATION_API_URI.equals(federationAPIEndpoint)) {
					if (INTERMEDIATE_ISSUER.getValue().equals(issuer.getValue()) && OP_ISSUER.getValue().equals(subject.getValue())) {
						return INTERMEDIATE_STMT_ABOUT_OP;
					}
					throw new ResolveException("Unknown subject: " + subject);
				} else {
					throw new ResolveException("Exception");
				}
			}
		};
		
		// Test the chain retriever
		List<EntityIDConstraint> excluded = Collections.singletonList((EntityIDConstraint) new ExactMatchEntityIDConstraint(new EntityID(INTERMEDIATE_ISSUER.getValue())));
		TrustChainConstraints constraints = new TrustChainConstraints(-1, null, excluded, null);
		
		assertEquals(-1, constraints.getMaxPathLength());
		assertTrue(constraints.getPermittedEntityIDs().isEmpty());
		assertEquals(excluded, constraints.getExcludedEntityIDs());
		
		DefaultTrustChainRetriever chainRetriever = new DefaultTrustChainRetriever(statementRetriever, constraints);
		assertEquals(constraints, chainRetriever.getConstraints());
		
		TrustChainSet trustChains = chainRetriever.retrieve(new EntityID(OP_ISSUER), null, Collections.singleton(new EntityID(ANCHOR_ISSUER)));
		assertTrue(trustChains.isEmpty());
		
		ResolveException resolveException = (ResolveException)chainRetriever.getAccumulatedExceptions().get(0);
		assertEquals("Reached authority which isn't permitted according to constraints: " + INTERMEDIATE_ISSUER, resolveException.getMessage());
		assertEquals(1, chainRetriever.getAccumulatedExceptions().size());
	}
}
