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
import java.util.*;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.federation.entities.*;
import com.nimbusds.openid.connect.sdk.federation.policy.MetadataPolicy;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.AddOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.DefaultOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.OneOfOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.SubsetOfOperation;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;


public class TrustChainTest extends TestCase {
	
	
	public static final EntityID ANCHOR_ENTITY_ID = new EntityID("https://federation.example.com");
	
	public static final RSAKey ANCHOR_RSA_JWK;
	
	public static final JWKSet ANCHOR_JWK_SET;
	
	public static final EntityID INTERMEDIATE_ENTITY_ID = new EntityID("https://some-org.example.com");
	
	public static final RSAKey INTERMEDIATE_RSA_JWK;
	
	public static final JWKSet INTERMEDIATE_JWK_SET;
	
	public static final RSAKey OP_RSA_JWK;
	
	public static final JWKSet OP_JWK_SET;
	
	public static final OIDCProviderMetadata OP_METADATA;
	
	public static final FederationEntityMetadata ANCHOR_METADATA;
	
	static {
		try {
			// Trust anchor
			ANCHOR_RSA_JWK = new RSAKeyGenerator(2048)
				.keyIDFromThumbprint(true)
				.keyUse(KeyUse.SIGNATURE)
				.generate();
			ANCHOR_JWK_SET = new JWKSet(ANCHOR_RSA_JWK.toPublicJWK());
			
			// Intermediate
			INTERMEDIATE_RSA_JWK = new RSAKeyGenerator(2048)
				.keyIDFromThumbprint(true)
				.keyUse(KeyUse.SIGNATURE)
				.generate();
			INTERMEDIATE_JWK_SET = new JWKSet(INTERMEDIATE_RSA_JWK.toPublicJWK());
			
			// OP
			OP_RSA_JWK = new RSAKeyGenerator(2048)
				.keyIDFromThumbprint(true)
				.keyUse(KeyUse.SIGNATURE)
				.generate();
			OP_JWK_SET = new JWKSet(OP_RSA_JWK.toPublicJWK());
			
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
		
		OP_METADATA = new OIDCProviderMetadata(
			new Issuer("https://op.c2id.com"),
			Collections.singletonList(SubjectType.PAIRWISE),
			URI.create("https://op.c2id.com/jwks.json"));
		OP_METADATA.setAuthorizationEndpointURI(URI.create("https://op.c2id.com/login"));
		OP_METADATA.setTokenEndpointURI(URI.create("https://op.c2id.com/token"));
		OP_METADATA.applyDefaults();
		
		ANCHOR_METADATA = new FederationEntityMetadata(URI.create("https://federation.example.com/fetch"));
		ANCHOR_METADATA.setFederationListEndpointURI(URI.create("https://federation.example.com/list"));
	}
	
	
	public static EntityStatementClaimsSet createOPStatementClaimsSet(final Issuer iss,
									  final EntityID authority) {
		
		Date now = new Date();
		long nowTS = DateUtils.toSecondsSinceEpoch(now);
		Date iat = DateUtils.fromSecondsSinceEpoch(nowTS);
		Date exp = DateUtils.fromSecondsSinceEpoch(nowTS + 60);
		
		Subject sub = new Subject(OP_METADATA.getIssuer().getValue());
		List<EntityID> authorityHints = Collections.singletonList(authority);
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			iss,
			sub,
			iat,
			exp,
			OP_JWK_SET);
		stmt.setOPMetadata(OP_METADATA);
		stmt.setAuthorityHints(authorityHints);
		return stmt;
	}
	
	
	public static EntityStatementClaimsSet createOPSelfStatementClaimsSet(final EntityID authority) {
		
		return createOPStatementClaimsSet(OP_METADATA.getIssuer(), authority);
	}
	
	
	public static EntityStatementClaimsSet createIntermediateStatementClaimsSet(final EntityID authority) {
		
		Date now = new Date();
		long nowTS = DateUtils.toSecondsSinceEpoch(now);
		Date iat = DateUtils.fromSecondsSinceEpoch(nowTS);
		Date exp = DateUtils.fromSecondsSinceEpoch(nowTS + 60);
		
		Issuer iss = new Issuer(authority.getValue());
		Subject sub = new Subject("https://some-org.example.com");
		List<EntityID> authorityHints = Collections.singletonList(authority);
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			iss,
			sub,
			iat,
			exp,
			INTERMEDIATE_JWK_SET);
		stmt.setAuthorityHints(authorityHints);
		return stmt;
	}
	
	
	public static EntityStatementClaimsSet createAnchorSelfStatementClaimsSet() {
		
		Date now = new Date();
		long nowTS = DateUtils.toSecondsSinceEpoch(now);
		Date iat = DateUtils.fromSecondsSinceEpoch(nowTS);
		Date exp = DateUtils.fromSecondsSinceEpoch(nowTS + 60);
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			ANCHOR_ENTITY_ID.toIssuer(),
			ANCHOR_ENTITY_ID.toSubject(),
			iat,
			exp,
			ANCHOR_JWK_SET
		);
		stmt.setFederationEntityMetadata(ANCHOR_METADATA);
		return stmt;
	}
	
	
	// Anchor -> OP
	public void testMinimal() throws Exception {
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(ANCHOR_ENTITY_ID.getValue()), ANCHOR_ENTITY_ID);
		EntityStatement anchorStmtAboutLeaf = EntityStatement.sign(anchorClaimsAboutLeaf, ANCHOR_RSA_JWK);
		
		List<EntityStatement> superiorStatements = Collections.singletonList(anchorStmtAboutLeaf);
		TrustChain trustChain = new TrustChain(leafStmt, superiorStatements);
		
		assertEquals(leafStmt, trustChain.getLeafConfiguration());
		assertEquals(superiorStatements, trustChain.getSuperiorStatements());
		assertNull(trustChain.getTrustAnchorConfiguration());
		
		assertEquals(ANCHOR_ENTITY_ID, trustChain.getTrustAnchorEntityID());
		
		trustChain.verifySignatures(ANCHOR_JWK_SET);
		
		// Iterator from leaf
		Iterator<EntityStatement> it = trustChain.iteratorFromLeaf();
		
		assertTrue(it.hasNext());
		assertEquals(leafStmt, it.next());
		
		assertTrue(it.hasNext());
		assertEquals(anchorStmtAboutLeaf, it.next());
		
		assertFalse(it.hasNext());
		assertNull(it.next());
		
		assertEquals(1, trustChain.length());
		
		assertTrue(trustChain.resolveCombinedMetadataPolicy(EntityType.OPENID_PROVIDER).entrySet().isEmpty());
		assertTrue(trustChain.resolveCombinedMetadataPolicy(EntityType.OPENID_RELYING_PARTY).entrySet().isEmpty());
		
		// Serialise and parse
		List<String> serializedJWTs = trustChain.toSerializedJWTs();
		assertEquals(2, serializedJWTs.size());
		trustChain = TrustChain.parseSerialized(serializedJWTs);
		assertEquals(leafStmt.getClaimsSet(), trustChain.getLeafConfiguration().getClaimsSet());
		assertEquals(anchorClaimsAboutLeaf, trustChain.getSuperiorStatements().get(0).getClaimsSet());
		assertNull(trustChain.getTrustAnchorConfiguration());
		assertEquals(ANCHOR_ENTITY_ID, trustChain.getTrustAnchorEntityID());
		trustChain.verifySignatures(ANCHOR_JWK_SET);
	}
	
	
	// Anchor -> Intermediate -> OP
	public void testWithIntermediate() throws Exception {
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(INTERMEDIATE_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet intermediateClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(INTERMEDIATE_ENTITY_ID), INTERMEDIATE_ENTITY_ID);
		EntityStatement intermediateStmtAboutLeaf = EntityStatement.sign(intermediateClaimsAboutLeaf, INTERMEDIATE_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutIntermediate = createIntermediateStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement anchorStmtAboutIntermediate = EntityStatement.sign(anchorClaimsAboutIntermediate, ANCHOR_RSA_JWK);
		
		List<EntityStatement> superiorStatements = Arrays.asList(intermediateStmtAboutLeaf, anchorStmtAboutIntermediate);
		TrustChain trustChain = new TrustChain(leafStmt, superiorStatements);
		
		assertEquals(leafStmt, trustChain.getLeafConfiguration());
		assertEquals(superiorStatements, trustChain.getSuperiorStatements());
		assertNull(trustChain.getTrustAnchorConfiguration());
		
		assertEquals(ANCHOR_ENTITY_ID, trustChain.getTrustAnchorEntityID());
		
		trustChain.verifySignatures(ANCHOR_JWK_SET);
		
		assertNotNull(trustChain.resolveExpirationTime());
		
		// Iterator from leaf
		Iterator<EntityStatement> it = trustChain.iteratorFromLeaf();
		
		assertTrue(it.hasNext());
		assertEquals(leafStmt, it.next());
		
		assertTrue(it.hasNext());
		assertEquals(intermediateStmtAboutLeaf, it.next());
		
		assertTrue(it.hasNext());
		assertEquals(anchorStmtAboutIntermediate, it.next());
		
		assertFalse(it.hasNext());
		assertNull(it.next());
		
		assertEquals(2, trustChain.length());
		
		assertTrue(trustChain.resolveCombinedMetadataPolicy(EntityType.OPENID_PROVIDER).entrySet().isEmpty());
		assertTrue(trustChain.resolveCombinedMetadataPolicy(EntityType.OPENID_RELYING_PARTY).entrySet().isEmpty());
		
		// Serialise and parse
		List<String> serializedJWTs = trustChain.toSerializedJWTs();
		assertEquals(3, serializedJWTs.size());
		trustChain = TrustChain.parseSerialized(serializedJWTs);
		assertEquals(leafStmt.getClaimsSet(), trustChain.getLeafConfiguration().getClaimsSet());
		assertEquals(intermediateClaimsAboutLeaf, trustChain.getSuperiorStatements().get(0).getClaimsSet());
		assertEquals(anchorClaimsAboutIntermediate, trustChain.getSuperiorStatements().get(1).getClaimsSet());
		assertNull(trustChain.getTrustAnchorConfiguration());
		assertEquals(ANCHOR_ENTITY_ID, trustChain.getTrustAnchorEntityID());
		trustChain.verifySignatures(ANCHOR_JWK_SET);
	}
	
	
	// Anchor -> OP
	public void testMinimal_withAnchorConfig() throws Exception {
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(ANCHOR_ENTITY_ID.getValue()), ANCHOR_ENTITY_ID);
		EntityStatement anchorStmtAboutLeaf = EntityStatement.sign(anchorClaimsAboutLeaf, ANCHOR_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaims = createAnchorSelfStatementClaimsSet();
		EntityStatement anchorStmt = EntityStatement.sign(anchorClaims, ANCHOR_RSA_JWK);
		
		List<EntityStatement> superiorStatements = Collections.singletonList(anchorStmtAboutLeaf);
		TrustChain trustChain = new TrustChain(leafStmt, superiorStatements, anchorStmt);
		
		assertEquals(leafStmt, trustChain.getLeafConfiguration());
		assertEquals(superiorStatements, trustChain.getSuperiorStatements());
		assertEquals(anchorStmt, trustChain.getTrustAnchorConfiguration());
		
		assertEquals(ANCHOR_ENTITY_ID, trustChain.getTrustAnchorEntityID());
		
		trustChain.verifySignatures(ANCHOR_JWK_SET);
		
		// Iterator from leaf
		Iterator<EntityStatement> it = trustChain.iteratorFromLeaf();
		
		assertTrue(it.hasNext());
		assertEquals(leafStmt, it.next());
		
		assertTrue(it.hasNext());
		assertEquals(anchorStmtAboutLeaf, it.next());
		
		assertFalse(it.hasNext());
		assertNull(it.next());
		
		assertEquals(1, trustChain.length());
		
		assertTrue(trustChain.resolveCombinedMetadataPolicy(EntityType.OPENID_PROVIDER).entrySet().isEmpty());
		assertTrue(trustChain.resolveCombinedMetadataPolicy(EntityType.OPENID_RELYING_PARTY).entrySet().isEmpty());
		
		// Serialise and parse
		List<String> serializedJWTs = trustChain.toSerializedJWTs();
		assertEquals(3, serializedJWTs.size());
		trustChain = TrustChain.parseSerialized(serializedJWTs);
		assertEquals(leafStmt.getClaimsSet(), trustChain.getLeafConfiguration().getClaimsSet());
		assertEquals(anchorClaimsAboutLeaf, trustChain.getSuperiorStatements().get(0).getClaimsSet());
		assertEquals(anchorClaims, trustChain.getTrustAnchorConfiguration().getClaimsSet());
		assertEquals(ANCHOR_ENTITY_ID, trustChain.getTrustAnchorEntityID());
		trustChain.verifySignatures(ANCHOR_JWK_SET);
	}
	
	
	// Anchor -> Intermediate -> OP
	public void testWithIntermediate_withAnchorConfig() throws Exception {
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(INTERMEDIATE_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet intermediateClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(INTERMEDIATE_ENTITY_ID), INTERMEDIATE_ENTITY_ID);
		EntityStatement intermediateStmtAboutLeaf = EntityStatement.sign(intermediateClaimsAboutLeaf, INTERMEDIATE_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutIntermediate = createIntermediateStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement anchorStmtAboutIntermediate = EntityStatement.sign(anchorClaimsAboutIntermediate, ANCHOR_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaims = createAnchorSelfStatementClaimsSet();
		EntityStatement anchorStmt = EntityStatement.sign(anchorClaims, ANCHOR_RSA_JWK);
		
		List<EntityStatement> superiorStatements = Arrays.asList(intermediateStmtAboutLeaf, anchorStmtAboutIntermediate);
		TrustChain trustChain = new TrustChain(leafStmt, superiorStatements, anchorStmt);
		
		assertEquals(leafStmt, trustChain.getLeafConfiguration());
		assertEquals(superiorStatements, trustChain.getSuperiorStatements());
		assertEquals(anchorStmt, trustChain.getTrustAnchorConfiguration());
		
		assertEquals(ANCHOR_ENTITY_ID, trustChain.getTrustAnchorEntityID());
		
		trustChain.verifySignatures(ANCHOR_JWK_SET);
		
		assertNotNull(trustChain.resolveExpirationTime());
		
		// Iterator from leaf
		Iterator<EntityStatement> it = trustChain.iteratorFromLeaf();
		
		assertTrue(it.hasNext());
		assertEquals(leafStmt, it.next());
		
		assertTrue(it.hasNext());
		assertEquals(intermediateStmtAboutLeaf, it.next());
		
		assertTrue(it.hasNext());
		assertEquals(anchorStmtAboutIntermediate, it.next());
		
		assertFalse(it.hasNext());
		assertNull(it.next());
		
		assertEquals(2, trustChain.length());
		
		assertTrue(trustChain.resolveCombinedMetadataPolicy(EntityType.OPENID_PROVIDER).entrySet().isEmpty());
		assertTrue(trustChain.resolveCombinedMetadataPolicy(EntityType.OPENID_RELYING_PARTY).entrySet().isEmpty());
		
		// Serialise and parse
		List<String> serializedJWTs = trustChain.toSerializedJWTs();
		assertEquals(4, serializedJWTs.size());
		trustChain = TrustChain.parseSerialized(serializedJWTs);
		assertEquals(leafStmt.getClaimsSet(), trustChain.getLeafConfiguration().getClaimsSet());
		assertEquals(intermediateClaimsAboutLeaf, trustChain.getSuperiorStatements().get(0).getClaimsSet());
		assertEquals(anchorClaimsAboutIntermediate, trustChain.getSuperiorStatements().get(1).getClaimsSet());
		assertEquals(anchorClaims, trustChain.getTrustAnchorConfiguration().getClaimsSet());
		assertEquals(ANCHOR_ENTITY_ID, trustChain.getTrustAnchorEntityID());
		trustChain.verifySignatures(ANCHOR_JWK_SET);
	}
	
	
	public void testMinimal_resolveExpirationTime() throws Exception {
		
		Date now = new Date();
		long nowTS = DateUtils.toSecondsSinceEpoch(now);
		Date nearestExp = DateUtils.fromSecondsSinceEpoch(nowTS + 10);
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(INTERMEDIATE_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(ANCHOR_ENTITY_ID.getValue()), ANCHOR_ENTITY_ID);
		// Override exp
		anchorClaimsAboutLeaf = new EntityStatementClaimsSet(
			new JWTClaimsSet.Builder(anchorClaimsAboutLeaf.toJWTClaimsSet())
				.expirationTime(nearestExp)
				.build());
		EntityStatement anchorStmtAboutLeaf = EntityStatement.sign(anchorClaimsAboutLeaf, ANCHOR_RSA_JWK);
		
		List<EntityStatement> superiorStatements = Collections.singletonList(anchorStmtAboutLeaf);
		TrustChain trustChain = new TrustChain(leafStmt, superiorStatements);
		
		assertEquals(nearestExp, trustChain.resolveExpirationTime());
	}
	
	
	public void testWithIntermediate_resolveExpirationTime() throws Exception {
		
		Date now = new Date();
		long nowTS = DateUtils.toSecondsSinceEpoch(now);
		Date nearestExp = DateUtils.fromSecondsSinceEpoch(nowTS + 10);
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet intermediateClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(INTERMEDIATE_ENTITY_ID), INTERMEDIATE_ENTITY_ID);
		// Override exp
		intermediateClaimsAboutLeaf = new EntityStatementClaimsSet(
			new JWTClaimsSet.Builder(intermediateClaimsAboutLeaf.toJWTClaimsSet())
				.expirationTime(nearestExp)
				.build());
		EntityStatement intermediateStmtAboutLeaf = EntityStatement.sign(intermediateClaimsAboutLeaf, INTERMEDIATE_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutIntermediate = createIntermediateStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement anchorStmtAboutIntermediate = EntityStatement.sign(anchorClaimsAboutIntermediate, ANCHOR_RSA_JWK);
		
		List<EntityStatement> superiorStatements = Arrays.asList(intermediateStmtAboutLeaf, anchorStmtAboutIntermediate);
		TrustChain trustChain = new TrustChain(leafStmt, superiorStatements);
		
		assertEquals(nearestExp, trustChain.resolveExpirationTime());
	}
	
	
	public void testConstructor_nullLeaf() throws JOSEException {
		
		EntityStatementClaimsSet anchorClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(ANCHOR_ENTITY_ID.getValue()), ANCHOR_ENTITY_ID);
		EntityStatement anchorStmtAboutLeaf = EntityStatement.sign(anchorClaimsAboutLeaf, ANCHOR_RSA_JWK);
		
		List<EntityStatement> superiorStatements = Collections.singletonList(anchorStmtAboutLeaf);
		
		try {
			new TrustChain(null, superiorStatements);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The leaf entity configuration must not be null", e.getMessage());
		}
	}
	
	
	public void testConstructor_nullSuperiors() throws JOSEException {
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		try {
			new TrustChain(leafStmt, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("There must be at least one superior statement (issued by the trust anchor)", e.getMessage());
		}
	}
	
	
	public void testConstructor_emptySuperiors() throws JOSEException {
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		try {
			new TrustChain(leafStmt, Collections.<EntityStatement>emptyList());
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("There must be at least one superior statement (issued by the trust anchor)", e.getMessage());
		}
	}
	
	
	public void testConstructor_brokenSubIssChain() throws Exception {
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(ANCHOR_ENTITY_ID.getValue()), ANCHOR_ENTITY_ID);
		
		// Replace sub with another
		anchorClaimsAboutLeaf = new EntityStatementClaimsSet(
			new JWTClaimsSet.Builder(anchorClaimsAboutLeaf.toJWTClaimsSet())
				.subject("https://invalid-subject.example.com")
				.build());
		
		EntityStatement anchorStmtAboutLeaf = EntityStatement.sign(anchorClaimsAboutLeaf, ANCHOR_RSA_JWK);
		
		List<EntityStatement> superiorStatements = Collections.singletonList(anchorStmtAboutLeaf);
		
		try {
			new TrustChain(leafStmt, superiorStatements);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("Broken subject - issuer chain", e.getMessage());
		}
	}
	
	
	public void testConstructor_illegalTrustAnchorConfig() throws Exception {
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(ANCHOR_ENTITY_ID.getValue()), ANCHOR_ENTITY_ID);
		EntityStatement anchorStmtAboutLeaf = EntityStatement.sign(anchorClaimsAboutLeaf, ANCHOR_RSA_JWK);
		
		List<EntityStatement> superiorStatements = Collections.singletonList(anchorStmtAboutLeaf);
		
		try {
			new TrustChain(leafStmt, superiorStatements, leafStmt); // leaf instead of anchor
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("Broken subject - issuer chain", e.getMessage());
		}
	}
	
	
	public void testConstructor_illegalTrustAnchorConfig_noSelfStatement() throws Exception {
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(ANCHOR_ENTITY_ID.getValue()), ANCHOR_ENTITY_ID);
		EntityStatement anchorStmtAboutLeaf = EntityStatement.sign(anchorClaimsAboutLeaf, ANCHOR_RSA_JWK);
		
		List<EntityStatement> superiorStatements = Collections.singletonList(anchorStmtAboutLeaf);
		
		try {
			new TrustChain(leafStmt, superiorStatements, anchorStmtAboutLeaf); // statement instead of anchor
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The trust anchor entity configuration must be a self-statement", e.getMessage());
		}
	}
	
	
	public void testVerifySignature_invalidLeafSignature()
		throws Exception {
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		
		RSAKey invalidKey = new RSAKeyGenerator(2048).keyID(OP_RSA_JWK.getKeyID()).generate();
		
		SignedJWT leafJWT = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(EntityStatement.JOSE_OBJECT_TYPE)
				.keyID(invalidKey.getKeyID())
				.build(),
			leafClaims.toJWTClaimsSet());
		leafJWT.sign(new RSASSASigner(invalidKey));
		
		EntityStatement leafStmt = EntityStatement.parse(leafJWT);
		
		EntityStatementClaimsSet anchorClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(ANCHOR_ENTITY_ID.getValue()), ANCHOR_ENTITY_ID);
		EntityStatement anchorStmtAboutLeaf = EntityStatement.sign(anchorClaimsAboutLeaf, ANCHOR_RSA_JWK);
		
		List<EntityStatement> superiorStatements = Collections.singletonList(anchorStmtAboutLeaf);
		TrustChain trustChain = new TrustChain(leafStmt, superiorStatements);
		
		try {
			trustChain.verifySignatures(ANCHOR_JWK_SET);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Invalid leaf entity configuration: JWT rejected: Invalid signature", e.getMessage());
		}
	}
	
	
	public void testVerifySignature_invalidAnchorSignature()
		throws Exception {
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(ANCHOR_ENTITY_ID.getValue()), ANCHOR_ENTITY_ID);
		
		RSAKey invalidKey = new RSAKeyGenerator(2048).keyID(ANCHOR_RSA_JWK.getKeyID()).generate();
		
		SignedJWT anchorJWT = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(EntityStatement.JOSE_OBJECT_TYPE)
				.keyID(invalidKey.getKeyID())
				.build(),
			anchorClaimsAboutLeaf.toJWTClaimsSet());
		anchorJWT.sign(new RSASSASigner(invalidKey));
		
		EntityStatement anchorStmtAboutLeaf = EntityStatement.parse(anchorJWT);
		
		List<EntityStatement> superiorStatements = Collections.singletonList(anchorStmtAboutLeaf);
		TrustChain trustChain = new TrustChain(leafStmt, superiorStatements);
		
		try {
			trustChain.verifySignatures(ANCHOR_JWK_SET);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Invalid statement from https://federation.example.com: JWT rejected: Invalid signature", e.getMessage());
		}
	}
	
	
	public void testVerifySignature_invalidAnchorConfigSignature()
		throws Exception {
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(ANCHOR_ENTITY_ID.getValue()), ANCHOR_ENTITY_ID);
		EntityStatement anchorStmtAboutLeaf = EntityStatement.sign(anchorClaimsAboutLeaf, ANCHOR_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaims = createAnchorSelfStatementClaimsSet();
		RSAKey invalidKey = new RSAKeyGenerator(2048).keyID(ANCHOR_RSA_JWK.getKeyID()).generate();
		SignedJWT anchorJWT = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(EntityStatement.JOSE_OBJECT_TYPE)
				.keyID(invalidKey.getKeyID())
				.build(),
			anchorClaims.toJWTClaimsSet());
		anchorJWT.sign(new RSASSASigner(invalidKey));
		EntityStatement anchorStmt = EntityStatement.parse(anchorJWT);
		
		List<EntityStatement> superiorStatements = Collections.singletonList(anchorStmtAboutLeaf);
		
		TrustChain trustChain = new TrustChain(leafStmt, superiorStatements, anchorStmt);
		
		try {
			trustChain.verifySignatures(ANCHOR_JWK_SET);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Invalid trust anchor entity configuration: JWT rejected: Invalid signature", e.getMessage());
		}
	}
	
	
	public void testVerifySignature_anchorKeyNotFoundInItsConfig()
		throws Exception {
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(ANCHOR_ENTITY_ID.getValue()), ANCHOR_ENTITY_ID);
		EntityStatement anchorStmtAboutLeaf = EntityStatement.sign(anchorClaimsAboutLeaf, ANCHOR_RSA_JWK);
		
		RSAKey newAnchorKey = new RSAKeyGenerator(2048).keyIDFromThumbprint(true).generate();
		EntityStatementClaimsSet anchorClaims = createAnchorSelfStatementClaimsSet();
		anchorClaims = new EntityStatementClaimsSet(
			anchorClaims.getIssuer(),
			anchorClaims.getSubject(),
			anchorClaims.getIssueTime(),
			anchorClaims.getExpirationTime(),
			new JWKSet(newAnchorKey)
		);
		EntityStatement anchorStmt = EntityStatement.sign(anchorClaims, newAnchorKey);
		
		List<EntityStatement> superiorStatements = Collections.singletonList(anchorStmtAboutLeaf);
		
		TrustChain trustChain = new TrustChain(leafStmt, superiorStatements, anchorStmt);
		
		try {
			trustChain.verifySignatures(ANCHOR_JWK_SET);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Signing JWK with thumbprint " + ANCHOR_RSA_JWK.computeThumbprint() + " not found in trust anchor entity configuration", e.getMessage());
		}
	}
	
	
	// Anchor -> OP
	public void testMinimal_signingJWKNotRegisteredWithAnchor() throws JOSEException, ParseException {
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(ANCHOR_ENTITY_ID.getValue()), ANCHOR_ENTITY_ID);
		// Replace the signing JWK with some other key
		JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder(anchorClaimsAboutLeaf.toJWTClaimsSet())
			.claim(EntityStatementClaimsSet.JWKS_CLAIM_NAME, new JWKSet(new RSAKeyGenerator(2048)
				.keyIDFromThumbprint(true)
				.keyUse(KeyUse.SIGNATURE)
				.generate()).toJSONObject())
			.build();
		anchorClaimsAboutLeaf = new EntityStatementClaimsSet(jwtClaimsSet);
		
		EntityStatement anchorStmtAboutLeaf = EntityStatement.sign(anchorClaimsAboutLeaf, ANCHOR_RSA_JWK);
		
		List<EntityStatement> superiorStatements = Collections.singletonList(anchorStmtAboutLeaf);
		TrustChain trustChain = new TrustChain(leafStmt, superiorStatements);
		
		assertEquals(leafStmt, trustChain.getLeafConfiguration());
		assertEquals(superiorStatements, trustChain.getSuperiorStatements());
		
		assertEquals(ANCHOR_ENTITY_ID, trustChain.getTrustAnchorEntityID());
		
		try {
			trustChain.verifySignatures(ANCHOR_JWK_SET);
			fail();
		} catch (BadJOSEException e) {
			assertEquals(
				"Signing JWK with thumbprint " + OP_RSA_JWK.computeThumbprint() + " not found in entity statement issued from superior https://federation.example.com",
				e.getMessage());
		}
	}
	
	
	public void testResolveMetadataPolicy_simple() throws JOSEException, BadJOSEException, PolicyViolationException {
		
		// Leaf OP self
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		// Anchor about OP
		EntityStatementClaimsSet anchorClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(ANCHOR_ENTITY_ID.getValue()), ANCHOR_ENTITY_ID);
		
		MetadataPolicy opMetadataPolicy = new MetadataPolicy();
		List<PolicyOperation> opsList = new LinkedList<>();
		DefaultOperation defaultOperation = new DefaultOperation();
		defaultOperation.configure(Collections.singletonList("ES256"));
		opsList.add(defaultOperation);
		SubsetOfOperation subsetOfOperation = new SubsetOfOperation();
		subsetOfOperation.configure(Arrays.asList("ES256", "ES384", "ES512"));
		opsList.add(subsetOfOperation);
		opMetadataPolicy.put("id_token_signing_alg_values_supported", opsList);
		
		MetadataPolicy rpMetadataPolicy = new MetadataPolicy();
		opsList = new LinkedList<>();
		defaultOperation = new DefaultOperation();
		defaultOperation.configure("ES256");
		opsList.add(defaultOperation);
		OneOfOperation oneOfOperation = new OneOfOperation();
		oneOfOperation.configure(Arrays.asList("ES256", "ES384", "ES512"));
		opsList.add(oneOfOperation);
		rpMetadataPolicy.put("id_token_signed_response_alg", opsList);
		
		
		JSONObject metadataPolicyJSONObject = new JSONObject();
		metadataPolicyJSONObject.put("openid_provider", opMetadataPolicy.toJSONObject());
		metadataPolicyJSONObject.put("openid_relying_party", rpMetadataPolicy.toJSONObject());
		
		//   "metadata_policy": {
		//    "openid_provider": {
		//      "id_token_signing_alg_values_supported": {
		//        "default": [
		//          "ES256"
		//        ],
		//        "subset_of": [
		//          "ES256",
		//          "ES384",
		//          "ES512"
		//        ]
		//      }
		//    },
		//    "openid_relying_party": {
		//      "id_token_signed_response_alg": {
		//        "default": "ES256",
		//        "one_of": [
		//          "ES256",
		//          "ES384",
		//          "ES512"
		//        ]
		//      }
		//    }
		//  },
		
		anchorClaimsAboutLeaf.setMetadataPolicyJSONObject(metadataPolicyJSONObject);
		EntityStatement anchorStmtAboutLeaf = EntityStatement.sign(anchorClaimsAboutLeaf, ANCHOR_RSA_JWK);
		
		List<EntityStatement> superiorStatements = Collections.singletonList(anchorStmtAboutLeaf);
		TrustChain trustChain = new TrustChain(leafStmt, superiorStatements);
		
		assertEquals(leafStmt, trustChain.getLeafConfiguration());
		assertEquals(superiorStatements, trustChain.getSuperiorStatements());
		
		assertEquals(ANCHOR_ENTITY_ID, trustChain.getTrustAnchorEntityID());
		
		trustChain.verifySignatures(ANCHOR_JWK_SET);
		
		assertEquals(opMetadataPolicy.toJSONObject(), trustChain.resolveCombinedMetadataPolicy(EntityType.OPENID_PROVIDER).toJSONObject());
		assertEquals(rpMetadataPolicy.toJSONObject(), trustChain.resolveCombinedMetadataPolicy(EntityType.OPENID_RELYING_PARTY).toJSONObject());
		assertTrue(trustChain.resolveCombinedMetadataPolicy(EntityType.FEDERATION_ENTITY).toJSONObject().isEmpty());
		assertTrue(trustChain.resolveCombinedMetadataPolicy(EntityType.OAUTH_AUTHORIZATION_SERVER).toJSONObject().isEmpty());
		assertTrue(trustChain.resolveCombinedMetadataPolicy(EntityType.OAUTH_CLIENT).toJSONObject().isEmpty());
		assertTrue(trustChain.resolveCombinedMetadataPolicy(EntityType.OAUTH_RESOURCE).toJSONObject().isEmpty());
	}
	
	
	public void testResolveMetadataPolicy_withIntermediate() throws JOSEException, BadJOSEException, PolicyViolationException, ParseException {
		
		// Leaf OP about self
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(INTERMEDIATE_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		// Intermediate about OP
		EntityStatementClaimsSet intermediateClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(INTERMEDIATE_ENTITY_ID), INTERMEDIATE_ENTITY_ID);
		
		MetadataPolicy opMetadataPolicy = new MetadataPolicy();
		List<PolicyOperation> opsList = new LinkedList<>();
		DefaultOperation defaultOperation = new DefaultOperation();
		defaultOperation.configure(Collections.singletonList("ES256"));
		opsList.add(defaultOperation);
		SubsetOfOperation subsetOfOperation = new SubsetOfOperation();
		subsetOfOperation.configure(Arrays.asList("ES256", "ES384", "ES512"));
		opsList.add(subsetOfOperation);
		opMetadataPolicy.put("id_token_signing_alg_values_supported", opsList);
		
		MetadataPolicy rpMetadataPolicy = new MetadataPolicy();
		opsList = new LinkedList<>();
		defaultOperation = new DefaultOperation();
		defaultOperation.configure("ES256");
		opsList.add(defaultOperation);
		OneOfOperation oneOfOperation = new OneOfOperation();
		oneOfOperation.configure(Arrays.asList("ES256", "ES384", "ES512"));
		opsList.add(oneOfOperation);
		rpMetadataPolicy.put("id_token_signed_response_alg", opsList);
		
		
		JSONObject metadataPolicyJSONObject = new JSONObject();
		metadataPolicyJSONObject.put("openid_provider", opMetadataPolicy.toJSONObject());
		metadataPolicyJSONObject.put("openid_relying_party", rpMetadataPolicy.toJSONObject());
		
		//   "metadata_policy": {
		//    "openid_provider": {
		//      "id_token_signing_alg_values_supported": {
		//        "default": [
		//          "ES256"
		//        ],
		//        "subset_of": [
		//          "ES256",
		//          "ES384",
		//          "ES512"
		//        ]
		//      }
		//    },
		//    "openid_relying_party": {
		//      "id_token_signed_response_alg": {
		//        "default": "ES256",
		//        "one_of": [
		//          "ES256",
		//          "ES384",
		//          "ES512"
		//        ]
		//      }
		//    }
		//  },
		
		intermediateClaimsAboutLeaf.setMetadataPolicyJSONObject(metadataPolicyJSONObject);
		
		EntityStatement intermediateStmtAboutLeaf = EntityStatement.sign(intermediateClaimsAboutLeaf, INTERMEDIATE_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutIntermediate = createIntermediateStatementClaimsSet(ANCHOR_ENTITY_ID);
		
		opMetadataPolicy = new MetadataPolicy();
		opsList = new LinkedList<>();
		AddOperation addOperation = new AddOperation();
		addOperation.configure("support@federation.example.com");
		opsList.add(addOperation);
		opMetadataPolicy.put("contacts", opsList);
		
		metadataPolicyJSONObject = new JSONObject();
		metadataPolicyJSONObject.put("openid_provider", opMetadataPolicy.toJSONObject());
		
		// {
		//  "openid_provider": {
		//    "contacts": {
		//      "add": "support@federation.example.com"
		//    }
		//  }
		//}
		
		anchorClaimsAboutIntermediate.setMetadataPolicyJSONObject(metadataPolicyJSONObject);
		
		EntityStatement anchorStmtAboutIntermediate = EntityStatement.sign(anchorClaimsAboutIntermediate, ANCHOR_RSA_JWK);
		
		List<EntityStatement> superiorStatements = Arrays.asList(intermediateStmtAboutLeaf, anchorStmtAboutIntermediate);
		TrustChain trustChain = new TrustChain(leafStmt, superiorStatements);
		
		assertEquals(leafStmt, trustChain.getLeafConfiguration());
		assertEquals(superiorStatements, trustChain.getSuperiorStatements());
		
		assertEquals(ANCHOR_ENTITY_ID, trustChain.getTrustAnchorEntityID());
		
		trustChain.verifySignatures(ANCHOR_JWK_SET);
		
		String expectedCombinedOPMetadataPolicyJSON = "{" +
			"  \"id_token_signing_alg_values_supported\": {" +
			"    \"default\": [" +
			"      \"ES256\"" +
			"    ]," +
			"    \"subset_of\": [" +
			"      \"ES256\"," +
			"      \"ES384\"," +
			"      \"ES512\"" +
			"    ]" +
			"  }," +
			"  \"contacts\": {" +
			"    \"add\": \"support@federation.example.com\"" +
			"  }" +
			"}";
		
		assertEquals(JSONObjectUtils.parse(expectedCombinedOPMetadataPolicyJSON), trustChain.resolveCombinedMetadataPolicy(EntityType.OPENID_PROVIDER).toJSONObject());
		assertEquals(rpMetadataPolicy.toJSONObject(), trustChain.resolveCombinedMetadataPolicy(EntityType.OPENID_RELYING_PARTY).toJSONObject());
		assertTrue(trustChain.resolveCombinedMetadataPolicy(EntityType.FEDERATION_ENTITY).toJSONObject().isEmpty());
		assertTrue(trustChain.resolveCombinedMetadataPolicy(EntityType.OAUTH_AUTHORIZATION_SERVER).toJSONObject().isEmpty());
		assertTrue(trustChain.resolveCombinedMetadataPolicy(EntityType.OAUTH_CLIENT).toJSONObject().isEmpty());
		assertTrue(trustChain.resolveCombinedMetadataPolicy(EntityType.OAUTH_RESOURCE).toJSONObject().isEmpty());
	}
	
	
	public void testParseJWTs_null() throws ParseException {
		
		try {
			TrustChain.parse(null);
			fail();
		} catch (NullPointerException e) {
			// ok
		}
	}
	
	
	public void testParseSerializedJWTs_null() throws ParseException {
		
		try {
			TrustChain.parseSerialized(null);
			fail();
		} catch (NullPointerException e) {
			// ok
		}
	}
	
	
	public void testParseJWTs_empty() {
		try {
			TrustChain.parse(Collections.<SignedJWT>emptyList());
			fail();
		} catch (ParseException e) {
			assertEquals("There must be at least 2 statement JWTs", e.getMessage());
		}
	}
	
	
	public void testParseJWTs_entityConfigOnly() throws JOSEException {
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		try {
			TrustChain.parse(Collections.singletonList(leafStmt.getSignedStatement()));
			fail();
		} catch (ParseException e) {
			assertEquals("There must be at least 2 statement JWTs", e.getMessage());
		}
	}
	
	
	public void testParseSerializedJWTs_illegalJWTs() {
		
		try {
			TrustChain.parseSerialized(Arrays.asList("abc.def.ghi", "111.222.333"));
			fail();
		} catch (ParseException e) {
			assertTrue(e.getMessage().startsWith("Invalid JWT in trust chain: Invalid JWS header: Invalid JSON:"));
		}
	}
	
	
	public void testParseJWTs_illegalOrderOfStatements_leafNotFirst() throws JOSEException {
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet intermediateClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(INTERMEDIATE_ENTITY_ID), INTERMEDIATE_ENTITY_ID);
		EntityStatement intermediateStmtAboutLeaf = EntityStatement.sign(intermediateClaimsAboutLeaf, INTERMEDIATE_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutIntermediate = createIntermediateStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement anchorStmtAboutIntermediate = EntityStatement.sign(anchorClaimsAboutIntermediate, ANCHOR_RSA_JWK);
		
		try {
			TrustChain.parseSerialized(Arrays.asList(
				anchorStmtAboutIntermediate.getSignedStatement().serialize(),
				intermediateStmtAboutLeaf.getSignedStatement().serialize(),
				leafStmt.getSignedStatement().serialize()));
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal trust chain: The leaf entity configuration must be a self-statement", e.getMessage());
		}
	}
	
	
	public void testParseJWTs_illegalOrderOfStatements_superiorChainBroken() throws JOSEException {
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet intermediateClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(INTERMEDIATE_ENTITY_ID), INTERMEDIATE_ENTITY_ID);
		EntityStatement intermediateStmtAboutLeaf = EntityStatement.sign(intermediateClaimsAboutLeaf, INTERMEDIATE_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutIntermediate = createIntermediateStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement anchorStmtAboutIntermediate = EntityStatement.sign(anchorClaimsAboutIntermediate, ANCHOR_RSA_JWK);
		
		try {
			TrustChain.parseSerialized(Arrays.asList(
				leafStmt.getSignedStatement().serialize(),
				anchorStmtAboutIntermediate.getSignedStatement().serialize(),
				intermediateStmtAboutLeaf.getSignedStatement().serialize()));
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal trust chain: Broken subject - issuer chain", e.getMessage());
		}
	}
	
	
	public void testParseJWTs_illegalOrderOfStatements_illegalAnchorConfig() throws JOSEException {
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet intermediateClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(INTERMEDIATE_ENTITY_ID), INTERMEDIATE_ENTITY_ID);
		EntityStatement intermediateStmtAboutLeaf = EntityStatement.sign(intermediateClaimsAboutLeaf, INTERMEDIATE_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutIntermediate = createIntermediateStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement anchorStmtAboutIntermediate = EntityStatement.sign(anchorClaimsAboutIntermediate, ANCHOR_RSA_JWK);
		
		try {
			TrustChain.parseSerialized(Arrays.asList(
				leafStmt.getSignedStatement().serialize(),
				anchorStmtAboutIntermediate.getSignedStatement().serialize(),
				intermediateStmtAboutLeaf.getSignedStatement().serialize(),
				intermediateStmtAboutLeaf.getSignedStatement().serialize() // repeat
				));
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal trust chain: Broken subject - issuer chain", e.getMessage());
		}
	}
	
	
	public void testParseJWTs_ignoreNullsInList() throws JOSEException, ParseException, BadJOSEException {
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet intermediateClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(INTERMEDIATE_ENTITY_ID), INTERMEDIATE_ENTITY_ID);
		EntityStatement intermediateStmtAboutLeaf = EntityStatement.sign(intermediateClaimsAboutLeaf, INTERMEDIATE_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutIntermediate = createIntermediateStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement anchorStmtAboutIntermediate = EntityStatement.sign(anchorClaimsAboutIntermediate, ANCHOR_RSA_JWK);
		
		TrustChain trustChain = TrustChain.parseSerialized(Arrays.asList(
			leafStmt.getSignedStatement().serialize(),
			null,
			intermediateStmtAboutLeaf.getSignedStatement().serialize(),
			null,
			anchorStmtAboutIntermediate.getSignedStatement().serialize()
		));
		
		assertEquals(2, trustChain.length());
		
		trustChain.verifySignatures(ANCHOR_JWK_SET);
	}
}
