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

package com.nimbusds.openid.connect.sdk.federation.api;


import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import static com.nimbusds.openid.connect.sdk.federation.trust.TrustChainTest.*;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementClaimsSet;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;
import com.nimbusds.openid.connect.sdk.federation.registration.ClientRegistrationType;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;
import com.nimbusds.openid.connect.sdk.federation.trust.marks.TrustMarkClaimsSet;
import com.nimbusds.openid.connect.sdk.federation.trust.marks.TrustMarkEntry;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;


public class ResolveClaimsSetTest extends TestCase {
	
	
	private static final Issuer ISS = new Issuer("https://abc-federation.c2id.com");
	private static final Subject SUB = new Subject("https://op.c2id.com");
	private static final Date IAT = DateUtils.fromSecondsSinceEpoch(1000);
	private static final Date EXP = DateUtils.fromSecondsSinceEpoch(2000);
	
	private static final OIDCProviderMetadata OP_METADATA = new OIDCProviderMetadata(
		new Issuer(SUB),
		Collections.singletonList(SubjectType.PAIRWISE),
		Collections.singletonList(ClientRegistrationType.AUTOMATIC),
		null,
		URI.create("https://op.c2id.com/jwks.jwt"),
		null);
	
	private static final JSONObject METADATA = new JSONObject();
	
	static {
		METADATA.put(EntityType.OPENID_PROVIDER.getValue(), OP_METADATA.toJSONObject());
	}
	
	
	public void testClaimNames() {
		
		assertEquals("iss", ResolveClaimsSet.ISS_CLAIM_NAME);
		assertEquals("sub", ResolveClaimsSet.SUB_CLAIM_NAME);
		assertEquals("iat", ResolveClaimsSet.IAT_CLAIM_NAME);
		assertEquals("exp", ResolveClaimsSet.EXP_CLAIM_NAME);
		assertEquals("metadata", ResolveClaimsSet.METADATA_CLAIM_NAME);
		assertEquals("trust_marks", ResolveClaimsSet.TRUST_MARKS_CLAIM_NAME);
		assertEquals("trust_chain", ResolveClaimsSet.TRUST_CHAIN_CLAIM_NAME);
		
		assertTrue(ResolveClaimsSet.getStandardClaimNames().contains(ResolveClaimsSet.IAT_CLAIM_NAME));
		
		assertTrue(ResolveClaimsSet.getStandardClaimNames().contains(ResolveClaimsSet.ISS_CLAIM_NAME));
		assertTrue(ResolveClaimsSet.getStandardClaimNames().contains(ResolveClaimsSet.SUB_CLAIM_NAME));
		assertTrue(ResolveClaimsSet.getStandardClaimNames().contains(ResolveClaimsSet.IAT_CLAIM_NAME));
		assertTrue(ResolveClaimsSet.getStandardClaimNames().contains(ResolveClaimsSet.EXP_CLAIM_NAME));
		assertTrue(ResolveClaimsSet.getStandardClaimNames().contains(ResolveClaimsSet.METADATA_CLAIM_NAME));
		assertTrue(ResolveClaimsSet.getStandardClaimNames().contains(ResolveClaimsSet.TRUST_MARKS_CLAIM_NAME));
		assertTrue(ResolveClaimsSet.getStandardClaimNames().contains(ResolveClaimsSet.TRUST_CHAIN_CLAIM_NAME));
		assertEquals(7, ResolveClaimsSet.getStandardClaimNames().size());
		
		try {
			ResolveClaimsSet.getStandardClaimNames().add("test");
			fail();
		} catch (UnsupportedOperationException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testMinimal() throws ParseException {
		
		ResolveClaimsSet claimsSet = new ResolveClaimsSet(ISS, SUB, IAT, EXP, METADATA);
		
		claimsSet.validateRequiredClaimsPresence();
		
		assertEquals(ISS, claimsSet.getIssuer());
		assertEquals(SUB, claimsSet.getSubject());
		assertEquals(IAT, claimsSet.getIssueTime());
		assertEquals(EXP, claimsSet.getExpirationTime());
		assertEquals(OP_METADATA.toJSONObject(), claimsSet.getOPMetadata().toJSONObject());
		assertNull(claimsSet.getTrustMarks());
		assertNull(claimsSet.getTrustChain());
		
		assertEquals(5, claimsSet.toJSONObject().size());
		
		claimsSet = new ResolveClaimsSet(claimsSet.toJWTClaimsSet());
		
		assertEquals(ISS, claimsSet.getIssuer());
		assertEquals(SUB, claimsSet.getSubject());
		assertEquals(IAT, claimsSet.getIssueTime());
		assertEquals(EXP, claimsSet.getExpirationTime());
		assertEquals(OP_METADATA.toJSONObject(), claimsSet.getOPMetadata().toJSONObject());
		assertNull(claimsSet.getTrustMarks());
		assertNull(claimsSet.getTrustChain());
	}
	
	
	public void testWithTrustChain() throws JOSEException, ParseException {
		
		ResolveClaimsSet claimsSet = new ResolveClaimsSet(ISS, SUB, IAT, EXP, METADATA);
		
		// trust_chain
		
		EntityStatementClaimsSet leafClaims = createOPSelfStatementClaimsSet(ANCHOR_ENTITY_ID);
		EntityStatement leafStmt = EntityStatement.sign(leafClaims, OP_RSA_JWK);
		
		EntityStatementClaimsSet anchorClaimsAboutLeaf = createOPStatementClaimsSet(new Issuer(ANCHOR_ENTITY_ID.getValue()), ANCHOR_ENTITY_ID);
		EntityStatement anchorStmtAboutLeaf = EntityStatement.sign(anchorClaimsAboutLeaf, ANCHOR_RSA_JWK);
		
		List<EntityStatement> superiorStatements = Collections.singletonList(anchorStmtAboutLeaf);
		TrustChain trustChain = new TrustChain(leafStmt, superiorStatements);
		
		claimsSet.setTrustChain(trustChain);
		
		JSONObject jsonObject = claimsSet.toJSONObject();
		
		assertEquals(trustChain.toSerializedJWTs(), jsonObject.get("trust_chain"));
		
		claimsSet = new ResolveClaimsSet(claimsSet.toJWTClaimsSet());
		
		assertEquals(ISS, claimsSet.getIssuer());
		assertEquals(SUB, claimsSet.getSubject());
		assertEquals(IAT, claimsSet.getIssueTime());
		assertEquals(EXP, claimsSet.getExpirationTime());
		assertEquals(OP_METADATA.toJSONObject(), claimsSet.getOPMetadata().toJSONObject());
		assertNull(claimsSet.getTrustMarks());
		assertEquals(trustChain.toSerializedJWTs(), claimsSet.getTrustChain().toSerializedJWTs());
		
		// clear trust_chain
		claimsSet.setTrustChain(null);
		assertNull(claimsSet.getTrustChain());
	}
	
	
	public void testWithTrustMarks() throws JOSEException, ParseException {
		
		ResolveClaimsSet claimsSet = new ResolveClaimsSet(ISS, SUB, IAT, EXP, METADATA);
		
		// trust_marks
		
		TrustMarkClaimsSet trustMarkClaimsSet_1 = new TrustMarkClaimsSet(
			new Issuer("https://tm1.example.com"),
			SUB,
			new Identifier("tm-1"),
			IAT);
		TrustMarkClaimsSet trustMarkClaimsSet_2 = new TrustMarkClaimsSet(
			new Issuer("https://tm2.example.com"),
			SUB,
			new Identifier("tm-2"),
			IAT);
		
		SignedJWT tm_1 = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), trustMarkClaimsSet_1.toJWTClaimsSet());
		tm_1.sign(new RSASSASigner(new RSAKeyGenerator(2048).generate()));
		
		SignedJWT tm_2 = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), trustMarkClaimsSet_2.toJWTClaimsSet());
		tm_2.sign(new RSASSASigner(new RSAKeyGenerator(2048).generate()));
		
		List<TrustMarkEntry> marks = new LinkedList<>();
		marks.add(new TrustMarkEntry(trustMarkClaimsSet_1.getID(), tm_1));
		marks.add(new TrustMarkEntry(trustMarkClaimsSet_2.getID(), tm_2));
		
		claimsSet.setTrustMarks(marks);
		
		assertEquals(marks.get(0).getID(), claimsSet.getTrustMarks().get(0).getID());
		assertEquals(marks.get(0).getTrustMark().serialize(), claimsSet.getTrustMarks().get(0).getTrustMark().serialize());
		assertEquals(marks.get(1).getID(), claimsSet.getTrustMarks().get(1).getID());
		assertEquals(marks.get(1).getTrustMark().serialize(), claimsSet.getTrustMarks().get(1).getTrustMark().serialize());
		assertEquals(2, claimsSet.getTrustMarks().size());
		
		// clear trust_marks
		claimsSet.setTrustMarks(null);
		assertNull(claimsSet.getTrustMarks());
	}
	
	
	public void testInvalidJWTClaimsSet() {
		
		try {
			new ResolveClaimsSet(new JWTClaimsSet.Builder().build());
			fail();
		} catch (ParseException e) {
			assertEquals("Missing iss (issuer) claim", e.getMessage());
		}
	}
	
	
	public void testConstructor_rejectNullIssuer_asEntityID() {
		
		try {
			new ResolveClaimsSet(
				null,
				new EntityID("https://op.example.com"),
				new Date(),
				new Date(),
				METADATA
			);
			fail();
		} catch (NullPointerException e) {
			// ok
		}
	}
	
	
	public void testConstructor_rejectNullSubject_asEntityID() {
		
		try {
			new ResolveClaimsSet(
				new EntityID("https://fed.example.com"),
				null,
				new Date(),
				new Date(),
				METADATA
			);
			fail();
		} catch (NullPointerException e) {
			// ok
		}
	}
	
	
	public void testConstructor_rejectNullIssueTime() {
		
		try {
			new ResolveClaimsSet(
				new EntityID("https://fed.example.com"),
				new EntityID("https://op.example.com"),
				null,
				new Date(),
				METADATA
			);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The iat (issued-at) claim must not be null", e.getMessage());
		}
	}
	
	
	public void testConstructor_rejectNullExpirationTime() {
		
		try {
			new ResolveClaimsSet(
				new EntityID("https://fed.example.com"),
				new EntityID("https://op.example.com"),
				new Date(),
				null,
				METADATA
			);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The exp (expiration) claim must not be null", e.getMessage());
		}
	}
	
	
	public void testConstructor_rejectNullMetadata() {
		
		try {
			new ResolveClaimsSet(
				new EntityID("https://fed.example.com"),
				new EntityID("https://op.example.com"),
				new Date(),
				new Date(),
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The metadata claim must not be null", e.getMessage());
		}
	}
	
	
	public void testConstructor_rejectNullIssuer() {
		
		try {
			new ResolveClaimsSet(
				null,
				new Subject("https://op.example.com"),
				new Date(),
				new Date(),
				METADATA
			);
			fail();
		} catch (NullPointerException e) {
			// ok
		}
	}
	
	
	public void testConstructor_rejectNullSubject() {
		
		try {
			new ResolveClaimsSet(
				new Issuer("https://fed.example.com"),
				null,
				new Date(),
				new Date(),
				METADATA
			);
			fail();
		} catch (NullPointerException e) {
			// ok
		}
	}
}
