/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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


import java.net.URI;
import java.util.*;

import junit.framework.TestCase;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.federation.policy.MetadataPolicy;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;
import com.nimbusds.openid.connect.sdk.federation.trust.constraints.TrustChainConstraints;
import com.nimbusds.openid.connect.sdk.federation.trust.marks.TrustMarkClaimsSet;
import com.nimbusds.openid.connect.sdk.federation.trust.marks.TrustMarkEntry;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;


public class EntityStatementClaimsSetTest extends TestCase {
	
	
	private static final JWKSet JWK_SET;
	
	
	static {
		try {
			RSAKey rsaJWK = new RSAKeyGenerator(2048)
				.keyIDFromThumbprint(true)
				.keyUse(KeyUse.SIGNATURE)
				.generate();
			JWK_SET = new JWKSet(rsaJWK.toPublicJWK());
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public void testClaimNames() {
		
		assertEquals("iss", EntityStatementClaimsSet.ISS_CLAIM_NAME);
		assertEquals("sub", EntityStatementClaimsSet.SUB_CLAIM_NAME);
		assertEquals("iat", EntityStatementClaimsSet.IAT_CLAIM_NAME);
		assertEquals("exp", EntityStatementClaimsSet.EXP_CLAIM_NAME);
		assertEquals("jwks", EntityStatementClaimsSet.JWKS_CLAIM_NAME);
		assertEquals("aud", EntityStatementClaimsSet.AUD_CLAIM_NAME);
		assertEquals("authority_hints", EntityStatementClaimsSet.AUTHORITY_HINTS_CLAIM_NAME);
		assertEquals("metadata", EntityStatementClaimsSet.METADATA_CLAIM_NAME);
		assertEquals("metadata_policy", EntityStatementClaimsSet.METADATA_POLICY_CLAIM_NAME);
		assertEquals("constraints", EntityStatementClaimsSet.CONSTRAINTS_CLAIM_NAME);
		assertEquals("crit", EntityStatementClaimsSet.CRITICAL_CLAIM_NAME);
		assertEquals("policy_language_crit", EntityStatementClaimsSet.POLICY_LANGUAGE_CRITICAL_CLAIM_NAME);
		assertEquals("trust_marks", EntityStatementClaimsSet.TRUST_MARKS_CLAIM_NAME);
		assertEquals("trust_marks_issuers", EntityStatementClaimsSet.TRUST_MARKS_ISSUERS_CLAIM_NAME);
		assertEquals("trust_anchor_id", EntityStatementClaimsSet.TRUST_ANCHOR_ID_CLAIM_NAME);
		
		assertTrue(EntityStatementClaimsSet.getStandardClaimNames().contains(EntityStatementClaimsSet.IAT_CLAIM_NAME));
		
		assertTrue(EntityStatementClaimsSet.getStandardClaimNames().contains(EntityStatementClaimsSet.ISS_CLAIM_NAME));
		assertTrue(EntityStatementClaimsSet.getStandardClaimNames().contains(EntityStatementClaimsSet.SUB_CLAIM_NAME));
		assertTrue(EntityStatementClaimsSet.getStandardClaimNames().contains(EntityStatementClaimsSet.IAT_CLAIM_NAME));
		assertTrue(EntityStatementClaimsSet.getStandardClaimNames().contains(EntityStatementClaimsSet.EXP_CLAIM_NAME));
		assertTrue(EntityStatementClaimsSet.getStandardClaimNames().contains(EntityStatementClaimsSet.JWKS_CLAIM_NAME));
		assertTrue(EntityStatementClaimsSet.getStandardClaimNames().contains(EntityStatementClaimsSet.AUD_CLAIM_NAME));
		assertTrue(EntityStatementClaimsSet.getStandardClaimNames().contains(EntityStatementClaimsSet.AUTHORITY_HINTS_CLAIM_NAME));
		assertTrue(EntityStatementClaimsSet.getStandardClaimNames().contains(EntityStatementClaimsSet.METADATA_CLAIM_NAME));
		assertTrue(EntityStatementClaimsSet.getStandardClaimNames().contains(EntityStatementClaimsSet.METADATA_POLICY_CLAIM_NAME));
		assertTrue(EntityStatementClaimsSet.getStandardClaimNames().contains(EntityStatementClaimsSet.CONSTRAINTS_CLAIM_NAME));
		assertTrue(EntityStatementClaimsSet.getStandardClaimNames().contains(EntityStatementClaimsSet.CRITICAL_CLAIM_NAME));
		assertTrue(EntityStatementClaimsSet.getStandardClaimNames().contains(EntityStatementClaimsSet.POLICY_LANGUAGE_CRITICAL_CLAIM_NAME));
		assertTrue(EntityStatementClaimsSet.getStandardClaimNames().contains(EntityStatementClaimsSet.TRUST_MARKS_CLAIM_NAME));
		assertTrue(EntityStatementClaimsSet.getStandardClaimNames().contains(EntityStatementClaimsSet.TRUST_MARKS_ISSUERS_CLAIM_NAME));
		assertTrue(EntityStatementClaimsSet.getStandardClaimNames().contains(EntityStatementClaimsSet.TRUST_ANCHOR_ID_CLAIM_NAME));
		assertEquals(15, EntityStatementClaimsSet.getStandardClaimNames().size());
		
		try {
			EntityStatementClaimsSet.getStandardClaimNames().add("test");
			fail();
		} catch (UnsupportedOperationException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testMinimal_withJWKSet()
		throws Exception {
		
		Issuer iss = new Issuer("https://abc-federation.c2id.com");
		Subject sub = new Subject("https://op.c2id.com");
		
		Date iat = DateUtils.fromSecondsSinceEpoch(1000);
		Date exp = DateUtils.fromSecondsSinceEpoch(2000);
		
		// Test ID and EntityID constructors
		for (EntityStatementClaimsSet stmt: Arrays.asList(
			new EntityStatementClaimsSet(
				iss,
				sub,
				iat,
				exp,
				JWK_SET),
			new EntityStatementClaimsSet(
				new EntityID(iss.getValue()),
				new EntityID(sub.getValue()),
				iat,
				exp,
				JWK_SET))) {
			
			stmt.validateRequiredClaimsPresence();
			assertFalse(stmt.isSelfStatement());
			assertFalse(stmt.hasMetadata());
			
			assertEquals(iss, stmt.getIssuer());
			assertEquals(iss.getValue(), stmt.getIssuerEntityID().getValue());
			assertEquals(sub, stmt.getSubject());
			assertEquals(sub.getValue(), stmt.getSubjectEntityID().getValue());
			assertEquals(iat, stmt.getIssueTime());
			assertEquals(exp, stmt.getExpirationTime());
			assertEquals(JWK_SET.toJSONObject(), stmt.getJWKSet().toJSONObject());
			
			assertNull(stmt.getAudience());
			assertNull(stmt.getAuthorityHints());
			assertNull(stmt.getRPMetadata());
			assertNull(stmt.getOPMetadata());
			assertNull(stmt.getOAuthClientMetadata());
			assertNull(stmt.getASMetadata());
			assertNull(stmt.getFederationEntityMetadata());
			assertNull(stmt.getMetadataPolicyJSONObject());
			assertNull(stmt.getTrustAnchorID());
			assertNull(stmt.getConstraints());
			assertNull(stmt.getTrustMarks());
			assertNull(stmt.getTrustMarksIssuers());
			assertNull(stmt.getCriticalExtensionClaims());
			assertNull(stmt.getCriticalPolicyExtensions());
			
			JWTClaimsSet jwtClaimsSet = stmt.toJWTClaimsSet();
			
			assertEquals(iss.getValue(), jwtClaimsSet.getIssuer());
			assertEquals(sub.getValue(), jwtClaimsSet.getSubject());
			assertEquals(iat, jwtClaimsSet.getIssueTime());
			assertEquals(exp, jwtClaimsSet.getExpirationTime());
			assertEquals(JWK_SET.toJSONObject(), jwtClaimsSet.getJSONObjectClaim("jwks"));
			assertEquals(5, jwtClaimsSet.getClaims().size());
			
			stmt = new EntityStatementClaimsSet(jwtClaimsSet);
			
			stmt.validateRequiredClaimsPresence();
			assertFalse(stmt.isSelfStatement());
			assertFalse(stmt.hasMetadata());
			
			assertEquals(iss, stmt.getIssuer());
			assertEquals(iss.getValue(), stmt.getIssuerEntityID().getValue());
			assertEquals(sub, stmt.getSubject());
			assertEquals(sub.getValue(), stmt.getSubjectEntityID().getValue());
			assertEquals(iat, stmt.getIssueTime());
			assertEquals(exp, stmt.getExpirationTime());
			assertEquals(JWK_SET.toJSONObject(), stmt.getJWKSet().toJSONObject());
			
			assertNull(stmt.getAudience());
			assertNull(stmt.getAuthorityHints());
			assertNull(stmt.getRPMetadata());
			assertNull(stmt.getOPMetadata());
			assertNull(stmt.getOAuthClientMetadata());
			assertNull(stmt.getASMetadata());
			assertNull(stmt.getFederationEntityMetadata());
			assertNull(stmt.getMetadataPolicyJSONObject());
			assertNull(stmt.getTrustAnchorID());
			assertNull(stmt.getConstraints());
			assertNull(stmt.getTrustMarks());
			assertNull(stmt.getTrustMarksIssuers());
			assertNull(stmt.getCriticalExtensionClaims());
			assertNull(stmt.getCriticalPolicyExtensions());
		}
	}
	
	
	public void testMinimal_noJWKSet()
		throws Exception {
		
		Issuer iss = new Issuer("https://op.c2id.com");
		Subject sub = new Subject("https://rp.example.com");
		
		Date iat = DateUtils.fromSecondsSinceEpoch(1000);
		Date exp = DateUtils.fromSecondsSinceEpoch(2000);
		
		// Test ID and EntityID constructors
		for (EntityStatementClaimsSet stmt: Arrays.asList(
			new EntityStatementClaimsSet(
				iss,
				sub,
				iat,
				exp,
				null),
			new EntityStatementClaimsSet(
				new EntityID(iss.getValue()),
				new EntityID(sub.getValue()),
				iat,
				exp,
				null))) {
			
			stmt.validateRequiredClaimsPresence();
			assertFalse(stmt.isSelfStatement());
			assertFalse(stmt.hasMetadata());
			
			assertEquals(iss, stmt.getIssuer());
			assertEquals(iss.getValue(), stmt.getIssuerEntityID().getValue());
			assertEquals(sub, stmt.getSubject());
			assertEquals(sub.getValue(), stmt.getSubjectEntityID().getValue());
			assertEquals(iat, stmt.getIssueTime());
			assertEquals(exp, stmt.getExpirationTime());
			assertNull(stmt.getJWKSet());
			
			assertNull(stmt.getAudience());
			assertNull(stmt.getAuthorityHints());
			assertNull(stmt.getRPMetadata());
			assertNull(stmt.getOPMetadata());
			assertNull(stmt.getOAuthClientMetadata());
			assertNull(stmt.getASMetadata());
			assertNull(stmt.getFederationEntityMetadata());
			assertNull(stmt.getMetadataPolicyJSONObject());
			assertNull(stmt.getTrustAnchorID());
			assertNull(stmt.getConstraints());
			assertNull(stmt.getTrustMarks());
			assertNull(stmt.getTrustMarksIssuers());
			assertNull(stmt.getCriticalExtensionClaims());
			assertNull(stmt.getCriticalPolicyExtensions());
			
			JWTClaimsSet jwtClaimsSet = stmt.toJWTClaimsSet();
			
			assertEquals(iss.getValue(), jwtClaimsSet.getIssuer());
			assertEquals(sub.getValue(), jwtClaimsSet.getSubject());
			assertEquals(iat, jwtClaimsSet.getIssueTime());
			assertEquals(exp, jwtClaimsSet.getExpirationTime());
			assertEquals(4, jwtClaimsSet.getClaims().size());
			
			stmt = new EntityStatementClaimsSet(jwtClaimsSet);
			
			stmt.validateRequiredClaimsPresence();
			assertFalse(stmt.isSelfStatement());
			assertFalse(stmt.hasMetadata());
			
			assertEquals(iss, stmt.getIssuer());
			assertEquals(iss.getValue(), stmt.getIssuerEntityID().getValue());
			assertEquals(sub, stmt.getSubject());
			assertEquals(sub.getValue(), stmt.getSubjectEntityID().getValue());
			assertEquals(iat, stmt.getIssueTime());
			assertEquals(exp, stmt.getExpirationTime());
			assertNull(stmt.getJWKSet());
			
			assertNull(stmt.getAudience());
			assertNull(stmt.getAuthorityHints());
			assertNull(stmt.getRPMetadata());
			assertNull(stmt.getOPMetadata());
			assertNull(stmt.getOAuthClientMetadata());
			assertNull(stmt.getASMetadata());
			assertNull(stmt.getFederationEntityMetadata());
			assertNull(stmt.getMetadataPolicyJSONObject());
			assertNull(stmt.getTrustAnchorID());
			assertNull(stmt.getConstraints());
			assertNull(stmt.getTrustMarks());
			assertNull(stmt.getTrustMarksIssuers());
			assertNull(stmt.getCriticalExtensionClaims());
			assertNull(stmt.getCriticalPolicyExtensions());
		}
	}
	
	
	private static OIDCClientMetadata createRPMetadata() {
		
		OIDCClientMetadata rpMetadata = new OIDCClientMetadata();
		rpMetadata.setRedirectionURI(URI.create("https://example.com"));
		rpMetadata.applyDefaults();
		return rpMetadata;
	}
	
	
	private static OIDCProviderMetadata createOPMetadata() {
		
		OIDCProviderMetadata opMetadata = new OIDCProviderMetadata(
			new Issuer("https://openid.c2id.com"),
			Arrays.asList(SubjectType.PUBLIC, SubjectType.PAIRWISE),
			URI.create("https://openid.c2id.com/jwks.json")
		);
		opMetadata.applyDefaults();
		return opMetadata;
	}
	
	
	private static ClientMetadata createOAuthClientMetadata() {
		
		ClientMetadata clientMetadata = new ClientMetadata();
		clientMetadata.setRedirectionURI(URI.create("https://example.com"));
		clientMetadata.applyDefaults();
		return clientMetadata;
	}
	
	
	private static AuthorizationServerMetadata createASMetadata() {
		
		AuthorizationServerMetadata asMetadata = new AuthorizationServerMetadata(new Issuer("https://openid.c2id.com"));
		asMetadata.applyDefaults();
		return asMetadata;
	}
	
	
	private static FederationEntityMetadata createFederationEntityMetadata() {
		
		return new FederationEntityMetadata(URI.create("https://federation.c2id.com/api"));
	}
	
	
	private static JSONObject createMetadataPolicy() throws ParseException {
		
		return JSONObjectUtils.parse("{\"response_types\":{\"subset_of\": [\"code\"]}}");
	}
	
	
	public void testWithRPMetadata_selfStated()
		throws Exception {
		
		Issuer iss = new Issuer("https://rp.c2id.com");
		Subject sub = new Subject("https://rp.c2id.com");
		
		Date iat = DateUtils.fromSecondsSinceEpoch(1000);
		Date exp = DateUtils.fromSecondsSinceEpoch(2000);
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			iss,
			sub,
			iat,
			exp,
			JWK_SET);
		
		try {
			stmt.validateRequiredClaimsPresence();
			fail();
		} catch (ParseException e) {
			assertEquals("Missing required metadata claim for self-statement", e.getMessage());
		}
		assertTrue(stmt.isSelfStatement());
		assertFalse(stmt.hasMetadata());
		
		// aud
		List<Audience> audList = new Audience("123").toSingleAudienceList();
		stmt.setAudience(audList);
		assertEquals(audList, stmt.getAudience());
		
		// authority_hints
		List<EntityID> authorityHints = Collections.singletonList(new EntityID("https://federation.example.com"));
		stmt.setAuthorityHints(authorityHints);
		assertEquals(authorityHints, stmt.getAuthorityHints());
		
		// metadata -> openid_relying_party
		OIDCClientMetadata rpMetadata = createRPMetadata();
		stmt.setRPMetadata(rpMetadata);
		assertEquals(rpMetadata.toJSONObject(), stmt.getRPMetadata().toJSONObject());
		
		// passes now
		assertTrue(stmt.hasMetadata());
		stmt.validateRequiredClaimsPresence();
		
		// metadata_policy
		JSONObject metadataPolicy = createMetadataPolicy();
		stmt.setMetadataPolicyJSONObject(metadataPolicy);
		assertEquals(metadataPolicy, stmt.getMetadataPolicyJSONObject());
		
		// constraints
		TrustChainConstraints constraints = new TrustChainConstraints(10, null, null, null);
		stmt.setConstraints(constraints);
		assertEquals(constraints, stmt.getConstraints());
		
		// crit
		List<String> crit = Collections.singletonList("jti");
		stmt.setCriticalExtensionClaims(crit);
		assertEquals(crit, stmt.getCriticalExtensionClaims());
		
		try {
			stmt.validateRequiredClaimsPresence();
			fail();
		} catch (ParseException e) {
			assertEquals("Missing critical jti claim", e.getMessage());
		}
		
		// jti
		stmt.setClaim("jti", "be0Chi8U");
		
		stmt.validateRequiredClaimsPresence();
		
		// policy_language_crit
		List<String> policyCrit = Collections.singletonList("regexp");
		stmt.setCriticalPolicyExtensions(policyCrit);
		assertEquals(policyCrit, stmt.getCriticalPolicyExtensions());
		
		// output
		JWTClaimsSet jwtClaimsSet = stmt.toJWTClaimsSet();
		
		assertEquals(iss.getValue(), jwtClaimsSet.getIssuer());
		assertEquals(sub.getValue(), jwtClaimsSet.getSubject());
		assertEquals(iat, jwtClaimsSet.getIssueTime());
		assertEquals(exp, jwtClaimsSet.getExpirationTime());
		assertEquals(JWK_SET.toJSONObject(), jwtClaimsSet.getJSONObjectClaim("jwks"));
		assertEquals(audList.get(0).getValue(), jwtClaimsSet.getAudience().get(0));
		assertEquals(authorityHints.get(0).getValue(), jwtClaimsSet.getStringListClaim("authority_hints").get(0));
		
		Map<String,Object> metadata = jwtClaimsSet.getJSONObjectClaim("metadata");
		OIDCClientMetadata parsedRPMetadata = OIDCClientMetadata.parse(new JSONObject(com.nimbusds.jose.util.JSONObjectUtils.getJSONObject(metadata, "openid_relying_party")));
		assertEquals(rpMetadata.toJSONObject(), parsedRPMetadata.toJSONObject());
		assertEquals(1, metadata.size());
		
		assertEquals(metadataPolicy, jwtClaimsSet.getJSONObjectClaim("metadata_policy"));
		assertEquals(constraints, TrustChainConstraints.parse(new JSONObject(jwtClaimsSet.getJSONObjectClaim("constraints"))));
		assertEquals(crit, jwtClaimsSet.getStringListClaim("crit"));
		assertEquals("be0Chi8U", jwtClaimsSet.getJWTID());
		assertEquals(policyCrit, jwtClaimsSet.getStringListClaim("policy_language_crit"));
		
		// parse
		EntityStatementClaimsSet parsed = new EntityStatementClaimsSet(jwtClaimsSet);
		
		assertEquals(stmt.getIssuer(), parsed.getIssuer());
		assertEquals(stmt.getSubject(), parsed.getSubject());
		assertEquals(stmt.getIssueTime(), parsed.getIssueTime());
		assertEquals(stmt.getExpirationTime(), parsed.getExpirationTime());
		assertEquals(stmt.getJWKSet().toJSONObject(), parsed.getJWKSet().toJSONObject());
		assertEquals(stmt.getAudience(), parsed.getAudience());
		assertEquals(stmt.getAuthorityHints(), parsed.getAuthorityHints());
		assertEquals(stmt.getRPMetadata().toJSONObject(), parsed.getRPMetadata().toJSONObject());
		assertEquals(stmt.getMetadataPolicyJSONObject(), parsed.getMetadataPolicyJSONObject());
		assertEquals(stmt.getConstraints(), parsed.getConstraints());
		assertEquals(stmt.getCriticalExtensionClaims(), parsed.getCriticalExtensionClaims());
		assertEquals(stmt.getStringClaim("jti"), parsed.getStringClaim("jti"));
		assertEquals(stmt.getCriticalPolicyExtensions(), parsed.getCriticalPolicyExtensions());
	}
	
	
	// Includes trust_anchor_id
	public void testWithRPMetadata_OPStated()
		throws Exception {
		
		Issuer iss = new Issuer("https://op.c2id.com");
		Subject sub = new Subject("https://rp.c2id.com");
		
		Date iat = DateUtils.fromSecondsSinceEpoch(1000);
		Date exp = DateUtils.fromSecondsSinceEpoch(2000);
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			iss,
			sub,
			iat,
			exp,
			JWK_SET);
		
		stmt.validateRequiredClaimsPresence();
		
		assertFalse(stmt.isSelfStatement());
		assertFalse(stmt.hasMetadata());
		
		// aud
		List<Audience> audList = new Audience("123").toSingleAudienceList();
		stmt.setAudience(audList);
		assertEquals(audList, stmt.getAudience());
		
		// authority_hints
		List<EntityID> authorityHints = Collections.singletonList(new EntityID("https://federation.example.com"));
		stmt.setAuthorityHints(authorityHints);
		assertEquals(authorityHints, stmt.getAuthorityHints());
		
		// metadata -> openid_relying_party
		OIDCClientMetadata rpMetadata = createRPMetadata();
		stmt.setRPMetadata(rpMetadata);
		assertEquals(rpMetadata.toJSONObject(), stmt.getRPMetadata().toJSONObject());
		
		// passes now
		assertTrue(stmt.hasMetadata());
		stmt.validateRequiredClaimsPresence();
		
		// metadata_policy
		JSONObject metadataPolicy = createMetadataPolicy();
		stmt.setMetadataPolicyJSONObject(metadataPolicy);
		assertEquals(metadataPolicy, stmt.getMetadataPolicyJSONObject());
		
		EntityID trustAnchorID = new EntityID("https://federation.example.com");
		stmt.setTrustAnchorID(trustAnchorID);
		assertEquals(trustAnchorID, stmt.getTrustAnchorID());
		
		// constraints
		TrustChainConstraints constraints = new TrustChainConstraints(10, null, null, null);
		stmt.setConstraints(constraints);
		assertEquals(constraints, stmt.getConstraints());
		
		// crit
		List<String> crit = Collections.singletonList("jti");
		stmt.setCriticalExtensionClaims(crit);
		assertEquals(crit, stmt.getCriticalExtensionClaims());
		
		try {
			stmt.validateRequiredClaimsPresence();
			fail();
		} catch (ParseException e) {
			assertEquals("Missing critical jti claim", e.getMessage());
		}
		
		// jti
		stmt.setClaim("jti", "be0Chi8U");
		
		stmt.validateRequiredClaimsPresence();
		
		// policy_language_crit
		List<String> policyCrit = Collections.singletonList("regexp");
		stmt.setCriticalPolicyExtensions(policyCrit);
		assertEquals(policyCrit, stmt.getCriticalPolicyExtensions());
		
		// output
		JWTClaimsSet jwtClaimsSet = stmt.toJWTClaimsSet();
		
		assertEquals(iss.getValue(), jwtClaimsSet.getIssuer());
		assertEquals(sub.getValue(), jwtClaimsSet.getSubject());
		assertEquals(iat, jwtClaimsSet.getIssueTime());
		assertEquals(exp, jwtClaimsSet.getExpirationTime());
		assertEquals(JWK_SET.toJSONObject(), jwtClaimsSet.getJSONObjectClaim("jwks"));
		assertEquals(audList.get(0).getValue(), jwtClaimsSet.getAudience().get(0));
		assertEquals(authorityHints.get(0).getValue(), jwtClaimsSet.getStringListClaim("authority_hints").get(0));
		
		Map<String, Object> metadata = jwtClaimsSet.getJSONObjectClaim("metadata");
		OIDCClientMetadata parsedRPMetadata = OIDCClientMetadata.parse(new JSONObject(com.nimbusds.jose.util.JSONObjectUtils.getJSONObject(metadata, "openid_relying_party")));
		assertEquals(rpMetadata.toJSONObject(), parsedRPMetadata.toJSONObject());
		assertEquals(1, metadata.size());
		
		assertEquals(trustAnchorID.getValue(), jwtClaimsSet.getStringClaim("trust_anchor_id"));
		
		assertEquals(metadataPolicy, jwtClaimsSet.getJSONObjectClaim("metadata_policy"));
		assertEquals(constraints, TrustChainConstraints.parse(new JSONObject(jwtClaimsSet.getJSONObjectClaim("constraints"))));
		assertEquals(crit, jwtClaimsSet.getStringListClaim("crit"));
		assertEquals("be0Chi8U", jwtClaimsSet.getJWTID());
		assertEquals(policyCrit, jwtClaimsSet.getStringListClaim("policy_language_crit"));
		
		// parse
		EntityStatementClaimsSet parsed = new EntityStatementClaimsSet(jwtClaimsSet);
		
		assertEquals(stmt.getIssuer(), parsed.getIssuer());
		assertEquals(stmt.getSubject(), parsed.getSubject());
		assertEquals(stmt.getIssueTime(), parsed.getIssueTime());
		assertEquals(stmt.getExpirationTime(), parsed.getExpirationTime());
		assertEquals(stmt.getJWKSet().toJSONObject(), parsed.getJWKSet().toJSONObject());
		assertEquals(stmt.getAudience(), parsed.getAudience());
		assertEquals(stmt.getAuthorityHints(), parsed.getAuthorityHints());
		assertEquals(stmt.getRPMetadata().toJSONObject(), parsed.getRPMetadata().toJSONObject());
		assertEquals(stmt.getMetadataPolicyJSONObject(), parsed.getMetadataPolicyJSONObject());
		assertEquals(stmt.getTrustAnchorID(), parsed.getTrustAnchorID());
		assertEquals(stmt.getConstraints(), parsed.getConstraints());
		assertEquals(stmt.getCriticalExtensionClaims(), parsed.getCriticalExtensionClaims());
		assertEquals(stmt.getStringClaim("jti"), parsed.getStringClaim("jti"));
		assertEquals(stmt.getCriticalPolicyExtensions(), parsed.getCriticalPolicyExtensions());
	}
	
	
	public void testWithOPMetadata_selfStated()
		throws Exception {
		
		Issuer iss = new Issuer("https://rp.c2id.com");
		Subject sub = new Subject("https://rp.c2id.com");
		
		Date iat = DateUtils.fromSecondsSinceEpoch(1000);
		Date exp = DateUtils.fromSecondsSinceEpoch(2000);
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			iss,
			sub,
			iat,
			exp,
			JWK_SET);
		
		OIDCProviderMetadata opMetadata = createOPMetadata();
		
		stmt.setOPMetadata(opMetadata);
		assertEquals(opMetadata.toJSONObject(), stmt.getOPMetadata().toJSONObject());
		
		JWTClaimsSet jwtClaimsSet = stmt.toJWTClaimsSet();
		Map<String, Object> metadata = jwtClaimsSet.getJSONObjectClaim("metadata");
		assertEquals(opMetadata.toJSONObject(), new JSONObject(com.nimbusds.jose.util.JSONObjectUtils.getJSONObject(metadata, "openid_provider")));
		
		stmt = new EntityStatementClaimsSet(jwtClaimsSet);
		assertEquals(opMetadata.toJSONObject(), stmt.getOPMetadata().toJSONObject());
		
		stmt.validateRequiredClaimsPresence();
		
		stmt.setOPMetadata(null);
		assertNull(stmt.getOPMetadata());
	}
	
	
	public void testWithASMetadata_selfStated()
		throws Exception {
		
		Issuer iss = new Issuer("https://rp.c2id.com");
		Subject sub = new Subject("https://rp.c2id.com");
		
		Date iat = DateUtils.fromSecondsSinceEpoch(1000);
		Date exp = DateUtils.fromSecondsSinceEpoch(2000);
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			iss,
			sub,
			iat,
			exp,
			JWK_SET);
		
		AuthorizationServerMetadata asMetadata = createASMetadata();
		
		stmt.setASMetadata(asMetadata);
		assertEquals(asMetadata.toJSONObject(), stmt.getASMetadata().toJSONObject());
		
		JWTClaimsSet jwtClaimsSet = stmt.toJWTClaimsSet();
		Map<String,Object> metadata = jwtClaimsSet.getJSONObjectClaim("metadata");
		assertEquals(asMetadata.toJSONObject(), new JSONObject(com.nimbusds.jose.util.JSONObjectUtils.getJSONObject(metadata, "oauth_authorization_server")));
		
		stmt = new EntityStatementClaimsSet(jwtClaimsSet);
		assertEquals(asMetadata.toJSONObject(), stmt.getASMetadata().toJSONObject());
		
		stmt.validateRequiredClaimsPresence();
		
		stmt.setASMetadata(null);
		assertNull(stmt.getASMetadata());
	}
	
	
	public void testWithOAuthClientMetadata_selfStated()
		throws Exception {
		
		Issuer iss = new Issuer("https://rp.c2id.com");
		Subject sub = new Subject("https://rp.c2id.com");
		
		Date iat = DateUtils.fromSecondsSinceEpoch(1000);
		Date exp = DateUtils.fromSecondsSinceEpoch(2000);
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			iss,
			sub,
			iat,
			exp,
			JWK_SET);
		
		ClientMetadata clientMetadata = createOAuthClientMetadata();
		
		stmt.setOAuthClientMetadata(clientMetadata);
		assertEquals(clientMetadata.toJSONObject(), stmt.getOAuthClientMetadata().toJSONObject());
		
		JWTClaimsSet jwtClaimsSet = stmt.toJWTClaimsSet();
		Map<String, Object> metadata = jwtClaimsSet.getJSONObjectClaim("metadata");
		assertEquals(clientMetadata.toJSONObject(), com.nimbusds.jose.util.JSONObjectUtils.getJSONObject(metadata, "oauth_client"));
		
		stmt = new EntityStatementClaimsSet(jwtClaimsSet);
		assertEquals(clientMetadata.toJSONObject(), stmt.getOAuthClientMetadata().toJSONObject());
		
		stmt.validateRequiredClaimsPresence();
		
		stmt.setOAuthClientMetadata(null);
		assertNull(stmt.getOAuthClientMetadata());
	}
	
	
	public void testWithFederationEntityMetadata_selfStated()
		throws Exception {
		
		Issuer iss = new Issuer("https://fed.c2id.com");
		Subject sub = new Subject("https://fed.c2id.com");
		
		Date iat = DateUtils.fromSecondsSinceEpoch(1000);
		Date exp = DateUtils.fromSecondsSinceEpoch(2000);
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			iss,
			sub,
			iat,
			exp,
			JWK_SET);
		
		FederationEntityMetadata fedMetadata = createFederationEntityMetadata();
		
		stmt.setFederationEntityMetadata(fedMetadata);
		assertEquals(fedMetadata.toJSONObject(), stmt.getFederationEntityMetadata().toJSONObject());
		
		JWTClaimsSet jwtClaimsSet = stmt.toJWTClaimsSet();
		Map<String, Object> metadata = jwtClaimsSet.getJSONObjectClaim("metadata");
		assertEquals(fedMetadata.toJSONObject(), com.nimbusds.jose.util.JSONObjectUtils.getJSONObject(metadata, "federation_entity"));
		
		stmt = new EntityStatementClaimsSet(jwtClaimsSet);
		assertEquals(fedMetadata.toJSONObject(), stmt.getFederationEntityMetadata().toJSONObject());
		
		stmt.validateRequiredClaimsPresence();
		
		stmt.setFederationEntityMetadata(null);
		assertNull(stmt.getFederationEntityMetadata());
	}
	
	
	public void testTypedMetadataPolicyGetterAndSetter()
		throws PolicyViolationException, ParseException {
		
		Issuer iss = new Issuer("https://fed.c2id.com");
		Subject sub = new Subject("https://fed.c2id.com");
		
		Date iat = DateUtils.fromSecondsSinceEpoch(1000);
		Date exp = DateUtils.fromSecondsSinceEpoch(2000);
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			iss,
			sub,
			iat,
			exp,
			JWK_SET);
		
		// get null
		assertNull(stmt.getMetadataPolicy(EntityType.OPENID_PROVIDER));
		assertNull(stmt.getMetadataPolicy(EntityType.OPENID_RELYING_PARTY));
		
		String opPolicyJSON = "{" +
			"    \"contacts\": {" +
			"      \"add\": \"ops@edugain.geant.org\"" +
			"    }" +
			"}";
		JSONObject opJSONObject = JSONObjectUtils.parse(opPolicyJSON);
		
		String rpPolicyJSON = "{" +
			"    \"contacts\": {" +
			"      \"add\": \"ops@edugain.geant.org\"" +
			"   }" +
			"}";
		JSONObject rpJSONObject = JSONObjectUtils.parse(rpPolicyJSON);
		
		MetadataPolicy opPolicy = MetadataPolicy.parse(rpJSONObject);
		MetadataPolicy rpPolicy = MetadataPolicy.parse(rpJSONObject);
		
		// set
		stmt.setMetadataPolicy(EntityType.OPENID_PROVIDER, opPolicy);
		stmt.setMetadataPolicy(EntityType.OPENID_RELYING_PARTY, rpPolicy);
		
		JSONObject policyJSONObject = stmt.getMetadataPolicyJSONObject();
		
		JSONObject expectedPolicyJSONObject = new JSONObject();
		expectedPolicyJSONObject.put(EntityType.OPENID_PROVIDER.getValue(), opJSONObject);
		expectedPolicyJSONObject.put(EntityType.OPENID_RELYING_PARTY.getValue(), rpJSONObject);
		assertEquals(expectedPolicyJSONObject, policyJSONObject);
		
		// get
		assertEquals(opJSONObject, stmt.getMetadataPolicy(EntityType.OPENID_PROVIDER).toJSONObject());
		assertEquals(rpJSONObject, stmt.getMetadataPolicy(EntityType.OPENID_RELYING_PARTY).toJSONObject());
		
		// delete
		stmt.setMetadataPolicy(EntityType.OPENID_PROVIDER, null);
		stmt.setMetadataPolicy(EntityType.OPENID_RELYING_PARTY, null);
		
		// get null
		assertNull(stmt.getMetadataPolicy(EntityType.OPENID_PROVIDER));
		assertNull(stmt.getMetadataPolicy(EntityType.OPENID_RELYING_PARTY));
		
		assertNull(stmt.getMetadataPolicyJSONObject());
	}
	
	
	public void testWithTrustMarks()
		throws Exception {
		
		Issuer iss = new Issuer("https://abc-federation.c2id.com");
		Subject sub = new Subject("https://op.c2id.com");
		
		Date iat = DateUtils.fromSecondsSinceEpoch(1000);
		Date exp = DateUtils.fromSecondsSinceEpoch(2000);
		
		TrustMarkClaimsSet trustMarkClaimsSet_1 = new TrustMarkClaimsSet(
			new Issuer("https://tm1.example.com"),
			sub,
			new Identifier("tm-1"),
			iat);
		TrustMarkClaimsSet trustMarkClaimsSet_2 = new TrustMarkClaimsSet(
			new Issuer("https://tm2.example.com"),
			sub,
			new Identifier("tm-2"),
			iat);
		
		SignedJWT tm_1 = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), trustMarkClaimsSet_1.toJWTClaimsSet());
		tm_1.sign(new RSASSASigner(new RSAKeyGenerator(2048).generate()));
		
		SignedJWT tm_2 = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), trustMarkClaimsSet_2.toJWTClaimsSet());
		tm_2.sign(new RSASSASigner(new RSAKeyGenerator(2048).generate()));
		
		List<TrustMarkEntry> marks = new LinkedList<>();
		marks.add(new TrustMarkEntry(trustMarkClaimsSet_1.getID(), tm_1));
		marks.add(new TrustMarkEntry(trustMarkClaimsSet_2.getID(), tm_2));
		
		Map<Identifier, List<Issuer>> issuers = new HashMap<>();
		issuers.put(trustMarkClaimsSet_1.getID(), Collections.singletonList(trustMarkClaimsSet_1.getIssuer()));
		issuers.put(trustMarkClaimsSet_2.getID(), Collections.singletonList(trustMarkClaimsSet_2.getIssuer()));
		
		// Test ID and EntityID constructors
		for (EntityStatementClaimsSet stmt: Arrays.asList(
			new EntityStatementClaimsSet(
				iss,
				sub,
				iat,
				exp,
				JWK_SET),
			new EntityStatementClaimsSet(
				new EntityID(iss.getValue()),
				new EntityID(sub.getValue()),
				iat,
				exp,
				JWK_SET))) {
			
			stmt.setTrustMarks(marks);
			
			assertEquals(marks.get(0).getID(), stmt.getTrustMarks().get(0).getID());
			assertEquals(marks.get(0).getTrustMark().serialize(), stmt.getTrustMarks().get(0).getTrustMark().serialize());
			assertEquals(marks.get(1).getID(), stmt.getTrustMarks().get(1).getID());
			assertEquals(marks.get(1).getTrustMark().serialize(), stmt.getTrustMarks().get(1).getTrustMark().serialize());
			assertEquals(2, stmt.getTrustMarks().size());
			
			stmt.setTrustMarksIssuers(issuers);
			
			assertEquals(issuers, stmt.getTrustMarksIssuers());
			
			JWTClaimsSet jwtClaimsSet = stmt.toJWTClaimsSet();
			
			List<?> jsonArray = (List<?>)jwtClaimsSet.getClaim(EntityStatementClaimsSet.TRUST_MARKS_CLAIM_NAME);
			assertEquals(marks.get(0).getID(), TrustMarkEntry.parse(new JSONObject((Map<String, Object>) jsonArray.get(0))).getID());
			assertEquals(marks.get(0).getTrustMark().serialize(), TrustMarkEntry.parse(new JSONObject((Map<String, Object>) jsonArray.get(0))).getTrustMark().serialize());
			assertEquals(marks.get(1).getID(), TrustMarkEntry.parse(new JSONObject((Map<String, Object>) jsonArray.get(1))).getID());
			assertEquals(marks.get(1).getTrustMark().serialize(), TrustMarkEntry.parse(new JSONObject((Map<String, Object>) jsonArray.get(1))).getTrustMark().serialize());
			assertEquals(2, jsonArray.size());
			
			assertEquals(issuers.toString(), jwtClaimsSet.getJSONObjectClaim(EntityStatementClaimsSet.TRUST_MARKS_ISSUERS_CLAIM_NAME).toString());
			assertEquals(2, jwtClaimsSet.getJSONObjectClaim(EntityStatementClaimsSet.TRUST_MARKS_ISSUERS_CLAIM_NAME).size());
			
			stmt = new EntityStatementClaimsSet(jwtClaimsSet);
			
			assertEquals(marks.get(0).getID(), stmt.getTrustMarks().get(0).getID());
			assertEquals(marks.get(0).getTrustMark().serialize(), stmt.getTrustMarks().get(0).getTrustMark().serialize());
			assertEquals(marks.get(1).getID(), stmt.getTrustMarks().get(1).getID());
			assertEquals(marks.get(1).getTrustMark().serialize(), stmt.getTrustMarks().get(1).getTrustMark().serialize());
			assertEquals(2, stmt.getTrustMarks().size());
			
			assertEquals(issuers, stmt.getTrustMarksIssuers());
			
			// Test set null
			stmt.setTrustMarks(null);
			assertNull(stmt.getTrustMarks());
			
			stmt.setTrustMarksIssuers(null);
			assertNull(stmt.getTrustMarksIssuers());
		}
	}
	
	
	public void testParseInteropExample() throws java.text.ParseException, ParseException, PolicyViolationException {
		
		String json = "{" +
			"  \"sub\": \"https://federation.catalogix.se:4002/eid/lu.se\"," +
			"  \"jwks\": {" +
			"    \"keys\": [" +
			"      {" +
			"        \"kty\": \"RSA\"," +
			"        \"e\": \"AQAB\"," +
			"        \"use\": \"sig\"," +
			"        \"kid\": \"SzhWamJCUnJtQy16THpuT0pOYlc1bGlid0FyTlR0RXJIb3pYTUUxVGp1Zw\"," +
			"        \"n\": \"tgUdKJM7Ddi0cfyH0eVI94r-UMfXX4NLm_FblI2hScYomlp6RdcPeja5GZADUldLTz2x2fuhviqt5oL5uN26d7DV-MBel4wMpN0SuIcLhSvJM0gs3lQhy74uMOgKzgRhpOoAmybnlPQccUzmRnTyJFBG9E6Xr4pF-RH60G7zfJLXPUN71K21twfc2urbfqj9kr3jjFt_bo4g4NIb8N3QSSaF3fpFRRlI1MQyiim3KCPlL2lgI1UEzfGWrA4CnEDeYFg-pDBjKlnEeud7IiO3VEk26mP9IdSHeFDNs9oimfKjDE7R5Yokhls1GvX7Oz0zmEuVCpsA4aBuDbWdkqNdCw\"" +
			"      }," +
			"      {" +
			"        \"kty\": \"EC\"," +
			"        \"use\": \"sig\"," +
			"        \"crv\": \"P-256\"," +
			"        \"kid\": \"bE5rd2VkcnJXc2hKX3lBaEU4VGQ3M0tuZVZob252c3hnSW1KTmJ1RmFBbw\"," +
			"        \"x\": \"YCdN_RkzgzdXf9jKb5DMOqm8Sw96pCwNYXekMjrrE0Y\"," +
			"        \"y\": \"gZQvZl8i71CL5HN8YY_Jakcj7Czx-yM_hIPanjuF6SQ\"" +
			"      }" +
			"    ]" +
			"  }," +
			"  \"metadata_policy\": {" +
			"    \"openid_provider\": {" +
			"      \"token_endpoint_auth_signing_alg_values_supported\": {" +
			"        \"default\": [" +
			"          \"ES256\"" +
			"        ]," +
			"        \"subset_of\": [" +
			"          \"ES256\"," +
			"          \"ES384\"," +
			"          \"ES512\"" +
			"        ]" +
			"      }," +
			"      \"userinfo_signing_alg_values_supported\": {" +
			"        \"default\": [" +
			"          \"ES256\"" +
			"        ]," +
			"        \"subset_of\": [" +
			"          \"ES256\"," +
			"          \"ES384\"," +
			"          \"ES512\"" +
			"        ]" +
			"      }," +
			"      \"id_token_signing_alg_values_supported\": {" +
			"        \"default\": [" +
			"          \"ES256\"" +
			"        ]," +
			"        \"subset_of\": [" +
			"          \"ES256\"," +
			"          \"ES384\"," +
			"          \"ES512\"" +
			"        ]" +
			"      }," +
			"      \"token_endpoint_auth_methods_supported\": {" +
			"        \"default\": [" +
			"          \"ES256\"" +
			"        ]," +
			"        \"subset_of\": [" +
			"          \"client_secret_jwt\"," +
			"          \"private_key_jwt\"" +
			"        ]" +
			"      }," +
			"      \"contacts\": {" +
			"        \"add\": \"operations@feide.no\"" +
			"      }" +
			"    }," +
			"    \"openid_relying_party\": {" +
			"      \"token_endpoint_auth_signing_alg\": {" +
			"        \"default\": \"ES256\"," +
			"        \"one_of\": [" +
			"          \"ES256\"," +
			"          \"ES384\"," +
			"          \"ES512\"" +
			"        ]" +
			"      }," +
			"      \"request_object_signing_alg\": {" +
			"        \"default\": \"ES256\"," +
			"        \"one_of\": [" +
			"          \"ES256\"," +
			"          \"ES384\"," +
			"          \"ES512\"" +
			"        ]" +
			"      }," +
			"      \"userinfo_signed_response_alg\": {" +
			"        \"default\": \"ES256\"," +
			"        \"one_of\": [" +
			"          \"ES256\"," +
			"          \"ES384\"," +
			"          \"ES512\"" +
			"        ]" +
			"      }," +
			"      \"id_token_signed_response_alg\": {" +
			"        \"default\": \"ES256\"," +
			"        \"one_of\": [" +
			"          \"ES256\"," +
			"          \"ES384\"," +
			"          \"ES512\"" +
			"        ]" +
			"      }" +
			"    }" +
			"  }," +
			"  \"iss\": \"https://federation.catalogix.se:4002/eid/feide.no\"," +
			"  \"authority_hints\": [" +
			"    \"https://federation.catalogix.se:4002/eid/feide.no\"" +
			"  ]," +
			"  \"exp\": 1607715732," +
			"  \"constraints\": {" +
			"    \"max_path_length\": 1" +
			"  }," +
			"  \"iat\": 1607629332" +
			"}";
		
		JSONObject jsonObject = JSONObjectUtils.parse(json);
		
		EntityStatementClaimsSet claimsSet = new EntityStatementClaimsSet(JWTClaimsSet.parse(jsonObject));
		
		assertEquals(jsonObject, claimsSet.toJSONObject());
		
		MetadataPolicy metadataRPPolicy = claimsSet.getMetadataPolicy(EntityType.OPENID_RELYING_PARTY);
		
		JSONObject expectedMetadataRPPolicyJSONObject = JSONObjectUtils.parse(
			"{" +
			"  \"token_endpoint_auth_signing_alg\": {" +
			"    \"default\": \"ES256\"," +
			"    \"one_of\": [" +
			"      \"ES256\"," +
			"      \"ES384\"," +
			"      \"ES512\"" +
			"    ]" +
			"  }," +
			"  \"request_object_signing_alg\": {" +
			"    \"default\": \"ES256\"," +
			"    \"one_of\": [" +
			"      \"ES256\"," +
			"      \"ES384\"," +
			"      \"ES512\"" +
			"    ]" +
			"  }," +
			"  \"userinfo_signed_response_alg\": {" +
			"    \"default\": \"ES256\"," +
			"    \"one_of\": [" +
			"      \"ES256\"," +
			"      \"ES384\"," +
			"      \"ES512\"" +
			"    ]" +
			"  }," +
			"  \"id_token_signed_response_alg\": {" +
			"    \"default\": \"ES256\"," +
			"    \"one_of\": [" +
			"      \"ES256\"," +
			"      \"ES384\"," +
			"      \"ES512\"" +
			"    ]" +
			"  }" +
			"}");
		
		assertEquals(expectedMetadataRPPolicyJSONObject, metadataRPPolicy.toJSONObject());
	}
}
