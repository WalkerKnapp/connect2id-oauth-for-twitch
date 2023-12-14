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


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import junit.framework.TestCase;

import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.List;


public class EntityStatementTest extends TestCase {
	
	
	public static final RSAKey RSA_JWK;
	
	
	public static final Base64URL RSA_JWK_THUMBPRINT;
	
	
	public static final JWKSet SIMPLE_JWK_SET;
	
	
	public static final OIDCProviderMetadata OP_METADATA;
	
	
	static {
		try {
			RSA_JWK = new RSAKeyGenerator(2048)
				.keyIDFromThumbprint(true)
				.keyUse(KeyUse.SIGNATURE)
				.generate();
			RSA_JWK_THUMBPRINT = RSA_JWK.computeThumbprint();
			SIMPLE_JWK_SET = new JWKSet(RSA_JWK.toPublicJWK());
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
	}
	
	
	public static EntityStatementClaimsSet createSelfIssuedEntityStatementClaimsSet() {
		
		Date now = new Date();
		long nowTS = DateUtils.toSecondsSinceEpoch(now);
		Date iat = DateUtils.fromSecondsSinceEpoch(nowTS);
		Date exp = DateUtils.fromSecondsSinceEpoch(nowTS + 60);
		
		Issuer iss = OP_METADATA.getIssuer();
		Subject sub = new Subject(OP_METADATA.getIssuer().getValue());
		List<EntityID> authorityHints = Collections.singletonList(new EntityID("https://federation.example.com"));
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			iss,
			sub,
			iat,
			exp,
			SIMPLE_JWK_SET);
		stmt.setOPMetadata(OP_METADATA);
		stmt.setAuthorityHints(authorityHints);
		return stmt;
	}
	
	
	public static EntityStatementClaimsSet createOPAboutRPEntityStatementClaimsSet() {
		
		Date now = new Date();
		long nowTS = DateUtils.toSecondsSinceEpoch(now);
		Date iat = DateUtils.fromSecondsSinceEpoch(nowTS);
		Date exp = DateUtils.fromSecondsSinceEpoch(nowTS + 60);
		
		Issuer iss = OP_METADATA.getIssuer();
		Subject sub = new Subject("https://rp.example.com");
		List<EntityID> authorityHints = Collections.singletonList(new EntityID("https://federation.example.com"));
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			iss,
			sub,
			iat,
			exp,
			null);
		stmt.setAuthorityHints(authorityHints);
		return stmt;
	}
	
	
	public void testTypeConstant() {
		
		assertEquals(new JOSEObjectType("entity-statement+jwt"), EntityStatement.JOSE_OBJECT_TYPE);
		assertEquals(new ContentType("application", "entity-statement+jwt"), EntityStatement.CONTENT_TYPE);
	}
	

	public void testLifeCycle_defaultJWSAlg() throws Exception {
		
		EntityStatementClaimsSet claimsSet = createSelfIssuedEntityStatementClaimsSet();
		
		EntityStatement entityStatement = EntityStatement.sign(claimsSet, RSA_JWK);
		
		assertEquals(OP_METADATA.getIssuer().getValue(), entityStatement.getEntityID().getValue());
		assertEquals(claimsSet.toJWTClaimsSet().getClaims(), entityStatement.getClaimsSet().toJWTClaimsSet().getClaims());
		
		JWSHeader jwsHeader = entityStatement.getSignedStatement().getHeader();
		assertEquals(JWSAlgorithm.RS256, jwsHeader.getAlgorithm());
		assertEquals(EntityStatement.JOSE_OBJECT_TYPE, jwsHeader.getType());
		assertEquals(RSA_JWK.getKeyID(), jwsHeader.getKeyID());
		assertEquals(3,  jwsHeader.toJSONObject().size());
		
		SignedJWT signedJWT = entityStatement.getSignedStatement();
		assertEquals(claimsSet.toJWTClaimsSet().getClaims(), signedJWT.getJWTClaimsSet().getClaims());
		assertTrue(signedJWT.verify(new RSASSAVerifier(RSA_JWK.toRSAPublicKey())));
		
		entityStatement = EntityStatement.parse(signedJWT.serialize());
		
		assertEquals(OP_METADATA.getIssuer().getValue(), entityStatement.getEntityID().getValue());
		assertEquals(claimsSet.toJWTClaimsSet().getClaims(), entityStatement.getClaimsSet().toJWTClaimsSet().getClaims());
		
		assertEquals(RSA_JWK_THUMBPRINT, entityStatement.verifySignatureOfSelfStatement());
		assertEquals(RSA_JWK_THUMBPRINT, entityStatement.verifySignature(SIMPLE_JWK_SET));
	}
	

	public void testLifeCycle_explicitJWSAlg() throws Exception {
		
		EntityStatementClaimsSet claimsSet = createSelfIssuedEntityStatementClaimsSet();
		
		EntityStatement entityStatement = EntityStatement.sign(claimsSet, RSA_JWK, JWSAlgorithm.RS512);
		
		assertEquals(OP_METADATA.getIssuer().getValue(), entityStatement.getEntityID().getValue());
		assertEquals(claimsSet.toJWTClaimsSet().getClaims(), entityStatement.getClaimsSet().toJWTClaimsSet().getClaims());
		
		JWSHeader jwsHeader = entityStatement.getSignedStatement().getHeader();
		assertEquals(JWSAlgorithm.RS512, jwsHeader.getAlgorithm());
		assertEquals(EntityStatement.JOSE_OBJECT_TYPE, jwsHeader.getType());
		assertEquals(RSA_JWK.getKeyID(), jwsHeader.getKeyID());
		assertEquals(3,  jwsHeader.toJSONObject().size());
		
		SignedJWT signedJWT = entityStatement.getSignedStatement();
		assertEquals(claimsSet.toJWTClaimsSet().getClaims(), signedJWT.getJWTClaimsSet().getClaims());
		assertTrue(signedJWT.verify(new RSASSAVerifier(RSA_JWK.toRSAPublicKey())));
		
		entityStatement = EntityStatement.parse(signedJWT.serialize());
		
		assertEquals(OP_METADATA.getIssuer().getValue(), entityStatement.getEntityID().getValue());
		assertEquals(claimsSet.toJWTClaimsSet().getClaims(), entityStatement.getClaimsSet().toJWTClaimsSet().getClaims());
		
		assertEquals(RSA_JWK_THUMBPRINT, entityStatement.verifySignatureOfSelfStatement());
		assertEquals(RSA_JWK_THUMBPRINT, entityStatement.verifySignature(SIMPLE_JWK_SET));
	}
	
	
	public void testLifeCycle_OPAboutRP() throws Exception {
		
		EntityStatementClaimsSet claimsSet = createOPAboutRPEntityStatementClaimsSet();
		
		OIDCClientMetadata origMetadata = new OIDCClientMetadata();
		origMetadata.setRedirectionURI(URI.create("https://rp.example.com/cb"));
		
		claimsSet.setRPMetadata(origMetadata);
		
		OIDCClientMetadata registeredMetadata = new OIDCClientMetadata(origMetadata);
		registeredMetadata.applyDefaults();
		OIDCClientInformation clientInfo = new OIDCClientInformation(
			new ClientID("123"),
			claimsSet.getIssueTime(),
			registeredMetadata,
			null);

		claimsSet.setRPMetadata(clientInfo.getOIDCMetadata()); // TODO
		
		EntityStatement registrationStatement = EntityStatement.sign(claimsSet, RSA_JWK);
		assertEquals(RSA_JWK_THUMBPRINT, registrationStatement.verifySignature(SIMPLE_JWK_SET));
	}
	
	
	public void testExpired() throws Exception {
		
		EntityStatementClaimsSet claimsSet = createSelfIssuedEntityStatementClaimsSet();
		
		// Put exp in past
		long now = DateUtils.toSecondsSinceEpoch(new Date());
		long iat = now - 3600;
		long exp = now - 1800;
		JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder(claimsSet.toJWTClaimsSet())
			.issueTime(DateUtils.fromSecondsSinceEpoch(iat))
			.expirationTime(DateUtils.fromSecondsSinceEpoch(exp))
			.build();
		
		claimsSet = new EntityStatementClaimsSet(jwtClaimsSet);
		
		EntityStatement entityStatement = EntityStatement.sign(claimsSet, RSA_JWK);
		
		try {
			EntityStatement.parse(entityStatement.getSignedStatement()).verifySignatureOfSelfStatement();
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Expired JWT", e.getMessage());
		}
	}
	
	
	public void testInvalidSignature_missingTypeHeader() throws Exception {
		
		EntityStatementClaimsSet claimsSet = createSelfIssuedEntityStatementClaimsSet();
		
		SignedJWT signedJWT = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(RSA_JWK.getKeyID()).build(),
			claimsSet.toJWTClaimsSet()
		);
		signedJWT.sign(new RSASSASigner(RSA_JWK));
		
		try {
			EntityStatement.parse(signedJWT.serialize()).verifySignatureOfSelfStatement();
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JWT rejected: Invalid or missing JWT typ (type) header", e.getMessage());
		}
	}
	
	
	public void testInvalidSignature_invalidTypeHeader() throws Exception {
		
		EntityStatementClaimsSet claimsSet = createSelfIssuedEntityStatementClaimsSet();
		
		SignedJWT signedJWT = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).keyID(RSA_JWK.getKeyID()).build(),
			claimsSet.toJWTClaimsSet()
		);
		signedJWT.sign(new RSASSASigner(RSA_JWK));
		
		try {
			EntityStatement.parse(signedJWT.serialize()).verifySignatureOfSelfStatement();
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JWT rejected: Invalid or missing JWT typ (type) header", e.getMessage());
		}
	}
	
	
	public void testInvalidSignature_noMatchingKey() throws Exception {
		
		EntityStatementClaimsSet claimsSet = createSelfIssuedEntityStatementClaimsSet();
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.keyIDFromThumbprint(true)
			.generate();
		
		SignedJWT signedJWT = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).type(EntityStatement.JOSE_OBJECT_TYPE).keyID(rsaJWK.getKeyID()).build(),
			claimsSet.toJWTClaimsSet()
		);
		signedJWT.sign(new RSASSASigner(rsaJWK));
		
		try {
			EntityStatement.parse(signedJWT.serialize()).verifySignatureOfSelfStatement();
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JWT rejected: Another JOSE algorithm expected, or no matching key(s) found", e.getMessage());
		}
	}
	
	
	public void testInvalidSignature_signature() throws Exception {
		
		EntityStatementClaimsSet claimsSet = createSelfIssuedEntityStatementClaimsSet();
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.keyID(RSA_JWK.getKeyID())
			.generate();
		
		SignedJWT signedJWT = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).type(EntityStatement.JOSE_OBJECT_TYPE).keyID(rsaJWK.getKeyID()).build(),
			claimsSet.toJWTClaimsSet()
		);
		signedJWT.sign(new RSASSASigner(rsaJWK)); // sign with non-registered key
		
		try {
			EntityStatement.parse(signedJWT.serialize()).verifySignatureOfSelfStatement();
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JWT rejected: Invalid signature", e.getMessage());
		}
	}
	
	
	public void testParseNotJWT() {
		
		try {
			EntityStatement.parse("invalid-jwt");
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid entity statement: Invalid serialized unsecured/JWS/JWE object: Missing part delimiters", e.getMessage());
		}
	}
}
