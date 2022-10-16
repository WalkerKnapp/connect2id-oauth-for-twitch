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

package com.nimbusds.openid.connect.sdk.federation.config;


import java.net.URI;
import java.util.Collections;
import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;


public class FederationEntityConfigurationSuccessResponseTest extends TestCase {
	
	
	private static final RSAKey RSA_JWK;
	
	
	private static final JWKSet SIMPLE_JWK_SET;
	
	
	private static final OIDCProviderMetadata OP_METADATA;
	
	
	static {
		try {
			RSA_JWK = new RSAKeyGenerator(2048)
				.keyIDFromThumbprint(true)
				.keyUse(KeyUse.SIGNATURE)
				.generate();
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
	
	
	public void testLifeCycle()
		throws Exception {
		
		Issuer iss = OP_METADATA.getIssuer();
		Subject sub = new Subject(OP_METADATA.getIssuer().getValue());
		
		Date now = new Date();
		long nowTS = DateUtils.toSecondsSinceEpoch(now);
		Date iat = DateUtils.fromSecondsSinceEpoch(nowTS);
		Date exp = DateUtils.fromSecondsSinceEpoch(nowTS + 60);
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			iss,
			sub,
			iat,
			exp,
			SIMPLE_JWK_SET);
		stmt.setOPMetadata(OP_METADATA);
		
		EntityStatement entityStatement = EntityStatement.sign(stmt, RSA_JWK);
		
		FederationEntityConfigurationSuccessResponse response = new FederationEntityConfigurationSuccessResponse(entityStatement);
		
		SignedJWT signedJWT = response.getEntityStatement().getSignedStatement();
		assertEquals(JWSAlgorithm.RS256, signedJWT.getHeader().getAlgorithm());
		assertEquals(stmt.toJWTClaimsSet().getClaims(), signedJWT.getJWTClaimsSet().getClaims());
		
		response.getEntityStatement().verifySignatureOfSelfStatement();
		assertEquals(stmt.toJWTClaimsSet().getClaims(), response.getEntityStatement().getClaimsSet().toJWTClaimsSet().getClaims());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertEquals(200, httpResponse.getStatusCode());
		assertEquals(EntityStatement.CONTENT_TYPE.toString(), httpResponse.getEntityContentType().toString());
		assertEquals(signedJWT.serialize(), httpResponse.getContent());
		
		response = FederationEntityConfigurationResponse.parse(httpResponse).toSuccessResponse();
		
		assertEquals(signedJWT.serialize(), response.getEntityStatement().getSignedStatement().getParsedString());
		
		response.getEntityStatement().verifySignatureOfSelfStatement();
		assertEquals(stmt.toJWTClaimsSet().getClaims(), response.getEntityStatement().getClaimsSet().toJWTClaimsSet().getClaims());
	}
	
	
	public void testInvalidSignature()
		throws Exception {
		
		Issuer iss = OP_METADATA.getIssuer();
		Subject sub = new Subject(OP_METADATA.getIssuer().getValue());
		
		Date now = new Date();
		long nowTS = DateUtils.toSecondsSinceEpoch(now);
		Date iat = DateUtils.fromSecondsSinceEpoch(nowTS);
		Date exp = DateUtils.fromSecondsSinceEpoch(nowTS + 60);
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			iss,
			sub,
			iat,
			exp,
			SIMPLE_JWK_SET);
		stmt.setOPMetadata(OP_METADATA);
		
		Audience audience = new Audience("https://rp.example.com");
		stmt.setAudience(audience);
		
		RSAKey signingJWK = new RSAKeyGenerator(2048).generate();
		
		SignedJWT signedStatement = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(EntityStatement.JOSE_OBJECT_TYPE)
				.keyID(signingJWK.getKeyID())
				.build(),
			stmt.toJWTClaimsSet());
		signedStatement.sign(new RSASSASigner(signingJWK));
		
		FederationEntityConfigurationSuccessResponse response = new FederationEntityConfigurationSuccessResponse(EntityStatement.parse(signedStatement));
		HTTPResponse httpResponse = response.toHTTPResponse();
		response = FederationEntityConfigurationResponse.parse(httpResponse).toSuccessResponse();
		
		try {
			response.getEntityStatement().verifySignatureOfSelfStatement();
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JWT rejected: Invalid signature", e.getMessage());
		}
	}
	
	
	public void testNotSelfIssued()
		throws Exception {
		
		Issuer iss = OP_METADATA.getIssuer();
		Subject sub = new Subject("https://some-host.example.com");
		
		Date now = new Date();
		long nowTS = DateUtils.toSecondsSinceEpoch(now);
		Date iat = DateUtils.fromSecondsSinceEpoch(nowTS - 3600);
		Date exp = DateUtils.fromSecondsSinceEpoch(nowTS - 1800);
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			iss,
			sub,
			iat,
			exp,
			SIMPLE_JWK_SET);
		stmt.setOPMetadata(OP_METADATA);
		
		Audience audience = new Audience("https://rp.example.com");
		stmt.setAudience(audience);
		
		EntityStatement entityStatement = EntityStatement.sign(stmt, RSA_JWK);
		
		FederationEntityConfigurationSuccessResponse response = new FederationEntityConfigurationSuccessResponse(entityStatement);
		HTTPResponse httpResponse = response.toHTTPResponse();
		response = FederationEntityConfigurationResponse.parse(httpResponse).toSuccessResponse();
		
		try {
			response.getEntityStatement().verifySignatureOfSelfStatement();
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Entity statement not self-issued", e.getMessage());
		}
	}
	
	
	public void testExpired()
		throws Exception {
		
		Issuer iss = OP_METADATA.getIssuer();
		Subject sub = new Subject(OP_METADATA.getIssuer().getValue());
		
		Date now = new Date();
		long nowTS = DateUtils.toSecondsSinceEpoch(now);
		Date iat = DateUtils.fromSecondsSinceEpoch(nowTS - 3600);
		Date exp = DateUtils.fromSecondsSinceEpoch(nowTS - 1800);
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			iss,
			sub,
			iat,
			exp,
			SIMPLE_JWK_SET);
		stmt.setOPMetadata(OP_METADATA);
		
		Audience audience = new Audience("https://rp.example.com");
		stmt.setAudience(audience);
		
		EntityStatement entityStatement = EntityStatement.sign(stmt, RSA_JWK);
		
		FederationEntityConfigurationSuccessResponse response = new FederationEntityConfigurationSuccessResponse(entityStatement);
		HTTPResponse httpResponse = response.toHTTPResponse();
		response = FederationEntityConfigurationResponse.parse(httpResponse).toSuccessResponse();
		
		try {
			response.getEntityStatement().verifySignatureOfSelfStatement();
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Expired JWT", e.getMessage());
		}
	}
	
	
	public void testIssueTimeInFuture()
		throws Exception {
		
		Issuer iss = OP_METADATA.getIssuer();
		Subject sub = new Subject(OP_METADATA.getIssuer().getValue());
		
		Date now = new Date();
		long nowTS = DateUtils.toSecondsSinceEpoch(now);
		Date iat = DateUtils.fromSecondsSinceEpoch(nowTS + 1800);
		Date exp = DateUtils.fromSecondsSinceEpoch(nowTS + 3600);
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			iss,
			sub,
			iat,
			exp,
			SIMPLE_JWK_SET);
		stmt.setOPMetadata(OP_METADATA);
		
		Audience audience = new Audience("https://rp.example.com");
		stmt.setAudience(audience);
		
		EntityStatement entityStatement = EntityStatement.sign(stmt, RSA_JWK);
		
		FederationEntityConfigurationSuccessResponse response = new FederationEntityConfigurationSuccessResponse(entityStatement);
		HTTPResponse httpResponse = response.toHTTPResponse();
		response = FederationEntityConfigurationResponse.parse(httpResponse).toSuccessResponse();
		
		try {
			response.getEntityStatement().verifySignatureOfSelfStatement();
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JWT issue time after current time", e.getMessage());
		}
	}
	
	
	public void testParseEmptyEntityBody() {
		
		HTTPResponse httpResponse = new HTTPResponse(200);
		httpResponse.setEntityContentType(EntityStatement.CONTENT_TYPE);
		
		try {
			FederationEntityConfigurationSuccessResponse.parse(httpResponse);
			fail();
		} catch (ParseException e) {
			assertEquals("Empty HTTP entity body", e.getMessage());
		}
	}
}