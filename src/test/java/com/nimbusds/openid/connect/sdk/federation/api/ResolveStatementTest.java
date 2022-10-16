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
import java.text.ParseException;
import java.util.Collections;
import java.util.Date;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;
import com.nimbusds.openid.connect.sdk.federation.registration.ClientRegistrationType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;


public class ResolveStatementTest extends TestCase {
	
	public static final RSAKey RSA_JWK;
	public static final JWKSet SIMPLE_JWK_SET;
	private static final Issuer ISS = new Issuer("https://abc-federation.c2id.com");
	private static final Subject SUB = new Subject("https://op.c2id.com");
	private static final Date NOW = new Date();
	private static final Date IAT = DateUtils.fromSecondsSinceEpoch(DateUtils.toSecondsSinceEpoch(NOW));
	private static final Date EXP = DateUtils.fromSecondsSinceEpoch(DateUtils.toSecondsSinceEpoch(NOW) + 3600);
	
	private static final OIDCProviderMetadata OP_METADATA = new OIDCProviderMetadata(
		new Issuer(SUB),
		Collections.singletonList(SubjectType.PAIRWISE),
		Collections.singletonList(ClientRegistrationType.AUTOMATIC),
		null,
		URI.create("https://op.c2id.com/jwks.jwt"),
		null);
	
	private static final JSONObject METADATA = new JSONObject();
	
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
		METADATA.put(EntityType.OPENID_PROVIDER.getValue(), OP_METADATA.toJSONObject());
	}
	
	
	public void testTypeConstant() {
		
		assertEquals(new JOSEObjectType("resolve-response+jwt"), ResolveStatement.JOSE_OBJECT_TYPE);
		assertEquals(new ContentType("application", "resolve-response+jwt"), ResolveStatement.CONTENT_TYPE);
	}
	

	public void testLifeCycle_defaultJWSAlg() throws JOSEException, BadJOSEException, ParseException, com.nimbusds.oauth2.sdk.ParseException {
		
		ResolveClaimsSet claimsSet = new ResolveClaimsSet(ISS, SUB, IAT, EXP, METADATA);
		
		ResolveStatement resolveStatement = ResolveStatement.sign(claimsSet, RSA_JWK);
		
		assertEquals(claimsSet, resolveStatement.getClaimsSet());
		
		SignedJWT jwt = resolveStatement.getSignedStatement();
		assertEquals(JWSAlgorithm.RS256, jwt.getHeader().getAlgorithm());
		assertEquals(ResolveStatement.JOSE_OBJECT_TYPE, jwt.getHeader().getType());
		assertEquals(RSA_JWK.getKeyID(), jwt.getHeader().getKeyID());
		assertEquals(3, jwt.getHeader().toJSONObject().size());
		
		assertEquals(claimsSet.toJWTClaimsSet(), jwt.getJWTClaimsSet());
		
		assertEquals(RSA_JWK.computeThumbprint(), resolveStatement.verifySignature(SIMPLE_JWK_SET));
		
		resolveStatement = ResolveStatement.parse(jwt.serialize());
		
		assertEquals(claimsSet, resolveStatement.getClaimsSet());
		
		assertEquals(RSA_JWK.computeThumbprint(), resolveStatement.verifySignature(SIMPLE_JWK_SET));
	}
	

	public void testLifeCycle_explicitJWSAlg() throws JOSEException, BadJOSEException, ParseException, com.nimbusds.oauth2.sdk.ParseException {
		
		JWSAlgorithm alg = JWSAlgorithm.PS256;
		
		ResolveClaimsSet claimsSet = new ResolveClaimsSet(ISS, SUB, IAT, EXP, METADATA);
		
		ResolveStatement resolveStatement = ResolveStatement.sign(claimsSet, RSA_JWK, alg);
		
		assertEquals(claimsSet, resolveStatement.getClaimsSet());
		
		SignedJWT jwt = resolveStatement.getSignedStatement();
		assertEquals(alg, jwt.getHeader().getAlgorithm());
		assertEquals(ResolveStatement.JOSE_OBJECT_TYPE, jwt.getHeader().getType());
		assertEquals(RSA_JWK.getKeyID(), jwt.getHeader().getKeyID());
		assertEquals(3, jwt.getHeader().toJSONObject().size());
		
		assertEquals(claimsSet.toJWTClaimsSet(), jwt.getJWTClaimsSet());
		
		assertEquals(RSA_JWK.computeThumbprint(), resolveStatement.verifySignature(SIMPLE_JWK_SET));
		
		resolveStatement = ResolveStatement.parse(jwt.serialize());
		
		assertEquals(claimsSet, resolveStatement.getClaimsSet());
		
		assertEquals(RSA_JWK.computeThumbprint(), resolveStatement.verifySignature(SIMPLE_JWK_SET));
	}
	
	
	public void testExpired() throws Exception {
		
		Date iat = new Date(0); // in the past
		Date exp = new Date(1000); // in the past
		
		ResolveClaimsSet claimsSet = new ResolveClaimsSet(ISS, SUB, iat, exp, METADATA);
		
		ResolveStatement resolveStatement = ResolveStatement.sign(claimsSet, RSA_JWK);
		
		try {
			ResolveStatement.parse(resolveStatement.getSignedStatement()).verifySignature(SIMPLE_JWK_SET);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Expired JWT", e.getMessage());
		}
	}
	
	
	public void testInvalidSignature_signature() throws Exception {
		
		ResolveClaimsSet claimsSet = new ResolveClaimsSet(ISS, SUB, IAT, EXP, METADATA);
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.keyID(RSA_JWK.getKeyID()) // copy kid
			.generate();
		
		ResolveStatement resolveStatement = ResolveStatement.sign(claimsSet, rsaJWK); // sign with non-registered key
		
		try {
			ResolveStatement.parse(resolveStatement.getSignedStatement().serialize()).verifySignature(SIMPLE_JWK_SET);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JWT rejected: Invalid signature", e.getMessage());
		}
	}
	
	
	public void testParseNotJWT() {
		
		try {
			ResolveStatement.parse("invalid-jwt");
			fail();
		} catch (com.nimbusds.oauth2.sdk.ParseException e) {
			assertEquals("Invalid resolve statement: Invalid serialized unsecured/JWS/JWE object: Missing part delimiters", e.getMessage());
		}
	}
}
