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

package com.nimbusds.openid.connect.sdk.federation.utils;


import java.text.ParseException;
import java.util.Collections;

import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;


public class JWTUtilsTest extends TestCase {
	
	
	public void testResolveSigningAlgorithm() throws JOSEException {
		
		// RSA
		assertEquals(JWSAlgorithm.RS256, JWTUtils.resolveSigningAlgorithm(new RSAKeyGenerator(2048).generate()));
		
		// EC
		assertEquals(JWSAlgorithm.ES256, JWTUtils.resolveSigningAlgorithm(new ECKeyGenerator(Curve.P_256).generate()));
		assertEquals(JWSAlgorithm.ES384, JWTUtils.resolveSigningAlgorithm(new ECKeyGenerator(Curve.P_384).generate()));
		assertEquals(JWSAlgorithm.ES512, JWTUtils.resolveSigningAlgorithm(new ECKeyGenerator(Curve.P_521).generate()));
		assertEquals(JWSAlgorithm.ES256K, JWTUtils.resolveSigningAlgorithm(new ECKeyGenerator(Curve.SECP256K1).generate()));
		
		// EdDSA
		assertEquals(JWSAlgorithm.EdDSA, JWTUtils.resolveSigningAlgorithm(new OctetKeyPairGenerator(Curve.Ed25519).generate()));
		
		// Unsupported
		try {
			JWTUtils.resolveSigningAlgorithm(new OctetSequenceKeyGenerator(128).generate());
			fail();
		} catch (JOSEException e) {
			assertEquals("Unsupported JWK type: " + KeyType.OCT, e.getMessage());
		}
	}
	
	
	public void testSign() throws JOSEException, com.nimbusds.oauth2.sdk.ParseException {
		
		JWK jwk = new RSAKeyGenerator(2048).keyID("1").generate();
		JWSAlgorithm alg = JWTUtils.resolveSigningAlgorithm(jwk);
		JOSEObjectType type = JOSEObjectType.JWT;
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("alice").build();
		
		SignedJWT jwt = JWTUtils.sign(jwk, alg, type, claimsSet);
		assertEquals(JWSObject.State.SIGNED, jwt.getState());
		
		assertEquals(alg, jwt.getHeader().getAlgorithm());
		assertEquals(type, jwt.getHeader().getType());
		assertEquals(jwk.getKeyID(), jwt.getHeader().getKeyID());
		assertEquals(3, jwt.getHeader().toJSONObject().size());
		
		assertEquals(claimsSet, JWTUtils.parseSignedJWTClaimsSet(jwt));
		
		assertTrue(jwt.verify(new RSASSAVerifier(jwk.toRSAKey().toPublicJWK())));
	}
	
	
	public void testVerify() throws JOSEException, BadJOSEException, ParseException {
		
		JWK jwk = new RSAKeyGenerator(2048).keyID("1").generate();
		JWSAlgorithm alg = JWTUtils.resolveSigningAlgorithm(jwk);
		JOSEObjectType type = JOSEObjectType.JWT;
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("alice").build();
		
		SignedJWT jwt = JWTUtils.sign(jwk, alg, type, claimsSet);
		
		assertEquals(
			ThumbprintUtils.compute(jwk),
			JWTUtils.verifySignature(
				jwt,
				type,
				new DefaultJWTClaimsVerifier<>(claimsSet, Collections.<String>emptySet()),
				new JWKSet(jwk)
			)
		);
		
		// Bad type
		try {
			JWTUtils.verifySignature(
				jwt,
				new JOSEObjectType("xxx"),
				new DefaultJWTClaimsVerifier<>(claimsSet, Collections.<String>emptySet()),
				new JWKSet(jwk)
			);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JWT rejected: Invalid or missing JWT typ (type) header", e.getMessage());
		}
		
		// No key match
		try {
			JWTUtils.verifySignature(
				jwt,
				type,
				new DefaultJWTClaimsVerifier<>(claimsSet, Collections.<String>emptySet()),
				new JWKSet(new ECKeyGenerator(Curve.P_256).generate().toPublicJWK()) // other key
			);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JWT rejected: Another JOSE algorithm expected, or no matching key(s) found", e.getMessage());
		}
		
		// Bad signature
		try {
			SignedJWT badJWT = SignedJWT.parse(jwt.getHeader().toBase64URL() + "." + jwt.getPayload().toBase64URL() + "." + "xxx");
			
			JWTUtils.verifySignature(
				badJWT,
				type,
				new DefaultJWTClaimsVerifier<>(claimsSet, Collections.<String>emptySet()),
				new JWKSet(jwk)
			);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JWT rejected: Invalid signature", e.getMessage());
		}
	}
	
	
	public void testVerify_missingType() throws JOSEException {
		
		JWK jwk = new RSAKeyGenerator(2048).keyID("1").generate();
		JWSAlgorithm alg = JWTUtils.resolveSigningAlgorithm(jwk);
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("alice").build();
		
		SignedJWT jwt = JWTUtils.sign(jwk, alg, null, claimsSet);
		
		// Bad type
		try {
			JWTUtils.verifySignature(
				jwt,
				JOSEObjectType.JWT,
				new DefaultJWTClaimsVerifier<>(claimsSet, Collections.<String>emptySet()),
				new JWKSet(jwk)
			);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("JWT rejected: Invalid or missing JWT typ (type) header", e.getMessage());
		}
	}
	
	
	public void testParseSignedJWTClaimsSet_notSigned() {
		
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), new JWTClaimsSet.Builder().subject("alice").build());
		
		try {
			JWTUtils.parseSignedJWTClaimsSet(jwt);
			fail();
		} catch (com.nimbusds.oauth2.sdk.ParseException e) {
			assertEquals("The JWT is not signed", e.getMessage());
		}
	}
	
	
	public void testParseSignedJWTClaimsSet_parseExceptionDueToIllegalClaimsFormat() throws JOSEException, ParseException {
		
		RSAKey key = new RSAKeyGenerator(2048).generate();
		
		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.RS256), new Payload("abc"));
		jwsObject.sign(new RSASSASigner(key));
		
		SignedJWT jwt = SignedJWT.parse(jwsObject.serialize());
		
		try {
			JWTUtils.parseSignedJWTClaimsSet(jwt);
			fail();
		} catch (com.nimbusds.oauth2.sdk.ParseException e) {
			assertEquals("Payload of JWS object is not a valid JSON object", e.getMessage());
		}
	}
}
