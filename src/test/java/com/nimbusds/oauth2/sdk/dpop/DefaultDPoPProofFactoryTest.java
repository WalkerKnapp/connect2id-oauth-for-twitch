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

package com.nimbusds.oauth2.sdk.dpop;


import java.net.URI;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;


public class DefaultDPoPProofFactoryTest extends TestCase {
	
	
	static final JWK RSA_JWK;
	
	static final JWK EC_JWK;
	
	static final JWK ED_JWK;

	static final JWTID JTI = new JWTID();
	
	static final String HTM = "POST";
	
	static final URI HTU = URI.create("https://c2id.com/token");
	
	static final AccessToken ACCESS_TOKEN = new BearerAccessToken();
	
	static final Nonce NONCE = new Nonce();
	
	static {
		try {
			RSA_JWK = new RSAKeyGenerator(2048)
				.generate();
			
			EC_JWK = new ECKeyGenerator(Curve.P_256)
				.generate();
			
			ED_JWK = new OctetKeyPairGenerator(Curve.Ed25519)
				.generate();
			
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public void testMinimalConstructor_RSA()
		throws JOSEException, ParseException {
		
		JWSVerifier verifier = new RSASSAVerifier(RSA_JWK.toPublicJWK().toRSAKey());
		
		for (JWSAlgorithm jwsAlg: JWSAlgorithm.Family.RSA) {
			testCycle(RSA_JWK, jwsAlg, verifier);
		}
		
		testCycle(EC_JWK, JWSAlgorithm.ES256, new ECDSAVerifier(EC_JWK.toPublicJWK().toECKey()));
		
		testCycle(ED_JWK, JWSAlgorithm.EdDSA, new Ed25519Verifier(ED_JWK.toPublicJWK().toOctetKeyPair()));
	}
	
	
	static void testCycle(final JWK jwk, final JWSAlgorithm jwsAlg, final JWSVerifier jwsVerifier)
		throws JOSEException, ParseException {
		
		DefaultDPoPProofFactory factory = new DefaultDPoPProofFactory(jwk, jwsAlg);
		
		assertEquals(jwk.toPublicJWK(), factory.getPublicJWK());
		
		assertEquals(jwsAlg, factory.getJWSAlgorithm());
		
		SignedJWT jwt;
		
		for (boolean withNonce: Arrays.asList(false, true)) {
		
			if (withNonce) {
				jwt = factory.createDPoPJWT(HTM, HTU, NONCE);
			} else {
				jwt = factory.createDPoPJWT(HTM, HTU);
			}
			
			assertTrue(jwt.verify(jwsVerifier));
			
			JWSHeader header = jwt.getHeader();
			assertEquals(jwsAlg, header.getAlgorithm());
			assertEquals(DefaultDPoPProofFactory.TYPE, header.getType());
			assertEquals(factory.getPublicJWK(), header.getJWK());
			assertEquals(3, header.getIncludedParams().size());
			
			JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
			String jti = claimsSet.getJWTID();
			assertEquals(DefaultDPoPProofFactory.MINIMAL_JTI_BYTE_LENGTH, new Base64URL(jti).decode().length);
			assertEquals(HTM, claimsSet.getStringClaim("htm"));
			assertEquals(HTU, claimsSet.getURIClaim("htu"));
			DateUtils.isWithin(claimsSet.getIssueTime(), new Date(), 2);
			
			if (withNonce) {
				assertEquals(NONCE.getValue(), claimsSet.getStringClaim("nonce"));
				assertEquals(5, claimsSet.getClaims().size());
			} else {
				assertEquals(4, claimsSet.getClaims().size());
			}
		}
	}
	
	
	public void testFullySpecified()
		throws JOSEException, ParseException {
		
		DefaultDPoPProofFactory factory = new DefaultDPoPProofFactory(RSA_JWK, JWSAlgorithm.RS256);
		
		assertEquals(RSA_JWK.toPublicJWK(), factory.getPublicJWK());
		
		assertEquals(JWSAlgorithm.RS256, factory.getJWSAlgorithm());
		
		Date iat = DateUtils.fromSecondsSinceEpoch(new Date().getTime() / 1000);
		
		SignedJWT jwt = factory.createDPoPJWT(JTI, HTM, HTU, iat, ACCESS_TOKEN, NONCE);
		
		assertTrue(jwt.verify(new RSASSAVerifier(RSA_JWK.toPublicJWK().toRSAKey())));
		
		JWSHeader header = jwt.getHeader();
		assertEquals(JWSAlgorithm.RS256, header.getAlgorithm());
		assertEquals(DefaultDPoPProofFactory.TYPE, header.getType());
		assertEquals(factory.getPublicJWK(), header.getJWK());
		assertEquals(3, header.getIncludedParams().size());
		
		JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
		assertEquals(JTI.getValue(), claimsSet.getJWTID());
		assertEquals(HTM, claimsSet.getStringClaim("htm"));
		assertEquals(HTU, claimsSet.getURIClaim("htu"));
		assertEquals(iat, claimsSet.getIssueTime());
		assertEquals(DPoPUtils.computeSHA256(ACCESS_TOKEN).toString(), claimsSet.getStringClaim("ath"));
		assertEquals(NONCE.getValue(), claimsSet.getStringClaim("nonce"));
		assertEquals(6, claimsSet.getClaims().size());
	}
}
