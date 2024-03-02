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

package com.nimbusds.oauth2.sdk.assertions.jwt;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils;
import junit.framework.TestCase;

import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;


/**
 * Tests the JWT assertion factory.
 */
public class JWTAssertionFactoryTest extends TestCase {


	public void testSupportedJWA() {

		assertTrue(JWTAssertionFactory.supportedJWAs().containsAll(JWSAlgorithm.Family.HMAC_SHA));
		assertTrue(JWTAssertionFactory.supportedJWAs().containsAll(JWSAlgorithm.Family.RSA));
		assertTrue(JWTAssertionFactory.supportedJWAs().containsAll(JWSAlgorithm.Family.EC));

		int algNum = JWSAlgorithm.Family.HMAC_SHA.size()
			+ JWSAlgorithm.Family.RSA.size()
			+ JWSAlgorithm.Family.EC.size();

		assertEquals(algNum, JWTAssertionFactory.supportedJWAs().size());
	}
	
	
	public void testCreateSigned_RSA256() throws Exception {
		
		Issuer op = new Issuer("https://c2id.com");
		
		ClientID clientID = new ClientID("123");
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.keyUse(KeyUse.SIGNATURE)
			.keyID("1")
			.generate();
		
		Date now = new Date();
		Date oneDayAgo = new Date(now.getTime() - 1000*60*60*24);
		Date oneDayAhead = new Date(now.getTime() + 1000*60*60*24);
		
		X509Certificate cert = X509CertificateUtils.generate(
			new Issuer("https://ca.example.com"),
			new Subject(clientID.getValue()),
			oneDayAgo,
			oneDayAhead,
			rsaJWK.toRSAPublicKey(),
			rsaJWK.toPrivateKey());
		
		List<Base64> x5c = Collections.singletonList(Base64.encode(cert.getEncoded()));
		
		Base64URL x5t256 = X509CertUtils.computeSHA256Thumbprint(cert);
		
		JWTAssertionDetails details = new JWTAssertionDetails(
			new Issuer(clientID.getValue()),
			new Subject(op.getValue()),
			new Audience(op.getValue() + "/token"));
		
		for (Provider provider: Arrays.asList(null, BouncyCastleProviderSingleton.getInstance())) {
			
			SignedJWT jwt = JWTAssertionFactory.create(
				details,
				JWSAlgorithm.RS256,
				rsaJWK.toPrivateKey(),
				rsaJWK.getKeyID(),
				x5c,
				x5t256,
				provider);
			
			assertEquals(JWSAlgorithm.RS256, jwt.getHeader().getAlgorithm());
			assertEquals(rsaJWK.getKeyID(), jwt.getHeader().getKeyID());
			assertEquals(x5c, jwt.getHeader().getX509CertChain());
			assertEquals(x5t256, jwt.getHeader().getX509CertSHA256Thumbprint());
			assertEquals(4, jwt.getHeader().getIncludedParams().size());
			
			assertEquals(details.toJWTClaimsSet(), jwt.getJWTClaimsSet());
			
			RSASSAVerifier verifier = new RSASSAVerifier(rsaJWK.toRSAPublicKey());
			verifier.getJCAContext().setProvider(provider);
			
			assertTrue(jwt.verify(verifier));
		}
	}
	
	
	public void testCreateSigned_ES256K() throws Exception {
		
		Issuer op = new Issuer("https://c2id.com");
		
		ClientID clientID = new ClientID("123");
		
		ECKey ecJWK = new ECKeyGenerator(Curve.SECP256K1)
			.keyUse(KeyUse.SIGNATURE)
			.keyID("1")
			.provider(BouncyCastleProviderSingleton.getInstance())
			.generate();
		
		JWTAssertionDetails details = new JWTAssertionDetails(
			new Issuer(clientID.getValue()),
			new Subject(op.getValue()),
			new Audience(op.getValue() + "/token"));
		
		SignedJWT jwt = JWTAssertionFactory.create(
			details,
			JWSAlgorithm.ES256K,
			ecJWK.toPrivateKey(),
			null,
			null,
			null,
			BouncyCastleProviderSingleton.getInstance());
		
		assertEquals(JWSAlgorithm.ES256K, jwt.getHeader().getAlgorithm());
		assertEquals(1, jwt.getHeader().getIncludedParams().size());
		
		assertEquals(details.toJWTClaimsSet(), jwt.getJWTClaimsSet());

		ECDSAVerifier verifier = new ECDSAVerifier(ecJWK.toECPublicKey());
		verifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		assertTrue(jwt.verify(verifier));
	}
	
	
	public void testCreateSigned_unsupportedJWSAlg() throws Exception {
		
		Issuer op = new Issuer("https://c2id.com");
		
		ClientID clientID = new ClientID("123");
		
		ECKey ecJWK = new ECKeyGenerator(Curve.SECP256K1)
			.keyUse(KeyUse.SIGNATURE)
			.keyID("1")
			.provider(BouncyCastleProviderSingleton.getInstance())
			.generate();
		
		JWTAssertionDetails details = new JWTAssertionDetails(
			new Issuer(clientID.getValue()),
			new Subject(op.getValue()),
			new Audience(op.getValue() + "/token"));
		
		try {
			JWTAssertionFactory.create(
				details,
				new JWSAlgorithm("xxx"),
				ecJWK.toPrivateKey(),
				ecJWK.getKeyID(),
				null,
				null,
				null);
			
			fail();
		} catch (JOSEException e) {
			assertEquals("Unsupported JWS algorithm: xxx", e.getMessage());
		}
	}
}
