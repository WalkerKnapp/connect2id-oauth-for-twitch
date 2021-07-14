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

package com.nimbusds.oauth2.sdk.dpop.verifiers;


import java.net.URI;
import java.util.Collections;
import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.id.JWTID;


public class DPoPTokenRequestVerifierTest extends TestCase {
	
	
	public void testForTokenEndpoint_RS256() throws Exception {
		
		String htm = "POST";
		URI htu = URI.create("https://c2id.com/token");
		
		DPoPIssuer issuer = new DPoPIssuer("client-123");
		RSAKey rsaJWK = new RSAKeyGenerator(2048).generate();
		DPoPProofFactory dPoPProofFactory = new DefaultDPoPProofFactory(
			rsaJWK,
			JWSAlgorithm.RS256
		);
		
		DPoPTokenRequestVerifier verifier = new DPoPTokenRequestVerifier(
			Collections.singleton(JWSAlgorithm.RS256),
			htu,
			2,
			new DefaultDPoPSingleUseChecker(
				10,
				10
			)
		);
		
		SignedJWT proof = dPoPProofFactory.createDPoPJWT(htm, htu);
		
		verifier.verify(issuer, proof);
		
		// Replay detection
		try {
			verifier.verify(issuer, proof);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: The jti was used before: " + proof.getJWTClaimsSet().getJWTID(), e.getMessage());
		}
		
		// Invalid HTTP URL
		proof = dPoPProofFactory.createDPoPJWT(htm, URI.create("https://op.example.com/userinfo"));
		
		try {
			verifier.verify(issuer, proof);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: JWT \"htu\" claim has value https://op.example.com/userinfo, must be https://c2id.com/token", e.getMessage());
		}
		
		// Invalid HTTP method
		proof = dPoPProofFactory.createDPoPJWT("GET", htu);
		
		try {
			verifier.verify(issuer, proof);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: JWT \"htm\" claim has value GET, must be POST", e.getMessage());
		}
		
		// JWS alg not accepted
		proof = new DefaultDPoPProofFactory(
			new ECKeyGenerator(Curve.P_256).generate(),
			JWSAlgorithm.ES256
		).createDPoPJWT(htm, htu);
		
		try {
			verifier.verify(issuer, proof);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: JWS header algorithm not accepted: ES256", e.getMessage());
		}
		
		// Missing typ header
		JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
			.jwtID(new JWTID().getValue())
			.claim("htm", htm)
			.claim("htu", htu.toString())
			.issueTime(new Date())
			.build();
		proof = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).jwk(rsaJWK.toPublicJWK()).build(),
			jwtClaimsSet
		);
		proof.sign(new RSASSASigner(rsaJWK));
		
		try {
			verifier.verify(issuer, proof);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: Required JOSE header \"typ\" (type) parameter is missing", e.getMessage());
		}
		
		// Missing jwk header
		proof = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).type(DPoPProofFactory.TYPE).build(),
			jwtClaimsSet
		);
		proof.sign(new RSASSASigner(rsaJWK));
		
		try {
			verifier.verify(issuer, proof);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: Missing JWS jwk header parameter", e.getMessage());
		}
		
		// Signing key doesn't match jwk header
		proof = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(DPoPProofFactory.TYPE)
				.jwk(new RSAKeyGenerator(2048).generate().toPublicJWK())
				.build(),
			jwtClaimsSet
		);
		proof.sign(new RSASSASigner(rsaJWK));
		
		try {
			verifier.verify(issuer, proof);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: Signed JWT rejected: Invalid signature", e.getMessage());
		}
		
		// jwk in header other key type
		proof = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(DPoPProofFactory.TYPE)
				.jwk(new ECKeyGenerator(Curve.P_256).generate().toPublicJWK())
				.build(),
			jwtClaimsSet
		);
		proof.sign(new RSASSASigner(rsaJWK));
		
		try {
			verifier.verify(issuer, proof);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: JWS header alg / jwk mismatch: alg=RS256 jwk.kty=EC", e.getMessage());
		}
	}
	
	
	public void testConstructor_nullEndpoint() {
		
		IllegalArgumentException exception = null;
		try {
			new DPoPTokenRequestVerifier(
				Collections.singleton(JWSAlgorithm.RS256),
				null,
				2,
				new DefaultDPoPSingleUseChecker(
					10,
					10
				)
			);
		} catch (IllegalArgumentException e) {
			exception = e;
		}
		
		assertEquals("The token endpoint URI must not be null", exception.getMessage());
	}
}
