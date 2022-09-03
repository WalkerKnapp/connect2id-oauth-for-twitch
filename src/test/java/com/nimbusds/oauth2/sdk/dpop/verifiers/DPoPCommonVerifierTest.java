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
import java.util.*;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;


public class DPoPCommonVerifierTest extends TestCase {
	
	
	private static final ECKey EC_JWK;
	
	
	static {
		try {
			EC_JWK = new ECKeyGenerator(Curve.P_256)
				.keyID("1")
				.generate();
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}


	public void testSupportedJWSAlgorithms() {
		
		Set<JWSAlgorithm> jwsAlgorithms = new HashSet<>();
		jwsAlgorithms.addAll(JWSAlgorithm.Family.RSA);
		jwsAlgorithms.addAll(JWSAlgorithm.Family.EC);
		
		assertEquals(jwsAlgorithms, DPoPCommonVerifier.SUPPORTED_JWS_ALGORITHMS);
		
		new DPoPCommonVerifier(
			jwsAlgorithms,
			2,
			new DefaultDPoPSingleUseChecker(
				10,
				10
			)
		);
	}
	
	
	public void testForTokenEndpoint_ES256() throws Exception {
		
		String htm = "POST";
		URI htu = URI.create("https://c2id.com/token");
		
		DPoPIssuer issuer = new DPoPIssuer("client-123");
		DPoPProofFactory dPoPProofFactory = new DefaultDPoPProofFactory(
			EC_JWK,
			JWSAlgorithm.ES256
		);
		
		DPoPCommonVerifier verifier = new DPoPCommonVerifier(
			Collections.singleton(JWSAlgorithm.ES256),
			2,
			new DefaultDPoPSingleUseChecker(
				10,
				10
			)
		);
		
		// Basic
		SignedJWT proof = dPoPProofFactory.createDPoPJWT(htm, htu);
		
		verifier.verify(htm, htu, issuer, proof, null, null, null);
		
		// Replay detection
		try {
			verifier.verify(htm, htu, issuer, proof, null, null, null);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: The jti was used before: " + proof.getJWTClaimsSet().getJWTID(), e.getMessage());
		}
		
		// Nonce
		Nonce nonce = new Nonce();
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, nonce);
		
		verifier.verify(htm, htu, issuer, proof, null, null, nonce);
		
		// Replay detection with nonce
		try {
			verifier.verify(htm, htu, issuer, proof, null, null, nonce);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: The jti was used before: " + proof.getJWTClaimsSet().getJWTID(), e.getMessage());
		}
		
		// Invalid nonce
		Nonce proofNonce = new Nonce();
		Nonce expectedNonce = new Nonce();
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, proofNonce);
		try {
			verifier.verify(htm, htu, issuer, proof, null, null, expectedNonce);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: JWT nonce claim has value " + proofNonce + ", must be " + expectedNonce, e.getMessage());
		}
		
		
		// Invalid HTTP method
		proof = dPoPProofFactory.createDPoPJWT("PUT", htu);
		
		try {
			verifier.verify(htm, htu, issuer, proof, null, null, null);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: JWT htm claim has value PUT, must be POST", e.getMessage());
		}
		
		// Invalid HTTP URL
		proof = dPoPProofFactory.createDPoPJWT(htm, URI.create("https://op.example.com/userinfo"));
		
		try {
			verifier.verify(htm, htu, issuer, proof, null, null, null);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: JWT htu claim has value https://op.example.com/userinfo, must be https://c2id.com/token", e.getMessage());
		}
		
		// JWS alg not accepted
		proof = new DefaultDPoPProofFactory(
				new RSAKeyGenerator(2048).generate(),
				JWSAlgorithm.RS256
			).createDPoPJWT(htm, htu);
		
		try {
			verifier.verify(htm, htu, issuer, proof, null, null, null);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: JWS header algorithm not accepted: RS256", e.getMessage());
		}
		
		// Missing typ header
		JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
			.jwtID(new JWTID().getValue())
			.claim("htm", htm)
			.claim("htu", htu.toString())
			.issueTime(new Date())
			.build();
		proof = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.ES256).jwk(EC_JWK.toPublicJWK()).build(),
			jwtClaimsSet
		);
		proof.sign(new ECDSASigner(EC_JWK));
		
		try {
			verifier.verify(htm, htu, issuer, proof, null, null, null);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: Required JOSE header typ (type) parameter is missing", e.getMessage());
		}
		
		// Missing jwk header
		proof = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.ES256).type(DPoPProofFactory.TYPE).build(),
			jwtClaimsSet
		);
		proof.sign(new ECDSASigner(EC_JWK));
		
		try {
			verifier.verify(htm, htu, issuer, proof, null, null, null);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: Missing JWS jwk header parameter", e.getMessage());
		}
		
		// Signing key doesn't match jwk header
		proof = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.ES256)
				.type(DPoPProofFactory.TYPE)
				.jwk(new ECKeyGenerator(Curve.P_256).generate().toPublicJWK())
				.build(),
			jwtClaimsSet
		);
		proof.sign(new ECDSASigner(EC_JWK));
		
		try {
			verifier.verify(htm, htu, issuer, proof, null, null, null);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: Signed JWT rejected: Invalid signature", e.getMessage());
		}
		
		// jwk in header other key type
		proof = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.ES256)
				.type(DPoPProofFactory.TYPE)
				.jwk(new RSAKeyGenerator(2048).generate().toPublicJWK())
				.build(),
			jwtClaimsSet
		);
		proof.sign(new ECDSASigner(EC_JWK));
		
		try {
			verifier.verify(htm, htu, issuer, proof, null, null, null);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: JWS header alg / jwk mismatch: alg=ES256 jwk.kty=RSA", e.getMessage());
		}
	}
	
	
	public void testForProtectedResource() throws Exception {
		
		String htm = "POST";
		URI htu = URI.create("https://c2id.com/userinfo");
		
		DPoPAccessToken accessToken = new DPoPAccessToken("iat5luciwooSa8Ogh5eweicahG8soo8a");
		
		DPoPIssuer issuer = new DPoPIssuer("client-123");
		ECKey EC_JWK = new ECKeyGenerator(Curve.P_256).generate();
		Base64URL jkt = EC_JWK.computeThumbprint();
		JWKThumbprintConfirmation cnf = new JWKThumbprintConfirmation(jkt);
		DPoPProofFactory dPoPProofFactory = new DefaultDPoPProofFactory(
			EC_JWK,
			JWSAlgorithm.ES256
		);
		
		DPoPCommonVerifier verifier = new DPoPCommonVerifier(
			Collections.singleton(JWSAlgorithm.ES256),
			2,
			new DefaultDPoPSingleUseChecker(
				10,
				10
			)
		);
		
		// Basic
		SignedJWT proof = dPoPProofFactory.createDPoPJWT(htm, htu, accessToken);
		assertNotNull(proof.getJWTClaimsSet().getStringClaim("ath"));
		
		verifier.verify(htm, htu, issuer, proof, accessToken, cnf, null);
		
		// Replay detection
		try {
			verifier.verify(htm, htu, issuer, proof, accessToken, cnf, null);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: The jti was used before: " + proof.getJWTClaimsSet().getJWTID(), e.getMessage());
		}
		
		// Nonce
		Nonce nonce = new Nonce();
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, accessToken, nonce);
		
		verifier.verify(htm, htu, issuer, proof, accessToken, cnf, nonce);
		
		// Replay detection with nonce
		try {
			verifier.verify(htm, htu, issuer, proof, accessToken, cnf, nonce);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: The jti was used before: " + proof.getJWTClaimsSet().getJWTID(), e.getMessage());
		}
		
		// Invalid nonce
		Nonce proofNonce = new Nonce();
		Nonce expectedNonce = new Nonce();
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, accessToken, proofNonce);
		try {
			verifier.verify(htm, htu, issuer, proof, accessToken, null, expectedNonce);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: JWT nonce claim has value " + proofNonce + ", must be " + expectedNonce, e.getMessage());
		}
		
		// Missing cnf
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, accessToken);
		NullPointerException npe = null;
		try {
			verifier.verify(htm, htu, issuer, proof, accessToken, null, null);
			fail();
		} catch (NullPointerException e) {
			npe = e;
		}
		assertNotNull(npe);
		
		// Missing ath
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, (AccessToken) null);
		try {
			verifier.verify(htm, htu, issuer, proof, accessToken, cnf, null);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: JWT missing required claims: [ath]", e.getMessage());
		}
		
		// Invalid ath - access token binding
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, new DPoPAccessToken("other-value"));
		
		try {
			verifier.verify(htm, htu, issuer, proof, accessToken, cnf, null);
			fail();
		} catch (AccessTokenValidationException e) {
			assertEquals("The access token hash doesn't match the JWT ath claim", e.getMessage());
		}
		
		// Invalid cnf - access token binding
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, accessToken);
		
		JWKThumbprintConfirmation invalidCNF = new JWKThumbprintConfirmation(new ECKeyGenerator(Curve.P_256).generate().computeThumbprint());
		
		try {
			verifier.verify(htm, htu, issuer, proof, accessToken, invalidCNF, null);
			fail();
		} catch (AccessTokenValidationException e) {
			assertEquals("The DPoP proof JWK doesn't match the JWK SHA-256 thumbprint confirmation", e.getMessage());
		}
	}
	
	
	public void testWithoutSingleUseChecker() throws Exception {
		
		String htm = "POST";
		URI htu = URI.create("https://c2id.com/token");
		
		DPoPIssuer issuer = new DPoPIssuer("client-123");
		ECKey EC_JWK = new ECKeyGenerator(Curve.P_256).generate();
		DPoPProofFactory dPoPProofFactory = new DefaultDPoPProofFactory(
			EC_JWK,
			JWSAlgorithm.ES256
		);
		
		DPoPCommonVerifier verifier = new DPoPCommonVerifier(
			Collections.singleton(JWSAlgorithm.ES256),
			2,
			null
		);
		
		SignedJWT proof = dPoPProofFactory.createDPoPJWT(htm, htu);
		
		// Replay not detected
		verifier.verify(htm, htu, issuer, proof, null, null, null);
		verifier.verify(htm, htu, issuer, proof, null, null, null);
	}
	
	
	public void testIllegalHTTPMethod() throws Exception {
		
		String htm = "POST";
		URI htu = URI.create("https://c2id.com/token");
		
		DPoPIssuer issuer = new DPoPIssuer("client-123");
		DPoPProofFactory dPoPProofFactory = new DefaultDPoPProofFactory(
			EC_JWK,
			JWSAlgorithm.ES256
		);
		
		DPoPCommonVerifier verifier = new DPoPCommonVerifier(
			Collections.singleton(JWSAlgorithm.ES256),
			2,
			null
		);
		
		SignedJWT proof = dPoPProofFactory.createDPoPJWT(htm, htu);
		
		for (String method: Arrays.asList("", " ", null)) {
			
			IllegalArgumentException exception = null;
			try {
				verifier.verify(method, htu, issuer, proof, null, null, null);
				fail();
			} catch (IllegalArgumentException e) {
				exception = e;
			}
			assertEquals("The HTTP request method must not be null or blank", exception.getMessage());
		}
	}
	
	
	public void testNUllURI() throws Exception {
		
		String htm = "POST";
		URI htu = URI.create("https://c2id.com/token");
		
		DPoPIssuer issuer = new DPoPIssuer("client-123");
		DPoPProofFactory dPoPProofFactory = new DefaultDPoPProofFactory(
			EC_JWK,
			JWSAlgorithm.ES256
		);
		
		DPoPCommonVerifier verifier = new DPoPCommonVerifier(
			Collections.singleton(JWSAlgorithm.ES256),
			2,
			null
		);
		
		SignedJWT proof = dPoPProofFactory.createDPoPJWT(htm, htu);
		
		IllegalArgumentException exception = null;
		try {
			verifier.verify(htm, null, issuer, proof, null, null, null);
			fail();
		} catch (IllegalArgumentException e) {
			exception = e;
		}
		assertEquals("The HTTP URI must not be null", exception.getMessage());
	}
	
	
	public void testURI_queryAndFragmentIgnored() throws Exception {
		
		String htm = "POST";
		URI htu = URI.create("https://c2id.com/token");
		
		DPoPIssuer issuer = new DPoPIssuer("client-123");
		DPoPProofFactory dPoPProofFactory = new DefaultDPoPProofFactory(
			EC_JWK,
			JWSAlgorithm.ES256
		);
		
		DPoPCommonVerifier verifier = new DPoPCommonVerifier(
			Collections.singleton(JWSAlgorithm.ES256),
			2,
			null
		);
		
		SignedJWT proof = dPoPProofFactory.createDPoPJWT(htm, htu);
		
		verifier.verify(htm, new URI(htu + "?key=value#fragment"), issuer, proof, null, null, null);
	}
}
