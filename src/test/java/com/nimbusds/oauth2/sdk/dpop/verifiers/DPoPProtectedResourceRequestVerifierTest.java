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

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;


public class DPoPProtectedResourceRequestVerifierTest extends TestCase {
	
	
	public void testCases() throws Exception {
		
		String htm = "GET";
		URI htu = URI.create("https://c2id.com/userinfo");
		
		DPoPAccessToken accessToken = new DPoPAccessToken("iat5luciwooSa8Ogh5eweicahG8soo8a");
		
		DPoPIssuer issuer = new DPoPIssuer("client-123");
		ECKey ecJWK = new ECKeyGenerator(Curve.P_256).generate();
		Base64URL jkt = ecJWK.computeThumbprint();
		JWKThumbprintConfirmation cnf = new JWKThumbprintConfirmation(jkt);
		DPoPProofFactory dPoPProofFactory = new DefaultDPoPProofFactory(
			ecJWK,
			JWSAlgorithm.ES256
		);
		
		DPoPProtectedResourceRequestVerifier verifier = new DPoPProtectedResourceRequestVerifier(
			Collections.singleton(JWSAlgorithm.ES256),
			2,
			new DefaultDPoPSingleUseChecker(
				10,
				10
			)
		);
		
		// Pass
		SignedJWT proof = dPoPProofFactory.createDPoPJWT(htm, htu, accessToken);
		assertNotNull(proof.getJWTClaimsSet().getStringClaim("ath"));
		
		verifier.verify(htm, htu, issuer, proof, accessToken, cnf);
		
		// Replay detection
		try {
			verifier.verify(htm, htu, issuer, proof, accessToken, cnf);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: The jti was used before: " + proof.getJWTClaimsSet().getJWTID(), e.getMessage());
		}
		
		// HTTP method doesn't match
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, accessToken);
		try {
			verifier.verify("POST", htu, issuer, proof, accessToken, cnf);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: JWT htm claim has value GET, must be POST", e.getMessage());
		}
		
		// HTTP URI doesn't match
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, accessToken);
		try {
			verifier.verify(htm, new URI("https://example.com/resource"), issuer, proof, accessToken, cnf);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: JWT htu claim has value https://c2id.com/userinfo, must be https://example.com/resource", e.getMessage());
		}
		
		// Missing DPoP proof
		try {
			verifier.verify(htm, htu, issuer, null, accessToken, cnf);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Missing required DPoP proof", e.getMessage());
		}
		
		// Missing access token
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, accessToken);
		try {
			verifier.verify(htm, htu, issuer, proof, null, cnf);
			fail();
		} catch (AccessTokenValidationException e) {
			assertEquals("Missing access token", e.getMessage());
		}
		
		// Missing cnf
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, accessToken);
		try {
			verifier.verify(htm, htu, issuer, proof, accessToken, null);
			fail();
		} catch (AccessTokenValidationException e) {
			assertEquals("Missing JWK SHA-256 thumbprint confirmation", e.getMessage());
		}
		
		// Missing ath
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, null);
		try {
			verifier.verify(htm, htu, issuer, proof, accessToken, cnf);
			fail();
		} catch (InvalidDPoPProofException e) {
			assertEquals("Invalid DPoP proof: JWT missing required claims: [ath]", e.getMessage());
		}
		
		// Invalid ath - access token binding
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, new DPoPAccessToken("other-value"));
		
		try {
			verifier.verify(htm, htu, issuer, proof, accessToken, cnf);
			fail();
		} catch (AccessTokenValidationException e) {
			assertEquals("The access token hash doesn't match the JWT ath claim", e.getMessage());
		}
		
		// Invalid cnf - access token binding
		proof = dPoPProofFactory.createDPoPJWT(htm, htu, accessToken);
		
		JWKThumbprintConfirmation invalidCNF = new JWKThumbprintConfirmation(new ECKeyGenerator(Curve.P_256).generate().computeThumbprint());
		
		try {
			verifier.verify(htm, htu, issuer, proof, accessToken, invalidCNF);
			fail();
		} catch (AccessTokenValidationException e) {
			assertEquals("The DPoP proof JWK doesn't match the JWK SHA-256 thumbprint confirmation", e.getMessage());
		}
	}
}
