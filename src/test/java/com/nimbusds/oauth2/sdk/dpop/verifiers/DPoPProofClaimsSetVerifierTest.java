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
import java.text.ParseException;
import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;


public class DPoPProofClaimsSetVerifierTest extends TestCase {
	
	
	private static final DPoPIssuer ISSUER = new DPoPIssuer(new ClientID("123"));
	
	
	private static final int MAX_CLOCK_SKEW_SECONDS = 5;

	
	public void testPass() throws BadJWTException {
		
		String method = "POST";
		URI endpoint = URI.create("https://c2id.com/token");
		JWTID jti = new JWTID(12);
		Date now = new Date();
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("htm", "POST")
			.claim("htu", endpoint.toString())
			.issueTime(now)
			.jwtID(jti.getValue())
			.build();
		
		new DPoPProofClaimsSetVerifier(endpoint, method, null, MAX_CLOCK_SKEW_SECONDS, false, null)
			.verify(claimsSet, new DPoPProofContext(ISSUER));
	}

	
	public void testPassWithNonce() throws BadJWTException {
		
		String method = "POST";
		URI endpoint = URI.create("https://c2id.com/token");
		Nonce nonce = new Nonce();
		JWTID jti = new JWTID(12);
		Date now = new Date();
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("htm", "POST")
			.claim("htu", endpoint.toString())
			.claim("nonce", nonce.getValue())
			.issueTime(now)
			.jwtID(jti.getValue())
			.build();
		
		new DPoPProofClaimsSetVerifier(endpoint, method, nonce, MAX_CLOCK_SKEW_SECONDS, false, null)
			.verify(claimsSet, new DPoPProofContext(ISSUER));
	}

	
	public void test_invalidMethod() {
		
		String method = "POST";
		URI endpoint = URI.create("https://c2id.com/token");
		JWTID jti = new JWTID(12);
		Date now = new Date();
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("htm", "PUT")
			.claim("htu", endpoint.toString())
			.issueTime(now)
			.jwtID(jti.getValue())
			.build();
		
		try {
			new DPoPProofClaimsSetVerifier(endpoint, method, null, MAX_CLOCK_SKEW_SECONDS, false, null)
				.verify(claimsSet, new DPoPProofContext(ISSUER));
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT htm claim has value PUT, must be POST", e.getMessage());
		}
	}

	
	public void test_invalidEndpoint() {
		
		String method = "POST";
		URI endpoint = URI.create("https://c2id.com/token");
		JWTID jti = new JWTID(12);
		Date now = new Date();
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("htm", "POST")
			.claim("htu", URI.create("https://example.com").toString())
			.issueTime(now)
			.jwtID(jti.getValue())
			.build();
		
		try {
			new DPoPProofClaimsSetVerifier(endpoint, method, null, MAX_CLOCK_SKEW_SECONDS, false, null)
				.verify(claimsSet, new DPoPProofContext(ISSUER));
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT htu claim has value https://example.com, must be https://c2id.com/token", e.getMessage());
		}
	}

	
	public void test_invalidNonce() {
		
		String method = "POST";
		URI endpoint = URI.create("https://c2id.com/token");
		Nonce nonce = new Nonce();
		JWTID jti = new JWTID(12);
		Date now = new Date();
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("htm", "POST")
			.claim("htu", endpoint.toString())
			.claim("nonce", nonce.getValue())
			.issueTime(now)
			.jwtID(jti.getValue())
			.build();
		
		Nonce expectedNonce = new Nonce();
		
		try {
			new DPoPProofClaimsSetVerifier(endpoint, method, expectedNonce, MAX_CLOCK_SKEW_SECONDS, false, null)
				.verify(claimsSet, new DPoPProofContext(ISSUER));
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT nonce claim has value " + nonce + ", must be " + expectedNonce, e.getMessage());
		}
	}

	
	public void test_nonceNotExpected() {
		
		String method = "POST";
		URI endpoint = URI.create("https://c2id.com/token");
		Nonce nonce = new Nonce();
		JWTID jti = new JWTID(12);
		Date now = new Date();
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("htm", "POST")
			.claim("htu", endpoint.toString())
			.claim("nonce", nonce.getValue())
			.issueTime(now)
			.jwtID(jti.getValue())
			.build();
		
		try {
			new DPoPProofClaimsSetVerifier(endpoint, method, null, MAX_CLOCK_SKEW_SECONDS, false, null)
				.verify(claimsSet, new DPoPProofContext(ISSUER));
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT has prohibited claims: [nonce]", e.getMessage());
		}
	}

	
	public void test_iatBehindMaxClockSkew() {
		
		String method = "POST";
		URI endpoint = URI.create("https://c2id.com/token");
		JWTID jti = new JWTID(12);
		Date now = new Date();
		Date twoMinAgo = new Date(now.getTime() - (MAX_CLOCK_SKEW_SECONDS + 1) * 1000);
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("htm", "POST")
			.claim("htu", endpoint.toString())
			.issueTime(twoMinAgo)
			.jwtID(jti.getValue())
			.build();
		
		try {
			new DPoPProofClaimsSetVerifier(endpoint, method, null, MAX_CLOCK_SKEW_SECONDS, false, null)
				.verify(claimsSet, new DPoPProofContext(ISSUER));
			fail();
		} catch (BadJWTException e) {
			assertEquals("The JWT iat claim is behind the current time by more than " + MAX_CLOCK_SKEW_SECONDS + " seconds", e.getMessage());
		}
	}

	
	public void test_iatAheadMaxClockSkew() {
		
		String method = "POST";
		URI endpoint = URI.create("https://c2id.com/token");
		JWTID jti = new JWTID(12);
		Date now = new Date();
		Date tenSecondsAhead = new Date(now.getTime() + (MAX_CLOCK_SKEW_SECONDS + 1) * 1000);
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("htm", "POST")
			.claim("htu", endpoint.toString())
			.issueTime(tenSecondsAhead)
			.jwtID(jti.getValue())
			.build();
		
		try {
			new DPoPProofClaimsSetVerifier(endpoint, method, null, MAX_CLOCK_SKEW_SECONDS, false, null)
				.verify(claimsSet, new DPoPProofContext(ISSUER));
			fail();
		} catch (BadJWTException e) {
			assertEquals("The JWT iat claim is ahead of the current time by more than " + MAX_CLOCK_SKEW_SECONDS + " seconds", e.getMessage());
		}
	}
	
	
	public void test_htmMissing() {
		
		String method = "POST";
		URI endpoint = URI.create("https://c2id.com/token");
		JWTID jti = new JWTID(12);
		Date now = new Date();
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("htu", endpoint.toString())
			.issueTime(now)
			.jwtID(jti.getValue())
			.build();
		
		try {
			new DPoPProofClaimsSetVerifier(endpoint, method, null, MAX_CLOCK_SKEW_SECONDS, false, null)
				.verify(claimsSet, new DPoPProofContext(ISSUER));
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [htm]", e.getMessage());
		}
	}
	
	
	public void test_htuMissing() {
		
		String method = "POST";
		URI endpoint = URI.create("https://c2id.com/token");
		JWTID jti = new JWTID(12);
		Date now = new Date();
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("htm", "PUT")
			.issueTime(now)
			.jwtID(jti.getValue())
			.build();
		
		try {
			new DPoPProofClaimsSetVerifier(endpoint, method, null, MAX_CLOCK_SKEW_SECONDS, false, null)
				.verify(claimsSet, new DPoPProofContext(ISSUER));
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [htu]", e.getMessage());
		}
	}
	
	
	public void test_nonceMissing() {
		
		String method = "POST";
		URI endpoint = URI.create("https://c2id.com/token");
		JWTID jti = new JWTID(12);
		Date now = new Date();
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("htm", "PUT")
			.claim("htu", endpoint.toString())
			.issueTime(now)
			.jwtID(jti.getValue())
			.build();
		
		try {
			new DPoPProofClaimsSetVerifier(endpoint, method, new Nonce(), MAX_CLOCK_SKEW_SECONDS, false, null)
				.verify(claimsSet, new DPoPProofContext(ISSUER));
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [nonce]", e.getMessage());
		}
	}
	
	
	public void test_iatMissing() {
		
		String method = "POST";
		URI endpoint = URI.create("https://c2id.com/token");
		JWTID jti = new JWTID(12);
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("htm", "PUT")
			.claim("htu", endpoint.toString())
			.jwtID(jti.getValue())
			.build();
		
		try {
			new DPoPProofClaimsSetVerifier(endpoint, method, null, MAX_CLOCK_SKEW_SECONDS, false, null)
				.verify(claimsSet, new DPoPProofContext(ISSUER));
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [iat]", e.getMessage());
		}
	}
	
	
	public void test_jtiMissing() {
		
		String method = "POST";
		URI endpoint = URI.create("https://c2id.com/token");
		Date now = new Date();
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("htm", "PUT")
			.claim("htu", endpoint.toString())
			.issueTime(now)
			.build();
		
		try {
			new DPoPProofClaimsSetVerifier(endpoint, method, null, MAX_CLOCK_SKEW_SECONDS, false, null)
				.verify(claimsSet, new DPoPProofContext(ISSUER));
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [jti]", e.getMessage());
		}
	}
	
	
	public void test_athMissing() {
		
		String method = "POST";
		URI endpoint = URI.create("https://c2id.com/token");
		JWTID jti = new JWTID(12);
		Date now = new Date();
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("htm", "PUT")
			.claim("htu", endpoint.toString())
			.issueTime(now)
			.jwtID(jti.getValue())
			.build();
		
		try {
			new DPoPProofClaimsSetVerifier(endpoint, method, null, MAX_CLOCK_SKEW_SECONDS, true, null)
				.verify(claimsSet, new DPoPProofContext(ISSUER));
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [ath]", e.getMessage());
		}
	}
	
	
	public void test_ath() throws JOSEException, ParseException, BadJWTException {
		
		String method = "POST";
		URI endpoint = URI.create("https://c2id.com/token");
		JWTID jti = new JWTID(12);
		Date now = new Date();
		
		AccessToken token = new DPoPAccessToken("iat5luciwooSa8Ogh5eweicahG8soo8a");
		
		JWTClaimsSet claimsSet = new DefaultDPoPProofFactory(
				new ECKeyGenerator(Curve.P_256).generate(),
				JWSAlgorithm.ES256
			)
			.createDPoPJWT(jti, method, endpoint, now, token)
			.getJWTClaimsSet();
		
		DPoPProofClaimsSetVerifier verifier = new DPoPProofClaimsSetVerifier(endpoint, method, null, MAX_CLOCK_SKEW_SECONDS, true, null);
		
		// Pass
		DPoPProofContext context = new DPoPProofContext(ISSUER);
		
		verifier.verify(claimsSet, context);
		
		assertEquals(new Base64URL(claimsSet.getStringClaim("ath")), context.getAccessTokenHash());
	}
	
	
	public void test_ath_withNonce() throws JOSEException, ParseException, BadJWTException {
		
		String method = "POST";
		URI endpoint = URI.create("https://c2id.com/token");
		Nonce nonce = new Nonce();
		JWTID jti = new JWTID(12);
		Date now = new Date();
		
		AccessToken token = new DPoPAccessToken("iat5luciwooSa8Ogh5eweicahG8soo8a");
		
		JWTClaimsSet claimsSet = new DefaultDPoPProofFactory(
				new ECKeyGenerator(Curve.P_256).generate(),
				JWSAlgorithm.ES256
			)
			.createDPoPJWT(jti, method, endpoint, now, token, nonce)
			.getJWTClaimsSet();
		
		DPoPProofClaimsSetVerifier verifier = new DPoPProofClaimsSetVerifier(endpoint, method, nonce, MAX_CLOCK_SKEW_SECONDS, true, null);
		
		// Pass
		DPoPProofContext context = new DPoPProofContext(ISSUER);
		
		verifier.verify(claimsSet, context);
		
		assertEquals(new Base64URL(claimsSet.getStringClaim("ath")), context.getAccessTokenHash());
	}
}
