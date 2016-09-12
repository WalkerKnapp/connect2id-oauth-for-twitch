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

package com.nimbusds.oauth2.sdk.auth.verifier;


import java.net.URI;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;

import com.nimbusds.oauth2.sdk.id.Audience;


/**
 * Tests the JWT claims set verifier for client authentication assertions.
 */
public class JWTAuthenticationClaimsSetVerifierTest extends TestCase {


	// Create for simple Authorisation Server (AS)
	private static JWTAuthenticationClaimsSetVerifier createForAS() {

		URI tokenEndpoint = URI.create("https://c2id.com/token");

		Set<Audience> expectedAud = new LinkedHashSet<>();
		expectedAud.add(new Audience(tokenEndpoint.toString()));

		return new JWTAuthenticationClaimsSetVerifier(expectedAud);
	}


	// Create for OpenID provider
	private static JWTAuthenticationClaimsSetVerifier createForOP() {

		URI tokenEndpoint = URI.create("https://c2id.com/token");
		URI opIssuer = URI.create("https://c2id.com");

		Set<Audience> expectedAud = new LinkedHashSet<>();
		expectedAud.add(new Audience(tokenEndpoint.toString()));
		expectedAud.add(new Audience(opIssuer.toString()));

		return new JWTAuthenticationClaimsSetVerifier(expectedAud);
	}


	private static void ensureRejected(final JWTClaimsSet claimsSet,
					   final String expectedMessage) {

		try {
			createForAS().verify(claimsSet);
			fail();
		} catch (BadJWTException e) {
			assertEquals(expectedMessage, e.getMessage());
		}

		try {
			createForOP().verify(claimsSet);
			fail();
		} catch (BadJWTException e) {
			assertEquals(expectedMessage, e.getMessage());
		}
	}


	public void testAudForAS() {

		JWTAuthenticationClaimsSetVerifier verifier = createForAS();

		assertTrue(verifier.getExpectedAudience().contains(new Audience("https://c2id.com/token")));
		assertEquals(1, verifier.getExpectedAudience().size());
	}


	public void testAudForOP() {

		JWTAuthenticationClaimsSetVerifier verifier = createForAS();

		assertTrue(verifier.getExpectedAudience().contains(new Audience("https://c2id.com/token")));
		assertEquals(1, verifier.getExpectedAudience().size());
	}


	public void testHappy()
		throws BadJWTException {

		Date now = new Date();
		Date in5min = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(in5min)
			.audience("https://c2id.com/token")
			.issuer("123")
			.subject("123")
			.build();

		createForAS().verify(claimsSet);
		createForOP().verify(claimsSet);
	}


	public void testExpired() {

		Date now = new Date();
		Date before5min = new Date(now.getTime() - 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(before5min)
			.audience("https://c2id.com")
			.issuer("123")
			.subject("123")
			.build();

		ensureRejected(claimsSet, "Expired JWT");
	}


	public void testMissingExpiration() {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.audience("https://c2id.com")
			.issuer("123")
			.subject("123")
			.build();

		ensureRejected(claimsSet, "Missing JWT expiration claim");
	}


	public void testMissingAud() {

		Date now = new Date();
		Date in5min = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(in5min)
			.issuer("123")
			.subject("123")
			.build();

		ensureRejected(claimsSet, "Missing JWT audience claim");
	}


	public void testUnexpectedAud() {

		Date now = new Date();
		Date in5min = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(in5min)
			.audience("c2id.com")
			.issuer("123")
			.subject("123")
			.build();

		try {
			createForAS().verify(claimsSet);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Invalid JWT audience claim, expected [https://c2id.com/token]", e.getMessage());
		}

		try {
			createForOP().verify(claimsSet);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Invalid JWT audience claim, expected [https://c2id.com/token, https://c2id.com]", e.getMessage());
		}
	}


	public void testMissingIssuer()
		throws BadJWTException {

		Date now = new Date();
		Date in5min = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(in5min)
			.audience("https://c2id.com/token")
			.subject("123")
			.build();

		ensureRejected(claimsSet, "Missing JWT issuer claim");
	}


	public void testMissingSubject()
		throws BadJWTException {

		Date now = new Date();
		Date in5min = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(in5min)
			.audience("https://c2id.com/token")
			.issuer("123")
			.build();

		ensureRejected(claimsSet, "Missing JWT subject claim");
	}


	public void testIssuerSubjectMismatch() {

		Date now = new Date();
		Date in5min = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(in5min)
			.audience("https://c2id.com/token")
			.issuer("123")
			.subject("456")
			.build();

		ensureRejected(claimsSet, "Issuer and subject JWT claims don't match");
	}
}
