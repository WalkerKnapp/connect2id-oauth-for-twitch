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
import java.util.*;

import com.nimbusds.oauth2.sdk.id.Issuer;
import junit.framework.TestCase;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.id.Audience;


/**
 * Tests the JWT claims set verifier for client authentication assertions.
 */
public class JWTAuthenticationClaimsSetVerifierTest extends TestCase {


	private static final Issuer ISSUER = new Issuer("https://c2id.com");

	private static final URI ENDPOINT = URI.create(ISSUER + "/token");


	// For an Authorisation Server (AS) / OpenID provider (OP)
	private static JWTAuthenticationClaimsSetVerifier create() {

		Set<Audience> allowedAud = new LinkedHashSet<>();
		allowedAud.add(new Audience(ISSUER));
		return new JWTAuthenticationClaimsSetVerifier(allowedAud, JWTAudienceCheck.STRICT, -1L);
	}


	// Legacy for an OpenID provider (OP)
	private static JWTAuthenticationClaimsSetVerifier createLegacy() {

		Set<Audience> allowedAudValues = new LinkedHashSet<>();
		allowedAudValues.add(new Audience(ENDPOINT));
		allowedAudValues.add(new Audience(ISSUER));
		return new JWTAuthenticationClaimsSetVerifier(allowedAudValues);
	}


	private static void ensureRejected(final JWTClaimsSet claimsSet,
					   final String expectedMessage) {

		try {
			create().verify(claimsSet, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals(expectedMessage, e.getMessage());
		}
	}


	public void testDefaultExpMaxAhead() {

		assertEquals(-1, create().getExpirationTimeMaxAhead());
	}


	public void testStrictCheckRequiresSingleValuedAud() {

		Set<Audience> allowedAudValues = new LinkedHashSet<>();
		allowedAudValues.add(new Audience(ENDPOINT));
		allowedAudValues.add(new Audience(ISSUER));

		try {
			new JWTAuthenticationClaimsSetVerifier(allowedAudValues, JWTAudienceCheck.STRICT, -1L);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("When strict the JWT audience must be single-valued", e.getMessage());
		}
	}


	public void testEmptyAud() {

		try {
			new JWTAuthenticationClaimsSetVerifier(new HashSet<Audience>());
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The expected audience set must not be null or empty", e.getMessage());
		}
	}


	public void testAud() {

		JWTAuthenticationClaimsSetVerifier verifier = create();

		assertEquals(Collections.singleton(new Audience(ISSUER)), verifier.getExpectedAudience());
		assertEquals(JWTAudienceCheck.STRICT, verifier.getAudienceCheck());
	}


	public void testHappy()
		throws BadJWTException {

		Date now = new Date();
		Date in5min = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(in5min)
			.audience(ISSUER.getValue())
			.issuer("123")
			.subject("123")
			.build();

		create().verify(claimsSet, null);
	}


	public void testHappy_legacy_multipleAudienceValues()
		throws BadJWTException {

		assertEquals(JWTAudienceCheck.LEGACY, createLegacy().getAudienceCheck());

		Date now = new Date();
		Date in5min = new Date(now.getTime() + 5*60*1000);

		// Two values, both permitted
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(in5min)
			.audience(Arrays.asList(ISSUER.getValue(), ENDPOINT.toString()))
			.issuer("123")
			.subject("123")
			.build();
		createLegacy().verify(claimsSet, null);

		// One value
		claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(in5min)
			.audience(Collections.singletonList(ISSUER.getValue()))
			.issuer("123")
			.subject("123")
			.build();
		createLegacy().verify(claimsSet, null);

		// Alt value
		claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(in5min)
			.audience(Collections.singletonList(ENDPOINT.toString()))
			.issuer("123")
			.subject("123")
			.build();
		createLegacy().verify(claimsSet, null);

		// Two values, one non-recognized
		claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(in5min)
			.audience(Arrays.asList(ISSUER.getValue(), "xxx"))
			.issuer("123")
			.subject("123")
			.build();
		createLegacy().verify(claimsSet, null);
	}


	public void testRejectMultipleAudienceValues() {

		Date now = new Date();
		Date in5min = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(in5min)
			.audience(Arrays.asList(ISSUER.getValue(), ENDPOINT.toString()))
			.issuer("123")
			.subject("123")
			.build();

		try {
			create().verify(claimsSet, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT multi-valued audience rejected: [https://c2id.com, https://c2id.com/token]", e.getMessage());
		}

		claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(in5min)
			.audience(Arrays.asList(ISSUER.getValue(), "xxx"))
			.issuer("123")
			.subject("123")
			.build();

		try {
			create().verify(claimsSet, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT multi-valued audience rejected: [https://c2id.com, xxx]", e.getMessage());
		}
	}


	public void testExpirationTooFarAhead() {

		Set<Audience> expectedAud = new LinkedHashSet<>();
		expectedAud.add(new Audience(ISSUER));

		JWTAuthenticationClaimsSetVerifier verifier = new JWTAuthenticationClaimsSetVerifier(expectedAud, 60L);

		Date now = new Date();
		Date in5min = new Date(now.getTime() + 61_000L);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(in5min)
			.audience(ISSUER.getValue())
			.issuer("123")
			.subject("123")
			.build();

		try {
			verifier.verify(claimsSet, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT expiration too far ahead", e.getMessage());
		}
	}


	public void testExpired() {

		Date now = new Date();
		Date before5min = new Date(now.getTime() - 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(before5min)
			.audience(ISSUER.getValue())
			.issuer("123")
			.subject("123")
			.build();

		ensureRejected(claimsSet, "Expired JWT");
	}


	public void testMissingExpiration() {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.audience(ISSUER.getValue())
			.issuer("123")
			.subject("123")
			.build();

		ensureRejected(claimsSet, "JWT missing required claims: [exp]");
	}


	public void testMissingAud() {

		Date now = new Date();
		Date in5min = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(in5min)
			.issuer("123")
			.subject("123")
			.build();

		ensureRejected(claimsSet, "JWT missing required audience");
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
			create().verify(claimsSet, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT audience rejected: [c2id.com]", e.getMessage());
		}

		try {
			createLegacy().verify(claimsSet, null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT audience rejected: [c2id.com]", e.getMessage());
		}
	}


	public void testMissingIssuer() {

		Date now = new Date();
		Date in5min = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(in5min)
			.audience(ISSUER.getValue())
			.subject("123")
			.build();

		ensureRejected(claimsSet, "JWT missing required claims: [iss]");
	}


	public void testMissingSubject() {

		Date now = new Date();
		Date in5min = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(in5min)
			.audience(ISSUER.getValue())
			.issuer("123")
			.build();

		ensureRejected(claimsSet, "JWT missing required claims: [sub]");
	}


	public void testIssuerSubjectMismatch() {

		Date now = new Date();
		Date in5min = new Date(now.getTime() + 5*60*1000);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.expirationTime(in5min)
			.audience(ISSUER.getValue())
			.issuer("123")
			.subject("456")
			.build();

		ensureRejected(claimsSet, "Issuer and subject JWT claims don't match");
	}
}
