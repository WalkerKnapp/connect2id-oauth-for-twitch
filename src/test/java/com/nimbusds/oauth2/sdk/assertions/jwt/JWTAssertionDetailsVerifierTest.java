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


import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import junit.framework.TestCase;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;


public class JWTAssertionDetailsVerifierTest extends TestCase {


	public void testSuccess()
		throws Exception {

		Issuer issuer = new Issuer("https://c2id.com");
		URI tokenEndpoint = URI.create("https://c2id.com/token");

		JWTAssertionDetailsVerifier verifier = new JWTAssertionDetailsVerifier(
			new HashSet<>(Arrays.asList(
				new Audience(issuer),
				new Audience(tokenEndpoint)
			))
		);

		assertTrue(verifier.getExpectedAudience().contains(new Audience(issuer)));
		assertTrue(verifier.getExpectedAudience().contains(new Audience(tokenEndpoint)));
		assertEquals(2, verifier.getExpectedAudience().size());

		// good claims - aud = OP / AS issuer, token endpoint
		for (String aud: Arrays.asList(issuer.getValue(), tokenEndpoint.toString())) {
			verifier.verify(
				new JWTClaimsSet.Builder()
					.issuer("123")
					.subject("alice")
					.audience(aud)
					.expirationTime(new Date(new Date().getTime() + 60 * 1000L))
					.build(),
				null);
		}

		// with "jti" claim
		for (String aud: Arrays.asList(issuer.getValue(), tokenEndpoint.toString())) {
			verifier.verify(
				new JWTClaimsSet.Builder()
					.issuer("123")
					.subject("alice")
					.audience(aud)
					.expirationTime(new Date(new Date().getTime() + 60 * 1000L))
					.jwtID(new JWTID().getValue())
					.build(),
				null);
		}

		// with "iat" claim
		for (String aud: Arrays.asList(issuer.getValue(), tokenEndpoint.toString())) {
			verifier.verify(
				new JWTClaimsSet.Builder()
					.issuer("123")
					.subject("alice")
					.audience(aud)
					.expirationTime(new Date(new Date().getTime() + 60 * 1000L))
					.issueTime(new Date())
					.build(),
				null);
		}

		// with "iat" + "jti" claims
		for (String aud: Arrays.asList(issuer.getValue(), tokenEndpoint.toString())) {
			verifier.verify(
				new JWTClaimsSet.Builder()
					.issuer("123")
					.subject("alice")
					.audience(aud)
					.expirationTime(new Date(new Date().getTime() + 60 * 1000L))
					.issueTime(new Date())
					.jwtID(new JWTID().getValue())
					.build(),
				null);
		}
	}


	public void testSuccess_oneGoodAudienceIsSufficient()
		throws Exception {

		Issuer issuer = new Issuer("https://c2id.com");
		URI tokenEndpoint = URI.create("https://c2id.com/token");

		JWTAssertionDetailsVerifier verifier = new JWTAssertionDetailsVerifier(
			new HashSet<>(Arrays.asList(
				new Audience(issuer),
				new Audience(tokenEndpoint)
			))
		);

		assertTrue(verifier.getExpectedAudience().contains(new Audience(issuer)));
		assertTrue(verifier.getExpectedAudience().contains(new Audience(tokenEndpoint)));
		assertEquals(2, verifier.getExpectedAudience().size());

		verifier.verify(
			new JWTClaimsSet.Builder()
				.issuer("123")
				.subject("alice")
				.audience(Arrays.asList(issuer.getValue(), "https://op.c2id.com"))
				.expirationTime(new Date(new Date().getTime() + 60 * 1000L))
				.build(),
			null);

		verifier.verify(
			new JWTClaimsSet.Builder()
				.issuer("123")
				.subject("alice")
				.audience(Arrays.asList(issuer.getValue(), tokenEndpoint.toString(), "https://op.c2id.com"))
				.expirationTime(new Date(new Date().getTime() + 60 * 1000L))
				.build(),
			null);
	}


	public void testConstructor_twoAudiences() {

		Issuer issuer = new Issuer("https://c2id.com");
		URI tokenEndpoint = URI.create("https://c2id.com/token");

		JWTAssertionDetailsVerifier verifier = new JWTAssertionDetailsVerifier(
			new HashSet<>(Arrays.asList(
				new Audience(issuer),
				new Audience(tokenEndpoint)
			))
		);

		assertTrue(verifier.getExpectedAudience().contains(new Audience(issuer)));
		assertTrue(verifier.getExpectedAudience().contains(new Audience(tokenEndpoint)));
		assertEquals(2, verifier.getExpectedAudience().size());
	}


	public void testConstructor_oneAudiences() {

		Issuer issuer = new Issuer("https://c2id.com");

		JWTAssertionDetailsVerifier verifier = new JWTAssertionDetailsVerifier(
			new HashSet<>(Collections.singletonList(new Audience(issuer)))
		);

		assertTrue(verifier.getExpectedAudience().contains(new Audience(issuer)));
		assertEquals(1, verifier.getExpectedAudience().size());
	}


	public void testConstructor_emptyAudiences() {

		try {
			new JWTAssertionDetailsVerifier(Collections.<Audience>emptySet());
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The expected audience set must not be null or empty", e.getMessage());
		}
	}


	public void testConstructor_nullAudiences() {

		try {
			new JWTAssertionDetailsVerifier(null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The expected audience set must not be null or empty", e.getMessage());
		}
	}


	public void testEmptyClaims() {

		Issuer issuer = new Issuer("https://c2id.com");
		URI tokenEndpoint = URI.create("https://c2id.com/token");

		JWTAssertionDetailsVerifier verifier = new JWTAssertionDetailsVerifier(
			new HashSet<>(Arrays.asList(
				new Audience(issuer),
				new Audience(tokenEndpoint)
			))
		);

		// empty claims
		try {
			verifier.verify(new JWTClaimsSet.Builder().build(), null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required audience", e.getMessage());
		}
	}


	public void testMissingClaims() {

		Issuer issuer = new Issuer("https://c2id.com");
		URI tokenEndpoint = URI.create("https://c2id.com/token");

		JWTAssertionDetailsVerifier verifier = new JWTAssertionDetailsVerifier(
			new HashSet<>(Arrays.asList(
				new Audience(issuer),
				new Audience(tokenEndpoint)
			))
		);

		assertTrue(verifier.getExpectedAudience().contains(new Audience(issuer)));
		assertTrue(verifier.getExpectedAudience().contains(new Audience(tokenEndpoint)));
		assertEquals(2, verifier.getExpectedAudience().size());

		try {
			verifier.verify(
				new JWTClaimsSet.Builder()
					.expirationTime(new Date(new Date().getTime() + 60*1000L))
					.subject("123")
					.issuer("123")
					.build(),
				null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required audience", e.getMessage());
		}

		try {
			verifier.verify(
				new JWTClaimsSet.Builder()
					.expirationTime(new Date(new Date().getTime() + 60*1000L))
					.audience(issuer.getValue())
					.subject("123")
					.build(),
				null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [iss]", e.getMessage());
		}

		try {
			verifier.verify(
				new JWTClaimsSet.Builder()
					.expirationTime(new Date(new Date().getTime() + 60*1000L))
					.audience(issuer.getValue())
					.issuer("123")
					.build(),
				null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [sub]", e.getMessage());
		}
	}


	public void testInvalidAudience() {

		Issuer issuer = new Issuer("https://c2id.com");
		URI tokenEndpoint = URI.create("https://c2id.com/token");

		JWTAssertionDetailsVerifier verifier = new JWTAssertionDetailsVerifier(
			new HashSet<>(Arrays.asList(
				new Audience(issuer),
				new Audience(tokenEndpoint)
			))
		);

		assertTrue(verifier.getExpectedAudience().contains(new Audience(issuer)));
		assertTrue(verifier.getExpectedAudience().contains(new Audience(tokenEndpoint)));
		assertEquals(2, verifier.getExpectedAudience().size());

		try {
			verifier.verify(
				new JWTClaimsSet.Builder()
					.expirationTime(new Date(new Date().getTime() + 60*1000L))
					.audience("xxx")
					.issuer("123")
					.subject("123")
					.build(),
				null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT audience rejected: [xxx]", e.getMessage());
		}
	}


	public void testExpired() {

		Issuer issuer = new Issuer("https://c2id.com");
		URI tokenEndpoint = URI.create("https://c2id.com/token");

		JWTAssertionDetailsVerifier verifier = new JWTAssertionDetailsVerifier(
			new HashSet<>(Arrays.asList(
				new Audience(issuer),
				new Audience(tokenEndpoint)
			))
		);

		assertTrue(verifier.getExpectedAudience().contains(new Audience(issuer)));
		assertTrue(verifier.getExpectedAudience().contains(new Audience(tokenEndpoint)));
		assertEquals(2, verifier.getExpectedAudience().size());

		try {
			verifier.verify(
				new JWTClaimsSet.Builder()
					.expirationTime(new Date(new Date().getTime() - 60*1000L))
					.audience(issuer.getValue())
					.issuer("123")
					.subject("123")
					.build(),
				null);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Expired JWT", e.getMessage());
		}
	}
}
