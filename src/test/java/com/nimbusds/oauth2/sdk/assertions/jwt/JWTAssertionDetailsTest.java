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
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import java.util.*;


/**
 * Tests the JWT bearer assertion details (claims set).
 */
public class JWTAssertionDetailsTest extends TestCase {


	public void testReservedClaimsNames() {

		// http://tools.ietf.org/html/rfc7523#section-3
		assertTrue(JWTAssertionDetails.getReservedClaimsNames().contains("iss"));
		assertTrue(JWTAssertionDetails.getReservedClaimsNames().contains("sub"));
		assertTrue(JWTAssertionDetails.getReservedClaimsNames().contains("aud"));
		assertTrue(JWTAssertionDetails.getReservedClaimsNames().contains("exp"));
		assertTrue(JWTAssertionDetails.getReservedClaimsNames().contains("nbf"));
		assertTrue(JWTAssertionDetails.getReservedClaimsNames().contains("iat"));
		assertTrue(JWTAssertionDetails.getReservedClaimsNames().contains("jti"));
		assertEquals(7, JWTAssertionDetails.getReservedClaimsNames().size());
	}


	public void testMinimalConstructor()
		throws Exception {

		Issuer iss = new Issuer("https://client.example.com");
		Subject sub = new Subject("alice");
		Audience aud = new Audience("https://server.c2id.com");

		JWTAssertionDetails claimsSet = new JWTAssertionDetails(iss, sub, aud);

		// Test getters
		assertEquals(iss, claimsSet.getIssuer());
		assertEquals(sub, claimsSet.getSubject());
		assertEquals(aud, claimsSet.getAudience().get(0));

		// 4 min < exp < 6 min
		final long now = new Date().getTime();
		final Date fourMinutesFromNow = new Date(now + 4 * 60 * 1000L);
		final Date sixMinutesFromNow = new Date(now + 6 * 60 * 1000L);
		assertTrue(claimsSet.getExpirationTime().after(fourMinutesFromNow));
		assertTrue(claimsSet.getExpirationTime().before(sixMinutesFromNow));

		assertNull(claimsSet.getIssueTime());
		assertNull(claimsSet.getNotBeforeTime());

		assertNotNull(claimsSet.getJWTID());
		assertEquals(new JWTID().getValue().length(), claimsSet.getJWTID().getValue().length());

		assertNull(claimsSet.getCustomClaims());

		// Test output to JSON object
		JSONObject jsonObject = claimsSet.toJSONObject();
		assertEquals(iss.getValue(), jsonObject.get("iss"));
		assertEquals(sub.getValue(), jsonObject.get("sub"));
		assertEquals(aud.getValue(), JSONObjectUtils.getString(jsonObject, "aud"));
		assertEquals(claimsSet.getExpirationTime().getTime() / 1000L, JSONObjectUtils.getLong(jsonObject, "exp"));
		assertEquals(claimsSet.getJWTID().getValue(), jsonObject.get("jti"));
		assertEquals(5, jsonObject.size());

		// Test output to JWT claims set
		JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
		assertEquals(iss.getValue(), jwtClaimsSet.getIssuer());
		assertEquals(sub.getValue(), jwtClaimsSet.getSubject());
		assertEquals(Collections.singletonList(aud.getValue()), jwtClaimsSet.getAudience());
		assertEquals(claimsSet.getExpirationTime(), jwtClaimsSet.getExpirationTime());
		assertEquals(claimsSet.getJWTID().getValue(), jwtClaimsSet.getJWTID());
		assertEquals(5, jwtClaimsSet.toJSONObject().size());

		// JWT "aud" must be string
		assertEquals("https://server.c2id.com", jwtClaimsSet.toJSONObject().get("aud"));

		// Test parse
		JWTAssertionDetails parsed = JWTAssertionDetails.parse(jwtClaimsSet);
		assertEquals(iss, parsed.getIssuer());
		assertEquals(sub, parsed.getSubject());
		assertEquals(aud, parsed.getAudience().get(0));
		assertEquals(claimsSet.getExpirationTime().getTime() / 1000L, parsed.getExpirationTime().getTime() / 1000L);
		assertNull(parsed.getIssueTime());
		assertNull(parsed.getNotBeforeTime());
		assertEquals(claimsSet.getJWTID(), parsed.getJWTID());
		assertNull(claimsSet.getCustomClaims());
	}


	public void testMultiValuedAudience()
		throws Exception {

		Issuer iss = new Issuer("https://client.example.com");
		Subject sub = new Subject("alice");
		Audience aud_1 = new Audience("https://server.c2id.com");
		Audience aud_2 = new Audience("https://server.c2id.com/token");

		Date now = DateUtils.nowWithSecondsPrecision();
		Date exp = new Date(now.getTime() + 60 * 1000L);

		JWTAssertionDetails claimsSet = new JWTAssertionDetails(
			iss,
			sub,
			Arrays.asList(aud_1, aud_2),
			exp,
			null,
			null,
			null,
			null);

		// Test getters
		assertEquals(iss, claimsSet.getIssuer());
		assertEquals(sub, claimsSet.getSubject());
		assertEquals(Arrays.asList(aud_1, aud_2), claimsSet.getAudience());
		assertEquals(exp, claimsSet.getExpirationTime());
		assertNull(claimsSet.getNotBeforeTime());
		assertNull(claimsSet.getIssueTime());
		assertNull(claimsSet.getJWTID());
		assertNull(claimsSet.getCustomClaims());

		// Test output to JSON object
		JSONObject jsonObject = claimsSet.toJSONObject();
		assertEquals(iss.getValue(), jsonObject.get("iss"));
		assertEquals(sub.getValue(), jsonObject.get("sub"));
		assertEquals(Audience.toStringList(claimsSet.getAudience()), JSONObjectUtils.getStringList(jsonObject, "aud"));
		assertEquals(claimsSet.getExpirationTime().getTime() / 1000L, JSONObjectUtils.getLong(jsonObject, "exp"));
		assertEquals(4, jsonObject.size());

		// Test output to JWT claims set
		JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
		assertEquals(iss.getValue(), jwtClaimsSet.getIssuer());
		assertEquals(sub.getValue(), jwtClaimsSet.getSubject());
		assertEquals(Audience.toStringList(claimsSet.getAudience()), jwtClaimsSet.getAudience());
		assertEquals(claimsSet.getExpirationTime(), jwtClaimsSet.getExpirationTime());
		assertEquals(4, jwtClaimsSet.toJSONObject().size());

		// Test parse
		JWTAssertionDetails parsed = JWTAssertionDetails.parse(jwtClaimsSet);
		assertEquals(iss, parsed.getIssuer());
		assertEquals(sub, parsed.getSubject());
		assertEquals(Arrays.asList(aud_1, aud_2), parsed.getAudience());
		assertEquals(claimsSet.getExpirationTime(), parsed.getExpirationTime());
		assertNull(parsed.getIssueTime());
		assertNull(parsed.getNotBeforeTime());
		assertNull(parsed.getJWTID());
		assertNull(claimsSet.getCustomClaims());
	}


	public void testWithCustomClaims()
		throws Exception {

		Issuer iss = new Issuer("https://client.example.com");
		Subject sub = new Subject("alice");
		Audience aud = new Audience("https://server.c2id.com");

		Map<String,Object> other = new LinkedHashMap<>();
		other.put("A", "B");
		other.put("ten", 10L);

		JWTAssertionDetails claimsSet = new JWTAssertionDetails(
			iss,
			sub,
			aud.toSingleAudienceList(),
			new Date(),
			null,
			null,
			null,
			other);

		assertEquals(other, claimsSet.getCustomClaims());

		// Test output to JSON object
		JSONObject jsonObject = claimsSet.toJSONObject();

		assertEquals(iss.getValue(), jsonObject.get("iss"));
		assertEquals(sub.getValue(), jsonObject.get("sub"));
		assertEquals(aud.getValue(), JSONObjectUtils.getString(jsonObject, "aud"));
		assertNotNull(jsonObject.get("exp"));
		assertEquals("B", jsonObject.get("A"));
		assertEquals(10L, jsonObject.get("ten"));
		assertEquals(6, jsonObject.size());

		// Test output to JWT claims set
		JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
		assertEquals(iss.getValue(), jwtClaimsSet.getIssuer());
		assertEquals(sub.getValue(), jwtClaimsSet.getSubject());
		assertEquals(Collections.singletonList(aud.getValue()), jwtClaimsSet.getAudience());
		assertNotNull(jwtClaimsSet.getExpirationTime());
		assertEquals("B", jwtClaimsSet.getStringClaim("A"));
		assertEquals(10L, jwtClaimsSet.getLongClaim("ten").longValue());

		// Test parse
		JWTAssertionDetails parsed = JWTAssertionDetails.parse(jwtClaimsSet);
		assertEquals(iss, parsed.getIssuer());
		assertEquals(sub, parsed.getSubject());
		assertEquals(Collections.singletonList(aud), parsed.getAudience());
		assertEquals(claimsSet.getExpirationTime().getTime() / 1000L, parsed.getExpirationTime().getTime() / 1000L);
		assertNull(parsed.getIssueTime());
		assertNull(parsed.getNotBeforeTime());
		assertEquals(claimsSet.getJWTID(), parsed.getJWTID());
		assertNotNull(claimsSet.getCustomClaims());
		other = claimsSet.getCustomClaims();
		assertEquals("B", other.get("A"));
		assertEquals(10L, other.get("ten"));
		assertEquals(2, other.size());
	}
}
