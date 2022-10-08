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

package com.nimbusds.openid.connect.sdk.federation.trust.marks;


import java.util.UUID;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;


public class TrustMarkEntryTest extends TestCase {


	public void testConstructor() throws JOSEException, ParseException {
		
		TrustMarkClaimsSet trustMarkClaimsSet = new TrustMarkClaimsSet(
			new Issuer("https://tm.example.com"),
			new Subject("https://op.example.com"),
			new Identifier("tm-1"),
			DateUtils.fromSecondsSinceEpoch(1000));
		
		SignedJWT tm = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), trustMarkClaimsSet.toJWTClaimsSet());
		tm.sign(new RSASSASigner(new RSAKeyGenerator(2048).generate()));
		
		TrustMarkEntry entry = new TrustMarkEntry(trustMarkClaimsSet.getID(), tm);
		
		assertEquals(trustMarkClaimsSet.getID(), entry.getID());
		assertEquals(trustMarkClaimsSet.getID(), entry.getKey());
		
		assertEquals(tm, entry.getTrustMark());
		assertEquals(tm, entry.getValue());
		
		try {
			entry.setValue(tm);
			fail();
		} catch (UnsupportedOperationException e) {
			assertNull(e.getMessage());
		}
		
		JSONObject jsonObject = entry.toJSONObject();
		assertEquals(trustMarkClaimsSet.getID().getValue(), jsonObject.get("id"));
		assertEquals(tm.serialize(), jsonObject.get("trust_mark"));
		assertEquals(2, jsonObject.size());
		
		entry = TrustMarkEntry.parse(jsonObject);
		
		assertEquals(trustMarkClaimsSet.getID(), entry.getID());
		assertEquals(tm.serialize(), entry.getTrustMark().serialize());
	}
	
	
	public void testConstructor_nullID() throws JOSEException, ParseException {
		
		TrustMarkClaimsSet trustMarkClaimsSet = new TrustMarkClaimsSet(
			new Issuer("https://tm.example.com"),
			new Subject("https://op.example.com"),
			new Identifier("tm-1"),
			DateUtils.fromSecondsSinceEpoch(1000));
		
		SignedJWT tm = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), trustMarkClaimsSet.toJWTClaimsSet());
		tm.sign(new RSASSASigner(new RSAKeyGenerator(2048).generate()));
		
		try {
			new TrustMarkEntry(null, tm);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testConstructor_nullTrustMark() {
		try {
			new TrustMarkEntry(new Identifier("tm-1"), null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testConstructor_trustMarkNotSigned() throws ParseException {
		
		TrustMarkClaimsSet trustMarkClaimsSet = new TrustMarkClaimsSet(
			new Issuer("https://tm.example.com"),
			new Subject("https://op.example.com"),
			new Identifier("tm-1"),
			DateUtils.fromSecondsSinceEpoch(1000));
		
		SignedJWT tm = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), trustMarkClaimsSet.toJWTClaimsSet());
		
		try {
			new TrustMarkEntry(new Identifier("tm-1"), tm);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The trust mark must be in a signed state", e.getMessage());
		}
	}
	
	
	public void testConstructor_trustMarkVerified() throws ParseException, JOSEException {
		
		TrustMarkClaimsSet trustMarkClaimsSet = new TrustMarkClaimsSet(
			new Issuer("https://tm.example.com"),
			new Subject("https://op.example.com"),
			new Identifier("tm-1"),
			DateUtils.fromSecondsSinceEpoch(1000));
		
		SignedJWT tm = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), trustMarkClaimsSet.toJWTClaimsSet());
		RSAKey key = new RSAKeyGenerator(2048).generate();
		tm.sign(new RSASSASigner(key.toRSAPrivateKey()));
		assertTrue(tm.verify(new RSASSAVerifier(key.toRSAPublicKey())));
		
		TrustMarkEntry entry = new TrustMarkEntry(new Identifier("tm-1"), tm);
		assertEquals(new Identifier("tm-1"), entry.getID());
		assertEquals(tm, entry.getTrustMark());
	}
	
	
	public void testParse_rejectEmpty() {
		
		try {
			TrustMarkEntry.parse(new JSONObject());
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key id", e.getMessage());
		}
	}
	
	public void testParse_illegalJWT() {
		
		JSONObject o = new JSONObject();
		o.put("id", UUID.randomUUID().toString());
		o.put("trust_mark", "abc.def.ghi");
		
		try {
			TrustMarkEntry.parse(o);
			fail();
		} catch (ParseException e) {
			assertTrue(e.getMessage().startsWith("Invalid JWS header:"));
		}
	}
}
