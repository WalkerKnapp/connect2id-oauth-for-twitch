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

package com.nimbusds.openid.connect.sdk.claims;


import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.Nonce;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import java.net.URI;
import java.util.*;


public class LogoutTokenClaimsSetTest extends TestCase {
	
	
	public void testEventTypeConstant() {
		
		assertEquals("http://schemas.openid.net/event/backchannel-logout", LogoutTokenClaimsSet.EVENT_TYPE);
	}
	
	
	public void testStandardClaimNames() {
		
		Set<String> claimNames = LogoutTokenClaimsSet.getStandardClaimNames();
		assertTrue(claimNames.contains("iss"));
		assertTrue(claimNames.contains("sub"));
		assertTrue(claimNames.contains("aud"));
		assertTrue(claimNames.contains("iat"));
		assertTrue(claimNames.contains("exp"));
		assertTrue(claimNames.contains("jti"));
		assertTrue(claimNames.contains("events"));
		assertTrue(claimNames.contains("sid"));
		assertEquals(8, claimNames.size());
	}
	

	public void testWithSubject()
		throws Exception {
		
		Issuer iss = new Issuer(URI.create("https://c2id.com"));
		Subject sub = new Subject("alice");
		List<Audience> audList = new Audience(new ClientID("123")).toSingleAudienceList();
		Date iat = DateUtils.fromSecondsSinceEpoch(10203040L);
		Date exp = DateUtils.fromSecondsSinceEpoch(10204050L);
		JWTID jti = new JWTID();
		
		LogoutTokenClaimsSet claimsSet = new LogoutTokenClaimsSet(iss, sub, audList, iat, exp, jti, null);
		
		assertEquals(iss, claimsSet.getIssuer());
		assertEquals(sub, claimsSet.getSubject());
		assertEquals(audList, claimsSet.getAudience());
		assertEquals(iat, claimsSet.getIssueTime());
		assertEquals(exp, claimsSet.getExpirationTime());
		assertEquals(jti, claimsSet.getJWTID());
		assertNull(claimsSet.getSessionID());
		
		JSONObject jsonObject = claimsSet.toJSONObject();
		
		assertEquals(iss.getValue(), jsonObject.get("iss"));
		assertEquals(sub.getValue(), jsonObject.get("sub"));
		assertEquals(Collections.singletonList("123"), JSONObjectUtils.getStringList(jsonObject, "aud"));
		assertEquals(DateUtils.toSecondsSinceEpoch(iat), jsonObject.get("iat"));
		assertEquals(DateUtils.toSecondsSinceEpoch(exp), jsonObject.get("exp"));
		assertEquals(jti.getValue(), jsonObject.get("jti"));
		JSONObject events = (JSONObject) jsonObject.get("events");
		JSONObject eventType = (JSONObject) events.get(LogoutTokenClaimsSet.EVENT_TYPE);
		assertTrue(eventType.isEmpty());
		
		claimsSet = LogoutTokenClaimsSet.parse(jsonObject.toJSONString());
		
		assertEquals(iss, claimsSet.getIssuer());
		assertEquals(sub, claimsSet.getSubject());
		assertEquals(audList, claimsSet.getAudience());
		assertEquals(iat, claimsSet.getIssueTime());
		assertEquals(exp, claimsSet.getExpirationTime());
		assertEquals(jti, claimsSet.getJWTID());
		assertNull(claimsSet.getSessionID());
		
		JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
		assertEquals(iss.getValue(), jwtClaimsSet.getIssuer());
		assertEquals(sub.getValue(), jwtClaimsSet.getSubject());
		assertEquals(Collections.singletonList("123"), jwtClaimsSet.getAudience());
		assertEquals(iat, jwtClaimsSet.getIssueTime());
		assertEquals(exp, jwtClaimsSet.getExpirationTime());
		assertEquals(jti.getValue(), jwtClaimsSet.getJWTID());
		assertNull(jwtClaimsSet.getClaim("sid"));
	}


	public void testWithSubject_deprecatedConstructor_noExp()
		throws Exception {

		Issuer iss = new Issuer(URI.create("https://c2id.com"));
		Subject sub = new Subject("alice");
		List<Audience> audList = new Audience(new ClientID("123")).toSingleAudienceList();
		Date iat = DateUtils.fromSecondsSinceEpoch(10203040L);
		JWTID jti = new JWTID();

		LogoutTokenClaimsSet claimsSet = new LogoutTokenClaimsSet(iss, sub, audList, iat, jti, null);

		assertEquals(iss, claimsSet.getIssuer());
		assertEquals(sub, claimsSet.getSubject());
		assertEquals(audList, claimsSet.getAudience());
		assertEquals(iat, claimsSet.getIssueTime());
		assertNull(claimsSet.getExpirationTime());
		assertEquals(jti, claimsSet.getJWTID());
		assertNull(claimsSet.getSessionID());

		JSONObject jsonObject = claimsSet.toJSONObject();

		assertEquals(iss.getValue(), jsonObject.get("iss"));
		assertEquals(sub.getValue(), jsonObject.get("sub"));
		assertEquals(Collections.singletonList("123"), JSONObjectUtils.getStringList(jsonObject, "aud"));
		assertEquals(DateUtils.toSecondsSinceEpoch(iat), jsonObject.get("iat"));
		assertEquals(jti.getValue(), jsonObject.get("jti"));
		JSONObject events = (JSONObject) jsonObject.get("events");
		JSONObject eventType = (JSONObject) events.get(LogoutTokenClaimsSet.EVENT_TYPE);
		assertTrue(eventType.isEmpty());
		assertEquals(6, jsonObject.size());

		try {
			LogoutTokenClaimsSet.parse(jsonObject.toJSONString());
			fail();
		} catch (ParseException e) {
			assertEquals("Missing or invalid exp claim", e.getMessage());
		}
	}
	

	public void testWithSessionID()
		throws Exception {
		
		Issuer iss = new Issuer(URI.create("https://c2id.com"));
		List<Audience> audList = new Audience(new ClientID("123")).toSingleAudienceList();
		Date iat = DateUtils.fromSecondsSinceEpoch(10203040L);
		Date exp = DateUtils.fromSecondsSinceEpoch(10204050L);
		JWTID jti = new JWTID();
		SessionID sid = new SessionID(UUID.randomUUID().toString());
		
		LogoutTokenClaimsSet claimsSet = new LogoutTokenClaimsSet(iss, null, audList, iat, exp, jti, sid);
		
		assertEquals(iss, claimsSet.getIssuer());
		assertNull(claimsSet.getSubject());
		assertEquals(audList, claimsSet.getAudience());
		assertEquals(iat, claimsSet.getIssueTime());
		assertEquals(exp, claimsSet.getExpirationTime());
		assertEquals(jti, claimsSet.getJWTID());
		assertEquals(sid, claimsSet.getSessionID());
		
		JSONObject jsonObject = claimsSet.toJSONObject();
		
		assertEquals(iss.getValue(), jsonObject.get("iss"));
		assertEquals(Collections.singletonList("123"), JSONObjectUtils.getStringList(jsonObject, "aud"));
		assertEquals(DateUtils.toSecondsSinceEpoch(iat), jsonObject.get("iat"));
		assertEquals(DateUtils.toSecondsSinceEpoch(exp), jsonObject.get("exp"));
		assertEquals(jti.getValue(), jsonObject.get("jti"));
		assertEquals(sid.getValue(), jsonObject.get("sid"));
		JSONObject events = (JSONObject) jsonObject.get("events");
		JSONObject eventType = (JSONObject) events.get(LogoutTokenClaimsSet.EVENT_TYPE);
		assertTrue(eventType.isEmpty());
		
		claimsSet = LogoutTokenClaimsSet.parse(jsonObject.toJSONString());
		
		assertEquals(iss, claimsSet.getIssuer());
		assertNull(claimsSet.getSubject());
		assertEquals(audList, claimsSet.getAudience());
		assertEquals(iat, claimsSet.getIssueTime());
		assertEquals(exp, claimsSet.getExpirationTime());
		assertEquals(jti, claimsSet.getJWTID());
		assertEquals(sid, claimsSet.getSessionID());
		
		JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
		assertEquals(iss.getValue(), jwtClaimsSet.getIssuer());
		assertEquals(Collections.singletonList("123"), jwtClaimsSet.getAudience());
		assertEquals(iat, jwtClaimsSet.getIssueTime());
		assertEquals(exp, jwtClaimsSet.getExpirationTime());
		assertEquals(jti.getValue(), jwtClaimsSet.getJWTID());
		assertEquals(sid.getValue(), jwtClaimsSet.getClaim("sid"));
	}


	public void testWithSessionID_deprecatedConstructor_noExp()
		throws Exception {

		Issuer iss = new Issuer(URI.create("https://c2id.com"));
		List<Audience> audList = new Audience(new ClientID("123")).toSingleAudienceList();
		Date iat = DateUtils.fromSecondsSinceEpoch(10203040L);
		JWTID jti = new JWTID();
		SessionID sid = new SessionID(UUID.randomUUID().toString());

		LogoutTokenClaimsSet claimsSet = new LogoutTokenClaimsSet(iss, null, audList, iat, jti, sid);

		assertEquals(iss, claimsSet.getIssuer());
		assertNull(claimsSet.getSubject());
		assertEquals(audList, claimsSet.getAudience());
		assertEquals(iat, claimsSet.getIssueTime());
		assertNull(claimsSet.getExpirationTime());
		assertEquals(jti, claimsSet.getJWTID());
		assertEquals(sid, claimsSet.getSessionID());

		JSONObject jsonObject = claimsSet.toJSONObject();

		assertEquals(iss.getValue(), jsonObject.get("iss"));
		assertEquals(Collections.singletonList("123"), JSONObjectUtils.getStringList(jsonObject, "aud"));
		assertEquals(DateUtils.toSecondsSinceEpoch(iat), jsonObject.get("iat"));
		assertEquals(jti.getValue(), jsonObject.get("jti"));
		assertEquals(sid.getValue(), jsonObject.get("sid"));
		JSONObject events = (JSONObject) jsonObject.get("events");
		JSONObject eventType = (JSONObject) events.get(LogoutTokenClaimsSet.EVENT_TYPE);
		assertTrue(eventType.isEmpty());
		assertEquals(6, jsonObject.size());

		try {
			LogoutTokenClaimsSet.parse(jsonObject.toJSONString());
			fail();
		} catch (ParseException e) {
			assertEquals("Missing or invalid exp claim", e.getMessage());
		}
	}
	

	public void testWithSubjectAndSessionID()
		throws Exception {
		
		Issuer iss = new Issuer(URI.create("https://c2id.com"));
		Subject sub = new Subject("alice");
		List<Audience> audList = new Audience(new ClientID("123")).toSingleAudienceList();
		Date iat = DateUtils.fromSecondsSinceEpoch(10203040L);
		Date exp = DateUtils.fromSecondsSinceEpoch(10204050L);
		JWTID jti = new JWTID();
		SessionID sid = new SessionID(UUID.randomUUID().toString());
		
		LogoutTokenClaimsSet claimsSet = new LogoutTokenClaimsSet(iss, sub, audList, iat, exp, jti, sid);
		
		assertEquals(iss, claimsSet.getIssuer());
		assertEquals(sub, claimsSet.getSubject());
		assertEquals(audList, claimsSet.getAudience());
		assertEquals(iat, claimsSet.getIssueTime());
		assertEquals(exp, claimsSet.getExpirationTime());
		assertEquals(jti, claimsSet.getJWTID());
		assertEquals(sid, claimsSet.getSessionID());
		
		JSONObject jsonObject = claimsSet.toJSONObject();
		
		assertEquals(iss.getValue(), jsonObject.get("iss"));
		assertEquals(sub.getValue(), jsonObject.get("sub"));
		assertEquals(Collections.singletonList("123"), JSONObjectUtils.getStringList(jsonObject, "aud"));
		assertEquals(DateUtils.toSecondsSinceEpoch(iat), jsonObject.get("iat"));
		assertEquals(jti.getValue(), jsonObject.get("jti"));
		assertEquals(sid.getValue(), jsonObject.get("sid"));
		JSONObject events = (JSONObject) jsonObject.get("events");
		JSONObject eventType = (JSONObject) events.get(LogoutTokenClaimsSet.EVENT_TYPE);
		assertTrue(eventType.isEmpty());
		assertEquals(8, jsonObject.size());
		
		claimsSet = LogoutTokenClaimsSet.parse(jsonObject.toJSONString());
		
		assertEquals(iss, claimsSet.getIssuer());
		assertEquals(sub, claimsSet.getSubject());
		assertEquals(audList, claimsSet.getAudience());
		assertEquals(iat, claimsSet.getIssueTime());
		assertEquals(exp, claimsSet.getExpirationTime());
		assertEquals(jti, claimsSet.getJWTID());
		assertEquals(sid, claimsSet.getSessionID());
		
		JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
		assertEquals(iss.getValue(), jwtClaimsSet.getIssuer());
		assertEquals(sub.getValue(), jwtClaimsSet.getSubject());
		assertEquals(Collections.singletonList("123"), jwtClaimsSet.getAudience());
		assertEquals(iat, jwtClaimsSet.getIssueTime());
		assertEquals(exp, jwtClaimsSet.getExpirationTime());
		assertEquals(jti.getValue(), jwtClaimsSet.getJWTID());
		assertEquals(sid.getValue(), jwtClaimsSet.getClaim("sid"));
		assertEquals(8, jwtClaimsSet.getClaims().size());
	}
	
	
	public void testNonceProhibited_output() {
		
		Issuer iss = new Issuer(URI.create("https://c2id.com"));
		Subject sub = new Subject("alice");
		List<Audience> audList = new Audience(new ClientID("123")).toSingleAudienceList();
		Date iat = DateUtils.fromSecondsSinceEpoch(10203040L);
		JWTID jti = new JWTID();
		SessionID sid = new SessionID(UUID.randomUUID().toString());
		
		LogoutTokenClaimsSet claimsSet = new LogoutTokenClaimsSet(iss, sub, audList, iat, jti, sid);
		claimsSet.setClaim("nonce", new Nonce().getValue());
		
		try {
			claimsSet.toJSONObject();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Nonce is prohibited", e.getMessage());
		}
		
		try {
			claimsSet.toJWTClaimsSet();
			fail();
		} catch (ParseException e) {
			assertEquals("Nonce is prohibited", e.getMessage());
		}
	}
	
	
	public void testNonceProhibited_parse()
		throws ParseException {
		
		Issuer iss = new Issuer(URI.create("https://c2id.com"));
		Subject sub = new Subject("alice");
		List<Audience> audList = new Audience(new ClientID("123")).toSingleAudienceList();
		Date iat = DateUtils.fromSecondsSinceEpoch(10203040L);
		Date exp = DateUtils.fromSecondsSinceEpoch(10204050L);
		JWTID jti = new JWTID();
		SessionID sid = new SessionID(UUID.randomUUID().toString());
		
		LogoutTokenClaimsSet claimsSet = new LogoutTokenClaimsSet(iss, sub, audList, iat, exp, jti, sid);
		
		JSONObject jsonObject = claimsSet.toJSONObject();
		jsonObject.put("nonce", new Nonce().getValue());
		
		try {
			LogoutTokenClaimsSet.parse(jsonObject.toJSONString());
			fail();
		} catch (ParseException e) {
			assertEquals("Nonce is prohibited", e.getMessage());
		}
		
		JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
		jwtClaimsSet = new JWTClaimsSet.Builder(jwtClaimsSet)
			.claim("nonce", new Nonce().getValue())
			.build();
		
		try {
			new LogoutTokenClaimsSet(jwtClaimsSet);
			fail();
		} catch (ParseException e) {
			assertEquals("Nonce is prohibited", e.getMessage());
		}
	}
	
	
	public void testConstructorSubAndSIDMissing() {
		
		try {
			new LogoutTokenClaimsSet(
				new Issuer("https://c2id.com"),
				null,
				new Audience("123").toSingleAudienceList(),
				new Date(),
				new Date(),
				new JWTID(),
				null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("Either the subject or the session ID must be set, or both", e.getMessage());
		}
	}
	
	
	public void testParseEventTypeMissing() {
		
		String json = "{\n" +
			"   \"iss\": \"https://server.example.com\",\n" +
			"   \"sub\": \"248289761001\",\n" +
			"   \"aud\": \"s6BhdRkqt3\",\n" +
			"   \"iat\": 1471566154,\n" +
			"   \"exp\": 1471569754,\n" +
			"   \"jti\": \"bWJq\",\n" +
			"   \"sid\": \"08a5019c-17e1-4977-8f42-65a12843ea02\"\n" +
			"  }";
		
		try {
			LogoutTokenClaimsSet.parse(json);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing or invalid events claim", e.getMessage());
		}
	}
}
