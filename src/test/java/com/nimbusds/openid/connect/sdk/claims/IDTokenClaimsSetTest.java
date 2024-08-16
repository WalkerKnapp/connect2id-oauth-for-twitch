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


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.Nonce;
import net.minidev.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;

import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static org.junit.Assert.*;


public class IDTokenClaimsSetTest {


        @Test
        public void testClaimNameConstants() {

		assertEquals("acr", IDTokenClaimsSet.ACR_CLAIM_NAME);
		assertEquals("amr", IDTokenClaimsSet.AMR_CLAIM_NAME);
		assertEquals("at_hash", IDTokenClaimsSet.AT_HASH_CLAIM_NAME);
		assertEquals("aud", IDTokenClaimsSet.AUD_CLAIM_NAME);
		assertEquals("auth_time", IDTokenClaimsSet.AUTH_TIME_CLAIM_NAME);
		assertEquals("azp", IDTokenClaimsSet.AZP_CLAIM_NAME);
		assertEquals("c_hash", IDTokenClaimsSet.C_HASH_CLAIM_NAME);
		assertEquals("s_hash", IDTokenClaimsSet.S_HASH_CLAIM_NAME);
		assertEquals("ds_hash", IDTokenClaimsSet.DS_HASH_CLAIM_NAME);
		assertEquals("exp", IDTokenClaimsSet.EXP_CLAIM_NAME);
		assertEquals("iat", IDTokenClaimsSet.IAT_CLAIM_NAME);
		assertEquals("iss", IDTokenClaimsSet.ISS_CLAIM_NAME);
		assertEquals("iss", IDTokenClaimsSet.ISS_CLAIM_NAME);
		assertEquals("nonce", IDTokenClaimsSet.NONCE_CLAIM_NAME);
		assertEquals("sub", IDTokenClaimsSet.SUB_CLAIM_NAME);
		assertEquals("sub_jwk", IDTokenClaimsSet.SUB_JWK_CLAIM_NAME);
		assertEquals("sid", IDTokenClaimsSet.SID_CLAIM_NAME);
	}


        @Test
        public void testStdClaims() {

		Set<String> stdClaimNames = IDTokenClaimsSet.getStandardClaimNames();

		assertTrue(stdClaimNames.contains("iss"));
		assertTrue(stdClaimNames.contains("sub"));
		assertTrue(stdClaimNames.contains("aud"));
		assertTrue(stdClaimNames.contains("exp"));
		assertTrue(stdClaimNames.contains("iat"));
		assertTrue(stdClaimNames.contains("auth_time"));
		assertTrue(stdClaimNames.contains("nonce"));
		assertTrue(stdClaimNames.contains("at_hash"));
		assertTrue(stdClaimNames.contains("c_hash"));
		assertTrue(stdClaimNames.contains("s_hash"));
		assertTrue(stdClaimNames.contains("ds_hash"));
		assertTrue(stdClaimNames.contains("acr"));
		assertTrue(stdClaimNames.contains("amr"));
		assertTrue(stdClaimNames.contains("azp"));
		assertTrue(stdClaimNames.contains("sub_jwk"));
		assertTrue(stdClaimNames.contains("sid"));

		assertEquals(16, stdClaimNames.size());
	}


        @Test
        public void testReadOnlyJWTClaimsSetConstructor()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer("https://c2id.com")
			.subject("alice")
			.audience("client-123")
			.expirationTime(new Date(3_600_000L))
			.issueTime(new Date(1_000L))
			.build();

		IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(claimsSet);
		assertEquals("https://c2id.com", idTokenClaimsSet.getIssuer().getValue());
		assertEquals("alice", idTokenClaimsSet.getSubject().getValue());
		assertEquals("client-123", idTokenClaimsSet.getAudience().get(0).getValue());
		assertEquals(3_600_000L, idTokenClaimsSet.getExpirationTime().getTime());
		assertEquals(1_000L, idTokenClaimsSet.getIssueTime().getTime());
	}


        @Test
        public void testParseRoundTrip()
		throws Exception {

		// Example from messages spec

		String json = "{\n" +
			"   \"iss\"       : \"https://server.example.com\",\n" +
			"   \"sub\"       : \"24400320\",\n" +
			"   \"aud\"       : \"s6BhdRkqt3\",\n" +
			"   \"nonce\"     : \"n-0S6_WzA2Mj\",\n" +
			"   \"exp\"       : 1311281970,\n" +
			"   \"iat\"       : 1311280970,\n" +
			"   \"auth_time\" : 1311280969,\n" +
			"   \"acr\"       : \"urn:mace:incommon:iap:silver\",\n" +
			"   \"at_hash\"   : \"MTIzNDU2Nzg5MDEyMzQ1Ng\"\n" +
			" }";

		JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(json);

		IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(jwtClaimsSet);

		assertEquals("https://server.example.com", idTokenClaimsSet.getIssuer().getValue());
		assertEquals("https://server.example.com", idTokenClaimsSet.getURLClaim("iss").toString());
		assertEquals("https://server.example.com", idTokenClaimsSet.getURIClaim("iss").toString());
		assertEquals("24400320", idTokenClaimsSet.getSubject().getValue());
		assertEquals("s6BhdRkqt3", idTokenClaimsSet.getAudience().get(0).getValue());
		assertEquals("n-0S6_WzA2Mj", idTokenClaimsSet.getNonce().getValue());
		assertEquals(1311281970L, DateUtils.toSecondsSinceEpoch(idTokenClaimsSet.getExpirationTime()));
		assertEquals(1311280970L, DateUtils.toSecondsSinceEpoch(idTokenClaimsSet.getIssueTime()));
		assertEquals(1311280969L, DateUtils.toSecondsSinceEpoch(idTokenClaimsSet.getAuthenticationTime()));
		assertEquals("urn:mace:incommon:iap:silver", idTokenClaimsSet.getACR().getValue());
		assertEquals("MTIzNDU2Nzg5MDEyMzQ1Ng", idTokenClaimsSet.getAccessTokenHash().getValue());

		json = new JSONObject(idTokenClaimsSet.toJWTClaimsSet().toJSONObject()).toJSONString();
		
		assertEquals(json, idTokenClaimsSet.toString());

		jwtClaimsSet = JWTClaimsSet.parse(json);

		idTokenClaimsSet = new IDTokenClaimsSet(jwtClaimsSet);

		assertEquals("https://server.example.com", idTokenClaimsSet.getIssuer().getValue());
		assertEquals("https://server.example.com", idTokenClaimsSet.getURLClaim("iss").toString());
		assertEquals("https://server.example.com", idTokenClaimsSet.getURIClaim("iss").toString());
		assertEquals("24400320", idTokenClaimsSet.getSubject().getValue());
		assertEquals("s6BhdRkqt3", idTokenClaimsSet.getAudience().get(0).getValue());
		assertEquals("n-0S6_WzA2Mj", idTokenClaimsSet.getNonce().getValue());
		assertEquals(1311281970L, DateUtils.toSecondsSinceEpoch(idTokenClaimsSet.getExpirationTime()));
		assertEquals(1311280970L, DateUtils.toSecondsSinceEpoch(idTokenClaimsSet.getIssueTime()));
		assertEquals(1311280969L, DateUtils.toSecondsSinceEpoch(idTokenClaimsSet.getAuthenticationTime()));
		assertEquals("urn:mace:incommon:iap:silver", idTokenClaimsSet.getACR().getValue());
		assertEquals("MTIzNDU2Nzg5MDEyMzQ1Ng", idTokenClaimsSet.getAccessTokenHash().getValue());
	}


        @Test
        public void testGettersAndSetters()
		throws Exception {

		Issuer issuer = new Issuer("iss");
		Subject subject = new Subject("sub");

		List<Audience> audList = new LinkedList<>();
		audList.add(new Audience("aud"));

		Date expirationTime = DateUtils.fromSecondsSinceEpoch(3L);
		Date issueTime = DateUtils.fromSecondsSinceEpoch(2L);

		IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(issuer, subject, audList, expirationTime, issueTime);

		Date authenticationTime = DateUtils.fromSecondsSinceEpoch(1L);
		idTokenClaimsSet.setAuthenticationTime(authenticationTime);

		Nonce nonce = new Nonce();
		idTokenClaimsSet.setNonce(nonce);

		AccessTokenHash accessTokenHash = new AccessTokenHash("123");
		idTokenClaimsSet.setAccessTokenHash(accessTokenHash);

		CodeHash codeHash = new CodeHash("456");
		idTokenClaimsSet.setCodeHash(codeHash);
		
		StateHash stateHash = new StateHash("789");
		idTokenClaimsSet.setStateHash(stateHash);

		DeviceSecretHash deviceSecretHash = new DeviceSecretHash("aa1heg4TahGe6eiT");
		idTokenClaimsSet.setDeviceSecretHash(deviceSecretHash);

		ACR acr = new ACR("1");
		idTokenClaimsSet.setACR(acr);

		List<AMR> amrList = new LinkedList<>();
		amrList.add(new AMR("A"));
		idTokenClaimsSet.setAMR(amrList);

		AuthorizedParty authorizedParty = new AuthorizedParty("azp");
		idTokenClaimsSet.setAuthorizedParty(authorizedParty);

		// Mandatory claims
		assertEquals("iss", idTokenClaimsSet.getIssuer().getValue());
		assertEquals("sub", idTokenClaimsSet.getSubject().getValue());
		assertEquals("aud", idTokenClaimsSet.getAudience().get(0).getValue());
		assertEquals(3L, idTokenClaimsSet.getExpirationTime().getTime() / 1000);
		assertEquals(2L, idTokenClaimsSet.getIssueTime().getTime() / 1000);

		// Optional claims
		assertEquals(1L, idTokenClaimsSet.getAuthenticationTime().getTime() / 1000);
		assertEquals(nonce.getValue(), idTokenClaimsSet.getNonce().getValue());
		assertEquals(accessTokenHash.getValue(), idTokenClaimsSet.getAccessTokenHash().getValue());
		assertEquals(codeHash.getValue(), idTokenClaimsSet.getCodeHash().getValue());
		assertEquals(stateHash.getValue(), idTokenClaimsSet.getStateHash().getValue());
		assertEquals(deviceSecretHash.getValue(), idTokenClaimsSet.getDeviceSecretHash().getValue());
		assertEquals(acr.getValue(), idTokenClaimsSet.getACR().getValue());
		assertEquals("A", idTokenClaimsSet.getAMR().get(0).getValue());
		assertEquals(authorizedParty.getValue(), idTokenClaimsSet.getAuthorizedParty().getValue());

		String json = idTokenClaimsSet.toJSONObject().toJSONString();
		
		assertEquals(json, idTokenClaimsSet.toString());

		// Try to JWT claims set too
		idTokenClaimsSet.toJWTClaimsSet();

		idTokenClaimsSet = IDTokenClaimsSet.parse(json);

		// Mandatory claims
		assertEquals("iss", idTokenClaimsSet.getIssuer().getValue());
		assertEquals("sub", idTokenClaimsSet.getSubject().getValue());
		assertEquals("aud", idTokenClaimsSet.getAudience().get(0).getValue());
		assertEquals(3L, idTokenClaimsSet.getExpirationTime().getTime() / 1000);
		assertEquals(2L, idTokenClaimsSet.getIssueTime().getTime() / 1000);

		// Optional claims
		assertEquals(1L, idTokenClaimsSet.getAuthenticationTime().getTime() / 1000);
		assertEquals(nonce.getValue(), idTokenClaimsSet.getNonce().getValue());
		assertEquals(accessTokenHash.getValue(), idTokenClaimsSet.getAccessTokenHash().getValue());
		assertEquals(codeHash.getValue(), idTokenClaimsSet.getCodeHash().getValue());
		assertEquals(stateHash.getValue(), idTokenClaimsSet.getStateHash().getValue());
		assertEquals(deviceSecretHash.getValue(), idTokenClaimsSet.getDeviceSecretHash().getValue());
		assertEquals(acr.getValue(), idTokenClaimsSet.getACR().getValue());
		assertEquals("A", idTokenClaimsSet.getAMR().get(0).getValue());
		assertEquals(authorizedParty.getValue(), idTokenClaimsSet.getAuthorizedParty().getValue());
	}


        @Test
        public void testStateHash()
		throws Exception {
		
		IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(
			new Issuer("https://c2id.com"),
			new Subject("alice"),
			new Audience("123").toSingleAudienceList(),
			new Date(60_000L),
			new Date(0L)
		);
		
		assertNull(idTokenClaimsSet.getStateHash());
		
		// Set / get null
		idTokenClaimsSet.setStateHash(null);
		assertNull(idTokenClaimsSet.getStateHash());
		
		State state = new State();
		StateHash stateHash = StateHash.compute(state, JWSAlgorithm.RS256);
		
		idTokenClaimsSet.setStateHash(stateHash);
		
		assertEquals(stateHash, idTokenClaimsSet.getStateHash());
		
		JSONObject jsonObject = idTokenClaimsSet.toJSONObject();
		
		assertEquals("https://c2id.com", jsonObject.get("iss"));
		assertEquals("alice", jsonObject.get("sub"));
		assertEquals(stateHash.getValue(), jsonObject.get("s_hash"));
		assertEquals(0L, jsonObject.get("iat"));
		assertEquals(60L, jsonObject.get("exp"));
		assertEquals("123", ((List<String>)jsonObject.get("aud")).get(0));
		assertEquals(6, jsonObject.size());
		
		idTokenClaimsSet = IDTokenClaimsSet.parse(jsonObject.toJSONString());
		
		assertEquals(stateHash, idTokenClaimsSet.getStateHash());
	}


        @Test
        public void testDeviceSecretHash()
		throws Exception {

		IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(
			new Issuer("https://c2id.com"),
			new Subject("alice"),
			new Audience("123").toSingleAudienceList(),
			new Date(60_000L),
			new Date(0L)
		);

		assertNull(idTokenClaimsSet.getDeviceSecretHash());

		// Set / get null
		idTokenClaimsSet.setDeviceSecretHash(null);
		assertNull(idTokenClaimsSet.getDeviceSecretHash());

		DeviceSecretHash deviceSecretHash = new DeviceSecretHash("aa1heg4TahGe6eiT");

		idTokenClaimsSet.setDeviceSecretHash(deviceSecretHash);

		assertEquals(deviceSecretHash, idTokenClaimsSet.getDeviceSecretHash());

		JSONObject jsonObject = idTokenClaimsSet.toJSONObject();

		assertEquals("https://c2id.com", jsonObject.get("iss"));
		assertEquals("alice", jsonObject.get("sub"));
		assertEquals(deviceSecretHash.getValue(), jsonObject.get("ds_hash"));
		assertEquals(0L, jsonObject.get("iat"));
		assertEquals(60L, jsonObject.get("exp"));
		assertEquals("123", ((List<String>)jsonObject.get("aud")).get(0));
		assertEquals(6, jsonObject.size());

		idTokenClaimsSet = IDTokenClaimsSet.parse(jsonObject.toJSONString());

		assertEquals(deviceSecretHash, idTokenClaimsSet.getDeviceSecretHash());
	}


        @Test
        public void testSingleAudSetAndGetWorkaround() {

		Issuer issuer = new Issuer("iss");
		Subject subject = new Subject("sub");

		List<Audience> audList = new LinkedList<>();
		audList.add(new Audience("aud"));

		Date expirationTime = DateUtils.fromSecondsSinceEpoch(10L);
		Date issueTime = DateUtils.fromSecondsSinceEpoch(5L);

		IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(issuer, subject, audList, expirationTime, issueTime);

		idTokenClaimsSet.setClaim("aud", "client-1");

		assertEquals("client-1", idTokenClaimsSet.getAudience().get(0).getValue());
	}


        @Test
        public void testHasRequiredClaimsCodeFlow()
		throws Exception {

		// See http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken

		ResponseType rt_code = ResponseType.parse("code");
		final boolean iatAuthzEndpoint = false;

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
			new Issuer("iss"),
			new Subject("sub"),
			new Audience("aud").toSingleAudienceList(),
			DateUtils.fromSecondsSinceEpoch(2),
			DateUtils.fromSecondsSinceEpoch(1));

		// c_hash not required, at_hash optional in response_type=code
		assertTrue(claimsSet.hasRequiredClaims(rt_code, iatAuthzEndpoint));

		claimsSet.setCodeHash(new CodeHash("c_hash"));
		assertTrue(claimsSet.hasRequiredClaims(rt_code, iatAuthzEndpoint));

		claimsSet.setAccessTokenHash(new AccessTokenHash("at_hash"));
		assertTrue(claimsSet.hasRequiredClaims(rt_code, iatAuthzEndpoint));
	}


        @Test
        public void testHasRequiredClaimsImplicitFlow()
		throws Exception {

		// See http://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken

		ResponseType rt_idToken = ResponseType.parse("id_token");
		ResponseType rt_idToken_token = ResponseType.parse("id_token token");
		final boolean iatAuthzEndpoint = true;

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
			new Issuer("iss"),
			new Subject("sub"),
			new Audience("aud").toSingleAudienceList(),
			DateUtils.fromSecondsSinceEpoch(2),
			DateUtils.fromSecondsSinceEpoch(1));

		// nonce always required
		Assert.assertFalse(claimsSet.hasRequiredClaims(rt_idToken, iatAuthzEndpoint));
		Assert.assertFalse(claimsSet.hasRequiredClaims(rt_idToken_token, iatAuthzEndpoint));

		claimsSet.setNonce(new Nonce());

		// at_hash required in id_token token, not in id_token
		assertTrue(claimsSet.hasRequiredClaims(rt_idToken, iatAuthzEndpoint));
		Assert.assertFalse(claimsSet.hasRequiredClaims(rt_idToken_token, iatAuthzEndpoint));

		claimsSet.setAccessTokenHash(new AccessTokenHash("at_hash"));

		assertTrue(claimsSet.hasRequiredClaims(rt_idToken, iatAuthzEndpoint));
		assertTrue(claimsSet.hasRequiredClaims(rt_idToken_token, iatAuthzEndpoint));
	}


        @Test
        public void testHasRequiredClaimsHybridFlow()
		throws Exception {

		// See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
		// See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken2

		ResponseType rt_code_idToken = ResponseType.parse("code id_token");
		ResponseType rt_code_token = ResponseType.parse("code token");
		ResponseType rt_code_idToken_token = ResponseType.parse("code id_token token");

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
			new Issuer("iss"),
			new Subject("sub"),
			new Audience("aud").toSingleAudienceList(),
			DateUtils.fromSecondsSinceEpoch(2),
			DateUtils.fromSecondsSinceEpoch(1));

		// Nonce always required in hybrid flow, regardless of issue endpoint
		Assert.assertFalse(claimsSet.hasRequiredClaims(rt_code_idToken, true));
		Assert.assertFalse(claimsSet.hasRequiredClaims(rt_code_token, true));
		Assert.assertFalse(claimsSet.hasRequiredClaims(rt_code_idToken_token, true));
		Assert.assertFalse(claimsSet.hasRequiredClaims(rt_code_idToken, false));
		Assert.assertFalse(claimsSet.hasRequiredClaims(rt_code_token, false));
		Assert.assertFalse(claimsSet.hasRequiredClaims(rt_code_idToken_token, false));

		claimsSet.setNonce(new Nonce());

		// at_hash and c_hash not required when id_token issued at token endpoint
		assertTrue(claimsSet.hasRequiredClaims(rt_code_idToken, false));
		assertTrue(claimsSet.hasRequiredClaims(rt_code_token, false));
		assertTrue(claimsSet.hasRequiredClaims(rt_code_idToken_token, false));

		// c_hash required with 'code id_token' and 'code id_token token' issued at authz endpoint
		Assert.assertFalse(claimsSet.hasRequiredClaims(rt_code_idToken, true));
		assertTrue(claimsSet.hasRequiredClaims(rt_code_token, true));
		Assert.assertFalse(claimsSet.hasRequiredClaims(rt_code_idToken_token, true));

		claimsSet.setCodeHash(new CodeHash("c_hash"));

		// at_hash required with 'code id_token token' issued at authz endpoint
		assertTrue(claimsSet.hasRequiredClaims(rt_code_idToken, true));
		assertTrue(claimsSet.hasRequiredClaims(rt_code_token, true));
		Assert.assertFalse(claimsSet.hasRequiredClaims(rt_code_idToken_token, true));

		claimsSet.setAccessTokenHash(new AccessTokenHash("at_hash"));

		assertTrue(claimsSet.hasRequiredClaims(rt_code_idToken, true));
		assertTrue(claimsSet.hasRequiredClaims(rt_code_token, true));
		assertTrue(claimsSet.hasRequiredClaims(rt_code_idToken_token, true));
	}


        @Test
        public void testRequiredClaims_unsupportedResponseType() {

		ResponseType responseType = new ResponseType("token");

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
			new Issuer("iss"),
			new Subject("sub"),
			new Audience("aud").toSingleAudienceList(),
			DateUtils.fromSecondsSinceEpoch(2),
			DateUtils.fromSecondsSinceEpoch(1));

		try {
			claimsSet.hasRequiredClaims(responseType, true);
			Assert.fail();
		} catch (IllegalArgumentException e) {
			assertEquals("Unsupported response_type: token", e.getMessage());
		}
	}


        @Test
        public void testSubjectJWK()
		throws Exception {

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
			new Issuer("iss"),
			new Subject("sub"),
			new Audience("aud").toSingleAudienceList(),
			DateUtils.fromSecondsSinceEpoch(2),
			DateUtils.fromSecondsSinceEpoch(1));

		assertNull(claimsSet.getSubjectJWK());

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);

		KeyPair keyPair = keyGen.generateKeyPair();

		RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();

		RSAKey rsaJWK = new RSAKey.Builder(publicKey).keyID("1").build();

		claimsSet.setSubjectJWK(rsaJWK);

		RSAKey rsaJWKOut = (RSAKey)claimsSet.getSubjectJWK();

		assertEquals(rsaJWK.getModulus(), rsaJWKOut.getModulus());
		assertEquals(rsaJWK.getPublicExponent(), rsaJWKOut.getPublicExponent());
		assertEquals(rsaJWK.getKeyID(), rsaJWKOut.getKeyID());


		String json = claimsSet.toJSONObject().toJSONString();

//		System.out.println("ID token with subject JWK: " + json);

		claimsSet = IDTokenClaimsSet.parse(json);

		rsaJWKOut = (RSAKey)claimsSet.getSubjectJWK();

		assertEquals(rsaJWK.getModulus(), rsaJWKOut.getModulus());
		assertEquals(rsaJWK.getPublicExponent(), rsaJWKOut.getPublicExponent());
		assertEquals(rsaJWK.getKeyID(), rsaJWKOut.getKeyID());
	}


        @Test
        public void testRejectPrivateSubjectJWK()
		throws Exception {

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
			new Issuer("iss"),
			new Subject("sub"),
			new Audience("aud").toSingleAudienceList(),
			DateUtils.fromSecondsSinceEpoch(2),
			DateUtils.fromSecondsSinceEpoch(1));

		assertNull(claimsSet.getSubjectJWK());

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);

		KeyPair keyPair = keyGen.generateKeyPair();

		RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();

		RSAKey rsaJWK = new RSAKey.Builder(publicKey).privateKey(privateKey).build();

		try {
			claimsSet.setSubjectJWK(rsaJWK);

			Assert.fail();

		} catch (IllegalArgumentException e) {
			// ok
		}
	}


        @Test
        public void testStringClaim() {

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
			new Issuer("iss"),
			new Subject("sub"),
			new Audience("aud").toSingleAudienceList(),
			DateUtils.fromSecondsSinceEpoch(2),
			DateUtils.fromSecondsSinceEpoch(1));

		claimsSet.setClaim("xString", "apples");

		assertEquals("apples", claimsSet.getStringClaim("xString"));

		assertNull(claimsSet.getStringClaim("exp"));
	}


        @Test
        public void testNumberClaim() {

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
			new Issuer("iss"),
			new Subject("sub"),
			new Audience("aud").toSingleAudienceList(),
			DateUtils.fromSecondsSinceEpoch(2),
			DateUtils.fromSecondsSinceEpoch(1));

		claimsSet.setClaim("xInteger", 10);

		assertEquals(10, claimsSet.getNumberClaim("xInteger").intValue());

		assertNull(claimsSet.getNumberClaim("iss"));
	}


        @Test
        public void testURLClaim()
		throws Exception {

		IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
			new Issuer("iss"),
			new Subject("sub"),
			new Audience("aud").toSingleAudienceList(),
			DateUtils.fromSecondsSinceEpoch(2),
			DateUtils.fromSecondsSinceEpoch(1));

		claimsSet.setURLClaim("xURL", new URL("http://example.com"));

		assertEquals("http://example.com", claimsSet.getURLClaim("xURL").toString());

		assertNull(claimsSet.getURLClaim("sub"));
	}


        @Test
        public void testParameterConstructor_rejectEmptyAudience() {

		try {
			new IDTokenClaimsSet(
				new Issuer("https://c2id.com"),
				new Subject("alice"),
				Collections.<Audience>emptyList(),
				new Date(DateUtils.nowWithSecondsPrecision().getTime() + 60_000),
				DateUtils.nowWithSecondsPrecision());
			Assert.fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The aud must not be empty", e.getMessage());
		}
	}


        @Test(expected = NullPointerException.class)
        public void testParameterConstructor_rejectAudienceWithNullValue() {

		new IDTokenClaimsSet(
			new Issuer("https://c2id.com"),
			new Subject("alice"),
			Arrays.asList(new Audience("123"), null),
			new Date(DateUtils.nowWithSecondsPrecision().getTime() + 60_000),
			DateUtils.nowWithSecondsPrecision());
	}


        @Test(expected = NullPointerException.class)
        public void testParameterConstructor_rejectNullExp() {

		new IDTokenClaimsSet(
			new Issuer("https://c2id.com"),
			new Subject("alice"),
			new Audience("123").toSingleAudienceList(),
			null,
			DateUtils.nowWithSecondsPrecision());
	}


        @Test(expected = NullPointerException.class)
        public void testParameterConstructor_rejectNullIat() {

		new IDTokenClaimsSet(
			new Issuer("https://c2id.com"),
			new Subject("alice"),
			new Audience("123").toSingleAudienceList(),
			new Date(DateUtils.nowWithSecondsPrecision().getTime() + 60_000),
			null);
	}


	@Test
	public void testParameterConstructor_rejectIatAfterExp() {

		try {
			new IDTokenClaimsSet(
				new Issuer("https://c2id.com"),
				new Subject("alice"),
				new Audience("123").toSingleAudienceList(),
				DateUtils.fromSecondsSinceEpoch(1), // exp
				DateUtils.fromSecondsSinceEpoch(2)); // iat
			Assert.fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The exp must be after iat", e.getMessage());
		}
	}


	@Test
	public void testParameterConstructor_rejectIatEqualsExp() {

		try {
			new IDTokenClaimsSet(
				new Issuer("https://c2id.com"),
				new Subject("alice"),
				new Audience("123").toSingleAudienceList(),
				DateUtils.fromSecondsSinceEpoch(1), // exp
				DateUtils.fromSecondsSinceEpoch(1)); // iat
			Assert.fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The exp must be after iat", e.getMessage());
		}
	}
}
