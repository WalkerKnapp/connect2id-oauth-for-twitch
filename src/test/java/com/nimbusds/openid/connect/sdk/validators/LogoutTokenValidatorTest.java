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

package com.nimbusds.openid.connect.sdk.validators;


import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.BadJWSException;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.claims.LogoutTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.SessionID;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;
import org.junit.Assert;

import java.net.URI;
import java.security.Key;
import java.util.*;


public class LogoutTokenValidatorTest extends TestCase {
	
	
	private static final Issuer ISSUER = new Issuer(URI.create("https://c2id.com"));
	
	
	private static final JWTID JWTID = new JWTID();
	
	
	private static final Subject SUBJECT = new Subject("alice");
	
	
	private static final SessionID SESSION_ID = new SessionID(UUID.randomUUID().toString());
	
	
	private static final ClientID CLIENT_ID = new ClientID("123");
	
	
	private static final Secret CLIENT_SECRET = new Secret(32);


	private static final Date IAT = DateUtils.nowWithSecondsPrecision();


	private static final Date EXP = DateUtils.fromSecondsSinceEpoch(IAT.getTime() + 5 * 60 * 1000L);
	
	
	private static final RSAKey RSA_SIGN_JWK;
	
	
	private static final RSAKey RSA_ENCRYPT_JWK;
	
	
	static {
		try {
			RSA_SIGN_JWK = new RSAKeyGenerator(2048)
				.keyUse(KeyUse.SIGNATURE)
				.keyIDFromThumbprint(true)
				.generate();
			
			RSA_ENCRYPT_JWK = new RSAKeyGenerator(2048)
				.keyUse(KeyUse.ENCRYPTION)
				.keyIDFromThumbprint(true)
				.generate();
			
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public void testRejectPlainJWT()
		throws Exception {
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			null)
			.toJWTClaimsSet();
		
		JWT logoutToken = new PlainJWT(claimsSet);
		
		try {
			validator.validate(logoutToken);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Unsecured (plain) logout tokens are illegal", e.getMessage());
		}
	}
	
	
	public void testGoodRSASigned_sub()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			null)
			.toJWTClaimsSet();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.keyID(RSA_SIGN_JWK.getKeyID())
				.build(),
			claimsSet);
		
		jwt.sign(new RSASSASigner(RSA_SIGN_JWK));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.RS256, new JWKSet(RSA_SIGN_JWK.toPublicJWK())
		);
		
		LogoutTokenClaimsSet validatedClaims = validator.validate(jwt);
		
		assertEquals(ISSUER, validatedClaims.getIssuer());
		assertEquals(SUBJECT, validatedClaims.getSubject());
		assertEquals(new Audience(CLIENT_ID).toSingleAudienceList(), validatedClaims.getAudience());
		assertNotNull(validatedClaims.getIssueTime());
		assertEquals(JWTID, validatedClaims.getJWTID());
		assertNull(validatedClaims.getSessionID());
	}
	
	
	public void testGoodRSASigned_sid()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			null,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			SESSION_ID)
			.toJWTClaimsSet();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.keyID(RSA_SIGN_JWK.getKeyID())
				.build(),
			claimsSet);
		
		jwt.sign(new RSASSASigner(RSA_SIGN_JWK));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.RS256, new JWKSet(RSA_SIGN_JWK.toPublicJWK())
		);
		
		LogoutTokenClaimsSet validatedClaims = validator.validate(jwt);
		
		assertEquals(ISSUER, validatedClaims.getIssuer());
		assertNull(validatedClaims.getSubject());
		assertEquals(new Audience(CLIENT_ID).toSingleAudienceList(), validatedClaims.getAudience());
		assertNotNull(validatedClaims.getIssueTime());
		assertEquals(JWTID, validatedClaims.getJWTID());
		assertEquals(SESSION_ID, validatedClaims.getSessionID());
	}
	
	
	public void testGoodRSASigned_sub_sid()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			SESSION_ID)
			.toJWTClaimsSet();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.keyID(RSA_SIGN_JWK.getKeyID())
				.build(),
			claimsSet);
		
		jwt.sign(new RSASSASigner(RSA_SIGN_JWK));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.RS256, new JWKSet(RSA_SIGN_JWK.toPublicJWK())
		);
		
		LogoutTokenClaimsSet validatedClaims = validator.validate(jwt);
		
		assertEquals(ISSUER, validatedClaims.getIssuer());
		assertEquals(SUBJECT, validatedClaims.getSubject());
		assertEquals(new Audience(CLIENT_ID).toSingleAudienceList(), validatedClaims.getAudience());
		assertNotNull(validatedClaims.getIssueTime());
		assertEquals(JWTID, validatedClaims.getJWTID());
		assertEquals(SESSION_ID, validatedClaims.getSessionID());
	}
	
	
	public void testGoodRSASigned_optionalType()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			SESSION_ID)
			.toJWTClaimsSet();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(LogoutTokenValidator.TYPE)
				.keyID(RSA_SIGN_JWK.getKeyID())
				.build(),
			claimsSet);
		
		jwt.sign(new RSASSASigner(RSA_SIGN_JWK));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.RS256, new JWKSet(RSA_SIGN_JWK.toPublicJWK())
		);
		
		LogoutTokenClaimsSet validatedClaims = validator.validate(jwt);
		
		assertEquals(ISSUER, validatedClaims.getIssuer());
		assertEquals(SUBJECT, validatedClaims.getSubject());
		assertEquals(new Audience(CLIENT_ID).toSingleAudienceList(), validatedClaims.getAudience());
		assertNotNull(validatedClaims.getIssueTime());
		assertEquals(JWTID, validatedClaims.getJWTID());
		assertEquals(SESSION_ID, validatedClaims.getSessionID());
	}


	// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/465
	public void testGoodRSASigned_genericType()
		throws Exception {

		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			SESSION_ID)
			.toJWTClaimsSet();

		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(JOSEObjectType.JWT)
				.keyID(RSA_SIGN_JWK.getKeyID())
				.build(),
			claimsSet);

		jwt.sign(new RSASSASigner(RSA_SIGN_JWK));

		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.RS256, new JWKSet(RSA_SIGN_JWK.toPublicJWK())
		);

		LogoutTokenClaimsSet validatedClaims = validator.validate(jwt);

		assertEquals(ISSUER, validatedClaims.getIssuer());
		assertEquals(SUBJECT, validatedClaims.getSubject());
		assertEquals(new Audience(CLIENT_ID).toSingleAudienceList(), validatedClaims.getAudience());
		assertNotNull(validatedClaims.getIssueTime());
		assertEquals(JWTID, validatedClaims.getJWTID());
		assertEquals(SESSION_ID, validatedClaims.getSessionID());
	}
	
	
	public void testGoodRSASigned_requireType()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			SESSION_ID)
			.toJWTClaimsSet();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(LogoutTokenValidator.TYPE)
				.keyID(RSA_SIGN_JWK.getKeyID())
				.build(),
			claimsSet);
		
		jwt.sign(new RSASSASigner(RSA_SIGN_JWK));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, true, new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, new ImmutableJWKSet<>(new JWKSet(RSA_SIGN_JWK.toPublicJWK()))), null
		);
		
		LogoutTokenClaimsSet validatedClaims = validator.validate(jwt);
		
		assertEquals(ISSUER, validatedClaims.getIssuer());
		assertEquals(SUBJECT, validatedClaims.getSubject());
		assertEquals(new Audience(CLIENT_ID).toSingleAudienceList(), validatedClaims.getAudience());
		assertNotNull(validatedClaims.getIssueTime());
		assertEquals(JWTID, validatedClaims.getJWTID());
		assertEquals(SESSION_ID, validatedClaims.getSessionID());
	}
	
	
	
	public void testGoodSignedThenEncrypted()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			null)
			.toJWTClaimsSet();
		
		for (boolean typed: Arrays.asList(true, false)) {
			
			SignedJWT jwt = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.RS256)
					.keyID(RSA_SIGN_JWK.getKeyID())
					.build(),
				claimsSet);
			jwt.sign(new RSASSASigner(RSA_SIGN_JWK));
			
			JWEObject jweObject = new JWEObject(
				new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
					.type(typed ? LogoutTokenValidator.TYPE : null)
					.build(),
				new Payload(jwt)
			);
			jweObject.encrypt(new RSAEncrypter(RSA_ENCRYPT_JWK));
			
			
			LogoutTokenValidator validator = new LogoutTokenValidator(
				ISSUER, CLIENT_ID, false,
				new JWSVerificationKeySelector(JWSAlgorithm.RS256, new ImmutableJWKSet(new JWKSet(RSA_SIGN_JWK.toPublicJWK()))),
				new JWEDecryptionKeySelector(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM, new ImmutableJWKSet(new JWKSet(RSA_ENCRYPT_JWK)))
			);
			
			LogoutTokenClaimsSet validatedClaims = validator.validate(jwt);
			
			assertEquals(ISSUER, validatedClaims.getIssuer());
			assertEquals(SUBJECT, validatedClaims.getSubject());
			assertEquals(new Audience(CLIENT_ID).toSingleAudienceList(), validatedClaims.getAudience());
			assertNotNull(validatedClaims.getIssueTime());
			assertEquals(JWTID, validatedClaims.getJWTID());
			assertNull(validatedClaims.getSessionID());
		}
	}
	
	
	public void testGoodHMACSecured()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			null)
			.toJWTClaimsSet();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			claimsSet);
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		LogoutTokenClaimsSet validatedClaims = validator.validate(jwt);
		
		assertEquals(ISSUER, validatedClaims.getIssuer());
		assertEquals(SUBJECT, validatedClaims.getSubject());
		assertEquals(new Audience(CLIENT_ID).toSingleAudienceList(), validatedClaims.getAudience());
		assertNotNull(validatedClaims.getIssueTime());
		assertEquals(JWTID, validatedClaims.getJWTID());
		assertNull(validatedClaims.getSessionID());
	}
	
	
	public void testHMACSecured_badHmac()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			null)
			.toJWTClaimsSet();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			claimsSet);
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, new Secret() // other hmac
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWSException e) {
			assertEquals("Signed JWT rejected: Invalid signature", e.getMessage());
		}
	}
	
	
	public void testNonceIllegal()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			null)
			.toJWTClaimsSet();
		
		claimsSet = new JWTClaimsSet.Builder(claimsSet)
			.claim("nonce", "abc")
			.build();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			claimsSet);
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT has prohibited claims: [nonce]", e.getMessage());
		}
	}
	
	
	public void testMissingRequiredType() throws ParseException, JOSEException {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			SESSION_ID)
			.toJWTClaimsSet();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.keyID(RSA_SIGN_JWK.getKeyID())
				.build(),
			claimsSet);
		
		jwt.sign(new RSASSASigner(RSA_SIGN_JWK));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, true, new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, new ImmutableJWKSet<>(new JWKSet(RSA_SIGN_JWK.toPublicJWK()))), null
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Invalid / missing logout token typ (type) header, must be logout+jwt", e.getMessage());
		}
	}
	
	
	public void testMissingRequiredType_signedThenEncrypted() throws ParseException, JOSEException {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			SESSION_ID)
			.toJWTClaimsSet();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.keyID(RSA_SIGN_JWK.getKeyID())
				.build(),
			claimsSet);
		jwt.sign(new RSASSASigner(RSA_SIGN_JWK));
		
		JWEObject jweObject = new JWEObject(
			new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM),
			new Payload(jwt)
		);
		jweObject.encrypt(new RSAEncrypter(RSA_ENCRYPT_JWK));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, true,
			new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, new ImmutableJWKSet<>(new JWKSet(RSA_SIGN_JWK.toPublicJWK()))),
			new JWEDecryptionKeySelector<>(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM, new ImmutableJWKSet<>(new JWKSet(RSA_ENCRYPT_JWK)))
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Invalid / missing logout token typ (type) header, must be logout+jwt", e.getMessage());
		}
	}
	
	
	public void testInvalidType() throws ParseException, JOSEException {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			SESSION_ID)
			.toJWTClaimsSet();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(new JOSEObjectType("id_token+jwt")) // some unaccepted type
				.keyID(RSA_SIGN_JWK.getKeyID())
				.build(),
			claimsSet);
		
		jwt.sign(new RSASSASigner(RSA_SIGN_JWK));
		
		for (boolean requireTypedToken: Arrays.asList(true, false)) {
			
			LogoutTokenValidator validator = new LogoutTokenValidator(
				ISSUER, CLIENT_ID, requireTypedToken, new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, new ImmutableJWKSet<>(new JWKSet(RSA_SIGN_JWK.toPublicJWK()))), null
			);
			
			try {
				validator.validate(jwt);
				fail();
			} catch (BadJOSEException e) {
				if (requireTypedToken) {
					assertEquals("Invalid / missing logout token typ (type) header, must be logout+jwt", e.getMessage());
				} else {
					assertEquals("If set the logout token typ (type) header must be logout+jwt or JWT", e.getMessage());
				}
			}
		}
	}
	
	
	public void testMissing_sub_sid()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			null)
			.toJWTClaimsSet();
		
		Map<String, Object> jsonObject = claimsSet.toJSONObject();
		jsonObject.remove("sub");
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			JWTClaimsSet.parse(jsonObject));
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing subject (sub) and / or session ID (sid) claim(s)", e.getMessage());
		}
	}
	
	
	public void testMissingEvents()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			null)
			.toJWTClaimsSet();
		
		Map<String, Object> jsonObject = claimsSet.toJSONObject();
		jsonObject.remove("events");
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			JWTClaimsSet.parse(jsonObject));
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [events]", e.getMessage());
		}
	}
	
	
	public void testMissingEventsType()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			null)
			.toJWTClaimsSet();
		
		JSONObject jsonObject = JSONObjectUtils.toJSONObject(claimsSet);
		JSONObject events = (JSONObject)jsonObject.get("events");
		events.remove(LogoutTokenClaimsSet.EVENT_TYPE);
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			JWTClaimsSet.parse(jsonObject));
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Missing event type, required http://schemas.openid.net/event/backchannel-logout", e.getMessage());
		}
	}
	
	
	public void testMissingIssuer()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			null)
			.toJWTClaimsSet();
		
		Map<String, Object> jsonObject = claimsSet.toJSONObject();
		jsonObject.remove("iss");
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			JWTClaimsSet.parse(jsonObject));
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [iss]", e.getMessage());
		}
	}
	
	
	public void testUnexpectedIssuer()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			new Issuer(URI.create("https://other-idp.com")),
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			null)
			.toJWTClaimsSet();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			claimsSet);
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT iss claim has value https://other-idp.com, must be https://c2id.com", e.getMessage());
		}
	}
	
	
	public void testMissingAudience()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			null)
			.toJWTClaimsSet();
		
		Map<String, Object> jsonObject = claimsSet.toJSONObject();
		jsonObject.remove("aud");
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			JWTClaimsSet.parse(jsonObject));
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required audience", e.getMessage());
		}
	}
	
	
	public void testUnexpectedAudience()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(new ClientID("other-client-id")).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			null)
			.toJWTClaimsSet();
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			claimsSet);
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT audience rejected: [other-client-id]", e.getMessage());
		}
	}
	
	
	public void testMissingJTI()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			null)
			.toJWTClaimsSet();
		
		Map<String, Object> jsonObject = claimsSet.toJSONObject();
		jsonObject.remove("jti");
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			JWTClaimsSet.parse(jsonObject));
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [jti]", e.getMessage());
		}
	}
	
	
	public void testMissingIssueTime()
		throws Exception {
		
		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			null)
			.toJWTClaimsSet();
		
		Map<String, Object> jsonObject = claimsSet.toJSONObject();
		jsonObject.remove("iat");
		
		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			JWTClaimsSet.parse(jsonObject));
		
		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));
		
		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);
		
		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [iat]", e.getMessage());
		}
	}


	public void testMissingExpirationTime()
		throws Exception {

		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			IAT,
			EXP,
			JWTID,
			null)
			.toJWTClaimsSet();

		Map<String, Object> jsonObject = claimsSet.toJSONObject();
		jsonObject.remove("exp");

		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			JWTClaimsSet.parse(jsonObject));

		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));

		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);

		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("JWT missing required claims: [exp]", e.getMessage());
		}
	}


	public void testExpired()
		throws Exception {

		Date now = DateUtils.nowWithSecondsPrecision();
		Date twoHoursAgo = new Date(now.getTime() - 2 * 60 * 60 * 1000L);
		Date oneHoursAgo = new Date(now.getTime() - 1 * 60 * 60 * 1000L);

		JWTClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(CLIENT_ID).toSingleAudienceList(),
			twoHoursAgo,
			oneHoursAgo,
			JWTID,
			null)
			.toJWTClaimsSet();

		SignedJWT jwt = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.HS256)
				.build(),
			claimsSet);

		jwt.sign(new MACSigner(CLIENT_SECRET.getValueBytes()));

		LogoutTokenValidator validator = new LogoutTokenValidator(
			ISSUER, CLIENT_ID, JWSAlgorithm.HS256, CLIENT_SECRET
		);

		try {
			validator.validate(jwt);
			fail();
		} catch (BadJWTException e) {
			assertEquals("Expired JWT", e.getMessage());
		}
	}
	
	
	public void testStaticFactoryMethod_HS256()
		throws Exception {
		
		// Create OP metadata (based on ID_token algs)
		OIDCProviderMetadata opMetadata = IDTokenValidatorTest.createOPMetadata().getKey();
		
		// Create client registration
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setRedirectionURI(URI.create("https://example.com/cb"));
		metadata.setIDTokenJWSAlg(JWSAlgorithm.HS256);
		metadata.applyDefaults();
		
		OIDCClientInformation clientInfo = new OIDCClientInformation(new ClientID("123"), new Date(), metadata, new Secret(ByteUtils.byteLength(256)));
		
		// Create validator
		LogoutTokenValidator v = LogoutTokenValidator.create(opMetadata, clientInfo, null);
		assertEquals(opMetadata.getIssuer(), v.getExpectedIssuer());
		assertEquals(clientInfo.getID(), v.getClientID());
		assertNotNull(v.getJWSKeySelector());
		assertNull(v.getJWEKeySelector());
		
		// Check JWS key selector
		List<Key> matches = v.getJWSKeySelector().selectJWSKeys(new JWSHeader(JWSAlgorithm.HS256), null);
		assertEquals(1, matches.size());
		Assert.assertArrayEquals(clientInfo.getSecret().getValueBytes(), matches.get(0).getEncoded());
		
		matches = v.getJWSKeySelector().selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("xxx").build(), null);
		assertTrue(matches.isEmpty());
		
		
		// Create ID token
		final Date now = new Date();
		final Date inOneHour = new Date(now.getTime() + 3600*1000L);
		LogoutTokenClaimsSet claimsSet = new LogoutTokenClaimsSet(
			ISSUER,
			SUBJECT,
			new Audience(clientInfo.getID()).toSingleAudienceList(),
			now,
			inOneHour,
			JWTID,
			SESSION_ID);
		
		SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet.toJWTClaimsSet());
		idToken.sign(new MACSigner(clientInfo.getSecret().getValueBytes()));
		idToken = SignedJWT.parse(idToken.serialize());
		
		assertEquals(1, v.getJWSKeySelector().selectJWSKeys(idToken.getHeader(), null).size());
		
		// Validate
		LogoutTokenClaimsSet validated = v.validate(idToken);
		assertEquals(claimsSet.getIssuer(), validated.getIssuer());
		assertEquals(claimsSet.getSubject(), validated.getSubject());
		assertEquals(claimsSet.getAudience().get(0), validated.getAudience().get(0));
		assertEquals(1, validated.getAudience().size());
		assertEquals(claimsSet.getIssueTime(), validated.getIssueTime());
		
		// Sign logout token with invalid RSA key
		final RSAKey badKey = new RSAKeyGenerator(2048)
			.keyID("1")
			.generate();
		
		idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(badKey.getKeyID()).build(), claimsSet.toJWTClaimsSet());
		idToken.sign(new RSASSASigner(badKey));
		assertEquals(JWSObject.State.SIGNED, idToken.getState());
		
		try {
			v.validate(idToken);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Signed JWT rejected: Another algorithm expected, or no matching key(s) found", e.getMessage());
		}
		
		// Sign ID token with bad HMAC key
		idToken = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("XXXXXXX").build(), claimsSet.toJWTClaimsSet());
		idToken.sign(new MACSigner("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
		assertEquals(JWSObject.State.SIGNED, idToken.getState());
		
		try {
			v.validate(idToken);
			fail();
		} catch (BadJOSEException e) {
			assertEquals("Signed JWT rejected: Another algorithm expected, or no matching key(s) found", e.getMessage());
		}
	}
}
