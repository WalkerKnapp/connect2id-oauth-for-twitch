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

package com.nimbusds.oauth2.sdk.dpop;


import java.security.cert.X509Certificate;
import java.util.Map;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.X509CertificateConfirmation;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


public class JWKThumbprintConfirmationTest extends TestCase {
	
	private static final RSAKey RSA_JWK;
	
	private static final Base64URL RSA_JWK_THUMBPRINT;
	
	static {
		try {
			RSA_JWK = new RSAKeyGenerator(2048).generate();
			RSA_JWK_THUMBPRINT = RSA_JWK.computeThumbprint();
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public void testConstructor() {
		
		JWKThumbprintConfirmation cnf = new JWKThumbprintConfirmation(RSA_JWK_THUMBPRINT);
		
		assertEquals(RSA_JWK_THUMBPRINT, cnf.getValue());
	}
	
	
	public void testConstructor_rejectNull() {
		
		NullPointerException exception = null;
		try {
			new JWKThumbprintConfirmation(null);
			fail();
		} catch (NullPointerException e) {
			exception = e;
		}
		assertNull(exception.getMessage());
	}


	public void testSimpleLifeCycle() throws JOSEException, ParseException {
		
		JWKThumbprintConfirmation cnf = JWKThumbprintConfirmation.of(RSA_JWK);
		
		assertEquals(RSA_JWK_THUMBPRINT, cnf.getValue());
		
		JSONObject jsonObject = cnf.toJSONObject();
		assertEquals(1, jsonObject.size());
		JSONObject cnfObject = JSONObjectUtils.getJSONObject(jsonObject, "cnf");
		assertEquals(RSA_JWK_THUMBPRINT.toString(), JSONObjectUtils.getString(cnfObject, "jkt"));
		assertEquals(1, cnfObject.size());
		
		cnf = JWKThumbprintConfirmation.parse(jsonObject);
		
		assertEquals(RSA_JWK_THUMBPRINT, cnf.getValue());
	}
	
	public void testMergeInto()
		throws Exception {
		
		JWKThumbprintConfirmation cnf = JWKThumbprintConfirmation.of(RSA_JWK);
		
		JSONObject jsonObject = new JSONObject();
		cnf.mergeInto(jsonObject);
		JSONObject cnfObject = JSONObjectUtils.getJSONObject(jsonObject, "cnf");
		assertEquals(cnf.getValue().toString(), JSONObjectUtils.getString(cnfObject, "jkt"));
		assertEquals(1, cnfObject.size());
		assertEquals(1, jsonObject.size());
	}
	
	
	public void testMergeInto_existingMembers()
		throws Exception {
		
		JWKThumbprintConfirmation cnf = JWKThumbprintConfirmation.of(RSA_JWK);
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("a", "123");
		JSONObject cnfObject = new JSONObject();
		cnfObject.put("b", "456");
		jsonObject.put("cnf", cnfObject);
		
		cnf.mergeInto(jsonObject);
		assertEquals("123", JSONObjectUtils.getString(jsonObject, "a"));
		cnfObject = JSONObjectUtils.getJSONObject(jsonObject, "cnf");
		assertEquals(cnf.getValue().toString(), JSONObjectUtils.getString(cnfObject, "jkt"));
		assertEquals("456", JSONObjectUtils.getString(cnfObject, "b"));
		assertEquals(2, cnfObject.size());
		assertEquals(2, jsonObject.size());
	}
	
	
	public void testCnfEntryMethods() throws JOSEException, ParseException {
		
		JWKThumbprintConfirmation cnf = JWKThumbprintConfirmation.of(RSA_JWK);
		
		Map.Entry<String,JSONObject> entry = cnf.toJWTClaim();
		assertEquals("cnf", entry.getKey());
		JSONObject cnfObject = entry.getValue();
		assertEquals(RSA_JWK_THUMBPRINT.toString(), JSONObjectUtils.getString(cnfObject, "jkt"));
		assertEquals(1, cnfObject.size());
		
		cnf = JWKThumbprintConfirmation.parseFromConfirmationJSONObject(cnfObject);
		
		assertEquals(RSA_JWK_THUMBPRINT, cnf.getValue());
	}
	
	
	public void testEqualityAndHashCode() {
		
		assertEquals(new JWKThumbprintConfirmation(RSA_JWK_THUMBPRINT), new JWKThumbprintConfirmation(RSA_JWK_THUMBPRINT));
		assertEquals(new JWKThumbprintConfirmation(RSA_JWK_THUMBPRINT).hashCode(), new JWKThumbprintConfirmation(RSA_JWK_THUMBPRINT).hashCode());
	}
	
	
	public void testInequalityAndHashCode() {
		
		Base64URL jkt = new Base64URL("abc");
		
		assertNotSame(new JWKThumbprintConfirmation(jkt), new JWKThumbprintConfirmation(RSA_JWK_THUMBPRINT));
		assertNotSame(new JWKThumbprintConfirmation(jkt).hashCode(), new JWKThumbprintConfirmation(RSA_JWK_THUMBPRINT).hashCode());
	}
	
	
	public void testJWTClaimsSetMethods() throws java.text.ParseException, ParseException {
		
		JWKThumbprintConfirmation cnf = new JWKThumbprintConfirmation(RSA_JWK_THUMBPRINT);
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();
		
		JWTClaimsSet updated = cnf.applyTo(claimsSet);
		
		assertEquals("alice", updated.getSubject());
		
		JSONObject cnfObject = new JSONObject(updated.getJSONObjectClaim("cnf"));
		assertEquals(RSA_JWK_THUMBPRINT.toString(), JSONObjectUtils.getString(cnfObject, "jkt"));
		assertEquals(1, cnfObject.size());
		assertEquals(2, updated.getClaims().size());
		
		JWKThumbprintConfirmation parsed = JWKThumbprintConfirmation.parse(updated);
		
		assertEquals(cnf, parsed);
	}
	
	
	public void testParseFromJSONObject_noCnf() {
		
		assertNull(JWKThumbprintConfirmation.parse(new JSONObject()));
	}
	
	
	public void testParseFromJSONObject_invalidJSONEntityType() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("cnf", "string");
		
		assertNull(JWKThumbprintConfirmation.parse(jsonObject));
	}
	
	
	public void testParseFromConfirmationJSONObject_noKty() {
		
		assertNull(JWKThumbprintConfirmation.parseFromConfirmationJSONObject(new JSONObject()));
	}
	
	
	public void testParseFromConfirmationJSONObject_invalidJSONEntityType() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("jkt", 10000L);
		
		assertNull(JWKThumbprintConfirmation.parseFromConfirmationJSONObject(jsonObject));
	}
}
