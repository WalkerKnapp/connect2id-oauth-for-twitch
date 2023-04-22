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

package com.nimbusds.oauth2.sdk.auth;


import java.security.cert.X509Certificate;
import java.util.Map;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


public class X509CertificateConfirmationTest extends TestCase {
	
	
	private static final String PEM_CERT = "-----BEGIN CERTIFICATE-----" +
		"MIICUTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBXMQswCQYDVQQGEwJDTjEL" +
		"MAkGA1UECBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMC" +
		"VU4xFDASBgNVBAMTC0hlcm9uZyBZYW5nMB4XDTA1MDcxNTIxMTk0N1oXDTA1MDgx" +
		"NDIxMTk0N1owVzELMAkGA1UEBhMCQ04xCzAJBgNVBAgTAlBOMQswCQYDVQQHEwJD" +
		"TjELMAkGA1UEChMCT04xCzAJBgNVBAsTAlVOMRQwEgYDVQQDEwtIZXJvbmcgWWFu" +
		"ZzBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCp5hnG7ogBhtlynpOS21cBewKE/B7j" +
		"V14qeyslnr26xZUsSVko36ZnhiaO/zbMOoRcKK9vEcgMtcLFuQTWDl3RAgMBAAGj" +
		"gbEwga4wHQYDVR0OBBYEFFXI70krXeQDxZgbaCQoR4jUDncEMH8GA1UdIwR4MHaA" +
		"FFXI70krXeQDxZgbaCQoR4jUDncEoVukWTBXMQswCQYDVQQGEwJDTjELMAkGA1UE" +
		"CBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMCVU4xFDAS" +
		"BgNVBAMTC0hlcm9uZyBZYW5nggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEE" +
		"BQADQQA/ugzBrjjK9jcWnDVfGHlk3icNRq0oV7Ri32z/+HQX67aRfgZu7KWdI+Ju" +
		"Wm7DCfrPNGVwFWUQOmsPue9rZBgO" +
		"-----END CERTIFICATE-----";
	
	
	public void testLifeCycle()
		throws Exception {
		
		X509Certificate clientCert = X509CertUtils.parse(PEM_CERT);
		
		Base64URL x5t = X509CertUtils.computeSHA256Thumbprint(clientCert);
		assertEquals(256, ByteUtils.bitLength(x5t.decode()));
		
		X509CertificateConfirmation certCnf = new X509CertificateConfirmation(x5t);
		
		assertEquals(x5t, certCnf.getValue());
		
		JSONObject jsonObject = certCnf.toJSONObject();
		JSONObject cnfObject = JSONObjectUtils.getJSONObject(jsonObject, "cnf");
		assertEquals(x5t.toString(), JSONObjectUtils.getString(cnfObject, "x5t#S256"));
		assertEquals(1, cnfObject.size());
		assertEquals(1, jsonObject.size());
		
		certCnf = X509CertificateConfirmation.parse(JWTClaimsSet.parse(jsonObject));
		assertEquals(x5t, certCnf.getValue());
	}
	
	
	public void testMergeInto()
		throws Exception {
		
		X509Certificate clientCert = X509CertUtils.parse(PEM_CERT);
		Base64URL x5t = X509CertUtils.computeSHA256Thumbprint(clientCert);
		X509CertificateConfirmation certCnf = new X509CertificateConfirmation(x5t);
		
		JSONObject jsonObject = new JSONObject();
		certCnf.mergeInto(jsonObject);
		JSONObject cnfObject = JSONObjectUtils.getJSONObject(jsonObject, "cnf");
		assertEquals(x5t.toString(), JSONObjectUtils.getString(cnfObject, "x5t#S256"));
		assertEquals(1, cnfObject.size());
		assertEquals(1, jsonObject.size());
	}
	
	
	public void testMergeInto_existingMembers()
		throws Exception {
		
		X509Certificate clientCert = X509CertUtils.parse(PEM_CERT);
		Base64URL x5t = X509CertUtils.computeSHA256Thumbprint(clientCert);
		X509CertificateConfirmation certCnf = new X509CertificateConfirmation(x5t);
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("a", "123");
		JSONObject cnf = new JSONObject();
		cnf.put("b", "456");
		jsonObject.put("cnf", cnf);
		
		certCnf.mergeInto(jsonObject);
		assertEquals("123", JSONObjectUtils.getString(jsonObject, "a"));
		JSONObject cnfObject = JSONObjectUtils.getJSONObject(jsonObject, "cnf");
		assertEquals(x5t.toString(), JSONObjectUtils.getString(cnfObject, "x5t#S256"));
		assertEquals("456", JSONObjectUtils.getString(cnfObject, "b"));
		assertEquals(2, cnfObject.size());
		assertEquals(2, jsonObject.size());
	}
	
	
	public void testOf()
		throws Exception {
		
		X509Certificate clientCert = X509CertUtils.parse(PEM_CERT);
		
		Base64URL x5t = X509CertUtils.computeSHA256Thumbprint(clientCert);
		assertEquals(256, ByteUtils.bitLength(x5t.decode()));
		
		X509CertificateConfirmation certCnf = X509CertificateConfirmation.of(clientCert);
		
		JSONObject jsonObject = certCnf.toJSONObject();
		JSONObject cnfObject = JSONObjectUtils.getJSONObject(jsonObject, "cnf");
		assertEquals(x5t.toString(), JSONObjectUtils.getString(cnfObject, "x5t#S256"));
		assertEquals(1, cnfObject.size());
		assertEquals(1, jsonObject.size());
	}
	
	
	public void testApplyToJWTClaimsSet()
		throws Exception {
		
		X509Certificate clientCert = X509CertUtils.parse(PEM_CERT);
		
		X509CertificateConfirmation certCnf = X509CertificateConfirmation.of(clientCert);
		
		JWTClaimsSet jwtClaimsSet = certCnf.applyTo(new JWTClaimsSet.Builder().build());
		
		Map<String, Object> cnfObject = jwtClaimsSet.getJSONObjectClaim("cnf");
		assertEquals(certCnf.getValue().toString(), com.nimbusds.jose.util.JSONObjectUtils.getString(cnfObject, "x5t#S256"));
		
		assertEquals(1, jwtClaimsSet.getClaims().size());
	}
	
	
	public void testRejectNullArg() {
		
		try {
			new X509CertificateConfirmation(null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The X.509 certificate thumbprint must not be null", e.getMessage());
		}
	}
	
	
	public void testParse_nullJWTClaimsSet() {
		
		try {
			X509CertificateConfirmation.parse((JWTClaimsSet) null);
			fail();
		} catch (NullPointerException e) {
			// ok
		}
	}
	
	
	public void testParse_nullJSONObject() {
		
		try {
			X509CertificateConfirmation.parse((JSONObject)null);
			fail();
		} catch (NullPointerException e) {
			// ok;
		}
	}
	
	
	public void testParseClaimsSet()
		throws Exception {
		
		String json = "{\n" +
			"       \"iss\": \"https://server.example.com\",\n" +
			"       \"sub\": \"ty.webb@example.com\",\n" +
			"       \"exp\": 1493726400,\n" +
			"       \"nbf\": 1493722800,\n" +
			"       \"cnf\":{\n" +
			"         \"x5t#S256\": \"bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2\"\n" +
			"       }\n" +
			"     }";
		
		assertEquals(new Base64URL("bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"), X509CertificateConfirmation.parse(JWTClaimsSet.parse(json)).getValue());
		
		assertEquals(new Base64URL("bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"), X509CertificateConfirmation.parse(JSONObjectUtils.parse(json)).getValue());
	}
	
	
	public void testParseX5TMissing()
		throws Exception {
		
		String json = "{\n" +
			"       \"iss\": \"https://server.example.com\",\n" +
			"       \"sub\": \"ty.webb@example.com\",\n" +
			"       \"exp\": 1493726400,\n" +
			"       \"nbf\": 1493722800,\n" +
			"       \"cnf\":{\n" +
			"       }\n" +
			"     }";
		
		assertNull(X509CertificateConfirmation.parse(JWTClaimsSet.parse(json)));
		
		assertNull(X509CertificateConfirmation.parse(JSONObjectUtils.parse(json)));
	}
	
	
	public void testToString() {
		
		assertEquals(
			"{\"cnf\":{\"x5t#S256\":\"bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2\"}}",
			new X509CertificateConfirmation(new Base64URL("bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2")).toString());
	}
}
