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

package com.nimbusds.oauth2.sdk.util;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.http.X509CertificateGenerator;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import junit.framework.TestCase;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Assert;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Collections;
import java.util.Date;


public class X509CertificateUtilsTest extends TestCase {
	
	
	public static final RSAPublicKey RSA_PUBLIC_KEY;
	
	
	public static final RSAPrivateKey RSA_PRIVATE_KEY;
	
	
	static {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			
			RSA_PUBLIC_KEY = (RSAPublicKey)keyPair.getPublic();
			RSA_PRIVATE_KEY = (RSAPrivateKey)keyPair.getPrivate();
			
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public void testHasMatchingIssuerAndSubject_true()
		throws Exception {
		
		X509Certificate cert = X509CertificateGenerator.generateCertificate(
			new Issuer("123"),
			new Subject("123"),
			RSA_PUBLIC_KEY,
			RSA_PRIVATE_KEY);
		
		assertTrue(X509CertificateUtils.hasMatchingIssuerAndSubject(cert));
	}
	
	
	public void testHasMatchingIssuerAndSubject_false()
		throws Exception {
		
		X509Certificate cert = X509CertificateGenerator.generateCertificate(
			new Issuer("123"),
			new Subject("456"),
			RSA_PUBLIC_KEY,
			RSA_PRIVATE_KEY);
		
		assertFalse(X509CertificateUtils.hasMatchingIssuerAndSubject(cert));
	}
	
	
	public void testIsSelfIssued_positive()
		throws Exception {
		
		X509Certificate cert = X509CertificateGenerator.generateSelfSignedCertificate(
			new Issuer("123"),
			RSA_PUBLIC_KEY,
			RSA_PRIVATE_KEY
		);
		
		assertTrue(X509CertificateUtils.isSelfIssued(cert));
		assertTrue(X509CertificateUtils.isSelfSigned(cert));
	}
	
	
	public void testIsSelfIssued_negative()
		throws Exception {
		
		X509Certificate cert = X509CertificateGenerator.generateCertificate(
			new Issuer("123"),
			new Subject("456"),
			RSA_PUBLIC_KEY,
			RSA_PRIVATE_KEY
		);
		
		assertFalse(X509CertificateUtils.isSelfIssued(cert));
		assertTrue(X509CertificateUtils.isSelfSigned(cert));
	}
	
	
	public void testPublicKeyMatches()
		throws Exception {
		
		X509Certificate cert = X509CertificateGenerator.generateCertificate(
			new Issuer("123"),
			new Subject("456"),
			RSA_PUBLIC_KEY,
			RSA_PRIVATE_KEY
		);
		
		assertTrue(X509CertificateUtils.publicKeyMatches(cert, RSA_PUBLIC_KEY));
	}
	
	
	public void testPublicKeyMatches_false()
		throws Exception {
		
		X509Certificate cert = X509CertificateGenerator.generateCertificate(
			new Issuer("123"),
			new Subject("456"),
			RSA_PUBLIC_KEY,
			RSA_PRIVATE_KEY
		);
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		KeyPair keyPair = gen.generateKeyPair();
		PublicKey otherPublicKey = keyPair.getPublic();
		
		assertFalse(X509CertificateUtils.publicKeyMatches(cert, otherPublicKey));
	}
	
	
	public void testPublicKeyMatches_viaJWK()
		throws Exception {
		
		X509Certificate cert = X509CertificateGenerator.generateCertificate(
			new Issuer("123"),
			new Subject("456"),
			RSA_PUBLIC_KEY,
			RSA_PRIVATE_KEY
		);
		
		RSAKey rsaJWK = com.nimbusds.jose.jwk.RSAKey.parse(cert);
		
		assertTrue(X509CertificateUtils.publicKeyMatches(cert, rsaJWK.toPublicKey()));
	}
	
	
	public void testGenerate_signRSA()
		throws Exception {
		
		Date now = new Date();
		Date nbf = new Date(now.getTime() - 1000);
		Date exp = new Date(now.getTime() + 3600_1000);
		
		Issuer issuer = new Issuer("https://c2id.com");
		Subject subject = new Subject("123");
		
		X509Certificate cert = X509CertificateUtils.generate(issuer, subject, nbf, exp, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
		
		assertEquals("CN=" + issuer, cert.getIssuerDN().getName());
		assertEquals("CN=" + subject, cert.getSubjectDN().getName());
		
		assertEquals(DateUtils.toSecondsSinceEpoch(nbf), DateUtils.toSecondsSinceEpoch(cert.getNotBefore()));
		assertEquals(DateUtils.toSecondsSinceEpoch(exp), DateUtils.toSecondsSinceEpoch(cert.getNotAfter()));
		
		Assert.assertArrayEquals(RSA_PUBLIC_KEY.getEncoded(), cert.getPublicKey().getEncoded());
		cert.verify(RSA_PUBLIC_KEY);
	}
	
	
	public void testGenerate_signECDSA()
		throws Exception {
		
		Date now = new Date();
		Date nbf = new Date(now.getTime() - 1000);
		Date exp = new Date(now.getTime() + 3600_1000);
		
		Issuer issuer = new Issuer("https://c2id.com");
		Subject subject = new Subject("123");
		
		ECKey ecJWK = new ECKeyGenerator(Curve.P_256).generate();
		
		X509Certificate cert = X509CertificateUtils.generate(issuer, subject, nbf, exp, ecJWK.toPublicKey(), ecJWK.toECPrivateKey());
		
		assertEquals("CN=" + issuer, cert.getIssuerDN().getName());
		assertEquals("CN=" + subject, cert.getSubjectDN().getName());
		
		assertEquals(DateUtils.toSecondsSinceEpoch(nbf), DateUtils.toSecondsSinceEpoch(cert.getNotBefore()));
		assertEquals(DateUtils.toSecondsSinceEpoch(exp), DateUtils.toSecondsSinceEpoch(cert.getNotAfter()));
		
		Assert.assertArrayEquals(ecJWK.toECPublicKey().getEncoded(), cert.getPublicKey().getEncoded());
		cert.verify(ecJWK.toPublicKey());
	}
	
	
	public void testGenerateSelfSigned()
		throws Exception {
		
		Date now = new Date();
		Date nbf = new Date(now.getTime() - 1000);
		Date exp = new Date(now.getTime() + 3600_1000);
		
		Issuer issuer = new Issuer("https://c2id.com");
		
		X509Certificate cert = X509CertificateUtils.generateSelfSigned(issuer, nbf, exp, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
		
		assertEquals("CN=" + issuer, cert.getIssuerDN().getName());
		assertEquals("CN=" + issuer, cert.getSubjectDN().getName());
		
		assertEquals(DateUtils.toSecondsSinceEpoch(nbf), DateUtils.toSecondsSinceEpoch(cert.getNotBefore()));
		assertEquals(DateUtils.toSecondsSinceEpoch(exp), DateUtils.toSecondsSinceEpoch(cert.getNotAfter()));
		
		Assert.assertArrayEquals(RSA_PUBLIC_KEY.getEncoded(), cert.getPublicKey().getEncoded());
		cert.verify(RSA_PUBLIC_KEY);
	}


	public void testEntraID_addCertToJWK() throws ParseException, JOSEException, IOException, OperatorCreationException, CertificateEncodingException {

		// Parse the RSA JWK
		String jwkString =
			"{" +
			"  \"kty\" : \"RSA\"," +
			"  \"use\" : \"sig\"," +
			"  \"kid\" : \"CXup\"," +
			"  \"n\"   : \"hrwD-lc-IwzwidCANmy4qsiZk11yp9kHykOuP0yOnwi36VomYTQVEzZXgh2sDJpGgAutdQudgwLoV8tVSsTG9SQHgJjH9Pd_9V4Ab6PANyZNG6DSeiq1QfiFlEP6Obt0JbRB3W7X2vkxOVaNoWrYskZodxU2V0ogeVL_LkcCGAyNu2jdx3j0DjJatNVk7ystNxb9RfHhJGgpiIkO5S3QiSIVhbBKaJHcZHPF1vq9g0JMGuUCI-OTSVg6XBkTLEGw1C_R73WD_oVEBfdXbXnLukoLHBS11p3OxU7f4rfxA_f_72_UwmWGJnsqS3iahbms3FkvqoL9x_Vj3GhuJSf97Q\"," +
			"  \"e\"   : \"AQAB\"," +
			"  \"d\"   : \"bmpuqB4PIhJcndRs_i0jOXKjyQzwBXXq2GuWxPEsgFBYx7fFdCuGifQiytMeSEW2OQFY6W7XaqJbXneYMmoI0qTwMQcD91FNX_vlR5he0dNlpZqqYsvVN3c_oT4ENoPUr4GF6L4Jz74gBOlVsE8rvw3MVqrfmbF543ONBJPUt3d1TjKwaZQlgPji-ycGg_P7K-dKxpyfQsC8xMmVmiAF4QQtnUa9vMgiChiO8-6VzGm2yWWyIUVRLxSohrbSNFhqF2zeWXePAw0_nzeZh3IDIMS5ABo92Pry4N3X-X7v_7nf8MGngK4duQ_1UkkLk-3u0I3tk_glsarDN0tYhzPwAQ\"" +
			"}";

		RSAKey rsaJWK = RSAKey.parse(jwkString);

		// Set the validity time window of the certificate
		Date notBefore = new Date();
		Date notAfter = new Date(notBefore.getTime() + 365 * 24 * 60 * 60 * 1000L);

		// Create a self-signed certificate
		X509Certificate x509Cert = X509CertificateUtils.generate(
			new Issuer("idp.c2id.com"),
			new Subject("idp.c2id.com"),
			notBefore,
			notAfter,
			rsaJWK.toPublicKey(),
			rsaJWK.toRSAPrivateKey()
		);

		System.out.println(x509Cert.getIssuerX500Principal());
		System.out.println(x509Cert.getSubjectX500Principal());
		System.out.println(x509Cert.getNotBefore());
		System.out.println(x509Cert.getNotAfter());
		// Example output:
		// CN=idp.c2id.com
		// CN=idp.c2id.com
		// Mon May 27 12:28:39 CET 2024
		// Tue May 27 12:28:39 CET 2025

		// Add the certificate to the RSA JWK
		rsaJWK = new RSAKey.Builder(rsaJWK)
			.x509CertChain(Collections.singletonList(Base64.encode(x509Cert.getEncoded())))
			.build();

		System.out.println(rsaJWK);
	}
}
