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


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils;
import junit.framework.TestCase;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;


public class PrivateKeyJWTTest extends TestCase {


	public void testSupportedJWAs() {

		Set<JWSAlgorithm> algs = PrivateKeyJWT.supportedJWAs();

		assertTrue(algs.contains(JWSAlgorithm.RS256));
		assertTrue(algs.contains(JWSAlgorithm.RS384));
		assertTrue(algs.contains(JWSAlgorithm.RS512));
		assertTrue(algs.contains(JWSAlgorithm.PS256));
		assertTrue(algs.contains(JWSAlgorithm.PS384));
		assertTrue(algs.contains(JWSAlgorithm.PS512));
		assertTrue(algs.contains(JWSAlgorithm.ES256));
		assertTrue(algs.contains(JWSAlgorithm.ES256K));
		assertTrue(algs.contains(JWSAlgorithm.ES384));
		assertTrue(algs.contains(JWSAlgorithm.ES512));
		assertEquals(10, algs.size());
	}


	public void testWithRSA()
		throws Exception {

		Issuer iss = new Issuer("https://sts.c2id.com");
		ClientID clientID = new ClientID("123");
		URI opIssuerURL = new URI("https://server.c2id.com");
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.generate();
		
		PrivateKey priv = rsaJWK.toRSAPrivateKey();
		RSAPublicKey pub = rsaJWK.toRSAPublicKey();

		for (JWSAlgorithm alg: JWSAlgorithm.Family.RSA) {
			
			for (boolean issAndSubSame: Arrays.asList(true, false)) {
				
				PrivateKeyJWT privateKeyJWT;
				if (issAndSubSame) {
					privateKeyJWT = new PrivateKeyJWT(clientID, opIssuerURL, alg, priv, null, null);
				} else {
					privateKeyJWT = new PrivateKeyJWT(iss, clientID, opIssuerURL, alg, priv, null, null);
				}
				
				assertEquals(new HashSet<>(Arrays.asList("client_id", "client_assertion", "client_assertion_type")), privateKeyJWT.getFormParameterNames());
				
				privateKeyJWT = PrivateKeyJWT.parse(privateKeyJWT.toParameters());
				
				assertEquals(alg, privateKeyJWT.getClientAssertion().getHeader().getAlgorithm());
				
				assertTrue(privateKeyJWT.getClientAssertion().verify(new RSASSAVerifier(pub)));
				
				assertEquals(clientID, privateKeyJWT.getJWTAuthenticationClaimsSet().getClientID());
				if (issAndSubSame) {
					assertEquals(clientID.getValue(), privateKeyJWT.getJWTAuthenticationClaimsSet().getIssuer().getValue());
				} else {
					assertEquals(iss, privateKeyJWT.getJWTAuthenticationClaimsSet().getIssuer());
				}
				assertEquals(clientID.getValue(), privateKeyJWT.getJWTAuthenticationClaimsSet().getSubject().getValue());
				assertEquals(opIssuerURL.toString(), privateKeyJWT.getJWTAuthenticationClaimsSet().getAudience().get(0).getValue());

				// 55s < exp < 65s
				final long now = new Date().getTime();
				final Date minFromNow = new Date(now + 55_000L);
				final Date maxFromNow = new Date(now + 65_000L);
				assertTrue(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().after(minFromNow));
				assertTrue(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().before(maxFromNow));
				assertNotNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getJWTID());
				assertNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getIssueTime());
				assertNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getNotBeforeTime());
				
			}
		}
	}


	public void testWithRSA_multipleKeyParams()
		throws Exception {

		Issuer iss = new Issuer("https://sts.c2id.com");
		ClientID clientID = new ClientID("123");
		URI opIssuerURL = new URI("https://server.c2id.com");
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.keyID("1")
			.generate();
		
		PrivateKey priv = rsaJWK.toRSAPrivateKey();
		RSAPublicKey pub = rsaJWK.toRSAPublicKey();
		
		Date now = new Date();
		Date oneDayAgo = new Date(now.getTime() - 1000*60*60*24);
		Date oneDayAhead = new Date(now.getTime() + 1000*60*60*24);
		
		X509Certificate cert = X509CertificateUtils.generate(
			new Issuer("https://ca.example.com"),
			new Subject(clientID.getValue()),
			oneDayAgo,
			oneDayAhead,
			rsaJWK.toRSAPublicKey(),
			rsaJWK.toPrivateKey());
		
		List<com.nimbusds.jose.util.Base64> x5c = Collections.singletonList(Base64.encode(cert.getEncoded()));
		
		Base64URL x5t256 = X509CertUtils.computeSHA256Thumbprint(cert);
		
		for (boolean issAndSubSame: Arrays.asList(true, false)) {
			
			PrivateKeyJWT privateKeyJWT;
			
			if (issAndSubSame) {
				privateKeyJWT = new PrivateKeyJWT(clientID, opIssuerURL, JWSAlgorithm.RS256, priv, rsaJWK.getKeyID(), x5c, x5t256, null);
			} else {
				privateKeyJWT = new PrivateKeyJWT(iss, clientID, opIssuerURL, JWSAlgorithm.RS256, priv, rsaJWK.getKeyID(), x5c, x5t256, null);
			}
			
			assertEquals(JWSAlgorithm.RS256, privateKeyJWT.getClientAssertion().getHeader().getAlgorithm());
			assertEquals(rsaJWK.getKeyID(), privateKeyJWT.getClientAssertion().getHeader().getKeyID());
			assertEquals(x5c, privateKeyJWT.getClientAssertion().getHeader().getX509CertChain());
			assertEquals(x5t256, privateKeyJWT.getClientAssertion().getHeader().getX509CertSHA256Thumbprint());
			assertEquals(4, privateKeyJWT.getClientAssertion().getHeader().getIncludedParams().size());
			
			privateKeyJWT = PrivateKeyJWT.parse(privateKeyJWT.toParameters());
			
			assertEquals(JWSAlgorithm.RS256, privateKeyJWT.getClientAssertion().getHeader().getAlgorithm());
			assertEquals(rsaJWK.getKeyID(), privateKeyJWT.getClientAssertion().getHeader().getKeyID());
			assertEquals(x5c, privateKeyJWT.getClientAssertion().getHeader().getX509CertChain());
			assertEquals(x5t256, privateKeyJWT.getClientAssertion().getHeader().getX509CertSHA256Thumbprint());
			assertEquals(4, privateKeyJWT.getClientAssertion().getHeader().getIncludedParams().size());
			
			assertTrue(privateKeyJWT.getClientAssertion().verify(new RSASSAVerifier(pub)));
			
			if (issAndSubSame) {
				assertEquals(clientID.getValue(), privateKeyJWT.getJWTAuthenticationClaimsSet().getIssuer().getValue());
			} else {
				assertEquals(iss, privateKeyJWT.getJWTAuthenticationClaimsSet().getIssuer());
			}
			assertEquals(clientID, privateKeyJWT.getJWTAuthenticationClaimsSet().getClientID());
			assertEquals(clientID.getValue(), privateKeyJWT.getJWTAuthenticationClaimsSet().getSubject().getValue());
			assertEquals(opIssuerURL.toString(), privateKeyJWT.getJWTAuthenticationClaimsSet().getAudience().get(0).getValue());
			
			// 55s < exp < 65s
			final Date minFromNow = new Date(now.getTime() + 55_000L);
			final Date maxFromNow = new Date(now.getTime() + 65_000L);
			assertTrue(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().after(minFromNow));
			assertTrue(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().before(maxFromNow));
			assertNotNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getJWTID());
			assertNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getIssueTime());
			assertNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getNotBeforeTime());
		}
	}


	public void testUnsupportedAlg()
		throws Exception {

		ClientID clientID = new ClientID("123");
		URI opIssuerURL = new URI("https://server.c2id.com");
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.keyID("1")
			.generate();
		
		PrivateKey priv = rsaJWK.toRSAPrivateKey();
		
		Date now = new Date();
		Date oneDayAgo = new Date(now.getTime() - 1000*60*60*24);
		Date oneDayAhead = new Date(now.getTime() + 1000*60*60*24);
		
		X509Certificate cert = X509CertificateUtils.generate(
			new Issuer("https://ca.example.com"),
			new Subject(clientID.getValue()),
			oneDayAgo,
			oneDayAhead,
			rsaJWK.toRSAPublicKey(),
			rsaJWK.toPrivateKey());
		
		List<com.nimbusds.jose.util.Base64> x5c = Collections.singletonList(Base64.encode(cert.getEncoded()));
		
		Base64URL x5t256 = X509CertUtils.computeSHA256Thumbprint(cert);

		try {
			new PrivateKeyJWT(clientID, opIssuerURL, new JWSAlgorithm("xxx"), priv, rsaJWK.getKeyID(), x5c, x5t256, null);
			fail();
		} catch (JOSEException e) {
			assertEquals("Unsupported JWS algorithm: xxx", e.getMessage());
		}
	}


	public void testWithES256_deprecated()
		throws Exception {

		ClientID clientID = new ClientID("123");
		URI opIssuerURL = new URI("https://server.c2id.com");

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
		KeyPair pair = keyGen.generateKeyPair();
		ECPrivateKey priv = (ECPrivateKey)pair.getPrivate();
		ECPublicKey pub = (ECPublicKey)pair.getPublic();

		PrivateKeyJWT privateKeyJWT = new PrivateKeyJWT(clientID, opIssuerURL, JWSAlgorithm.ES256, priv, null, null);

		privateKeyJWT = PrivateKeyJWT.parse(privateKeyJWT.toParameters());

		assertTrue(privateKeyJWT.getClientAssertion().verify(new ECDSAVerifier(pub)));

		assertEquals(clientID, privateKeyJWT.getJWTAuthenticationClaimsSet().getClientID());
		assertEquals(clientID.getValue(), privateKeyJWT.getJWTAuthenticationClaimsSet().getIssuer().getValue());
		assertEquals(clientID.getValue(), privateKeyJWT.getJWTAuthenticationClaimsSet().getSubject().getValue());
		assertEquals(opIssuerURL.toString(), privateKeyJWT.getJWTAuthenticationClaimsSet().getAudience().get(0).getValue());

		// 55s < exp < 65s
		final long now = new Date().getTime();
		final Date minFromNow = new Date(now + 55_000L);
		final Date maxFromNow = new Date(now + 65_000L);
		assertTrue(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().after(minFromNow));
		assertTrue(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().before(maxFromNow));
		assertNotNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getJWTID());
		assertNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getIssueTime());
		assertNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getNotBeforeTime());
	}


	public void testWithES256AndKeyID_deprecated()
		throws Exception {

		ClientID clientID = new ClientID("123");
		URI opIssuerURL = new URI("https://server.c2id.com");

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
		KeyPair pair = keyGen.generateKeyPair();
		ECPrivateKey priv = (ECPrivateKey)pair.getPrivate();
		ECPublicKey pub = (ECPublicKey)pair.getPublic();

		PrivateKeyJWT privateKeyJWT = new PrivateKeyJWT(clientID, opIssuerURL, JWSAlgorithm.ES256, priv, "1", null);
		assertEquals("1", privateKeyJWT.getClientAssertion().getHeader().getKeyID());

		privateKeyJWT = PrivateKeyJWT.parse(privateKeyJWT.toParameters());

		assertEquals("1", privateKeyJWT.getClientAssertion().getHeader().getKeyID());

		assertTrue(privateKeyJWT.getClientAssertion().verify(new ECDSAVerifier(pub)));

		assertEquals(clientID, privateKeyJWT.getJWTAuthenticationClaimsSet().getClientID());
		assertEquals(clientID.getValue(), privateKeyJWT.getJWTAuthenticationClaimsSet().getIssuer().getValue());
		assertEquals(clientID.getValue(), privateKeyJWT.getJWTAuthenticationClaimsSet().getSubject().getValue());
		assertEquals(opIssuerURL.toString(), privateKeyJWT.getJWTAuthenticationClaimsSet().getAudience().get(0).getValue());

		// 55s < exp < 65s
		final long now = new Date().getTime();
		final Date minFromNow = new Date(now + 55_000L);
		final Date maxFromNow = new Date(now + 65_000L);
		assertTrue(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().after(minFromNow));
		assertTrue(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().before(maxFromNow));
		assertNotNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getJWTID());
		assertNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getIssueTime());
		assertNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getNotBeforeTime());
	}
	
	
	public void testParse_clientIDMismatch()
		throws Exception {
		
		ClientID clientID = new ClientID("123");
		URI opIssuerURL = new URI("https://server.c2id.com");
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		KeyPair pair = keyGen.generateKeyPair();
		PrivateKey priv = pair.getPrivate();
		
		PrivateKeyJWT privateKeyJWT = new PrivateKeyJWT(clientID, opIssuerURL, JWSAlgorithm.RS256, priv, null, null);
		
		Map<String,List<String>> params = privateKeyJWT.toParameters();
		
		assertNull(params.get("client_id"));
		
		params.put("client_id", Collections.singletonList("456")); // different client_id
		
		try {
			PrivateKeyJWT.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid private key JWT authentication: The client identifier doesn't match the client assertion subject", e.getMessage());
		}
	}
}
