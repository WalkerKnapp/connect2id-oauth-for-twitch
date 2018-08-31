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


import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import com.nimbusds.oauth2.sdk.ParseException;
import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;

import com.nimbusds.oauth2.sdk.id.ClientID;


/**
 * Tests the private key JWT authentication class.
 */
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


	public void testWithRS256()
		throws Exception {

		ClientID clientID = new ClientID("123");
		URI tokenEndpoint = new URI("https://c2id.com/token");

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		KeyPair pair = keyGen.generateKeyPair();
		RSAPrivateKey priv = (RSAPrivateKey)pair.getPrivate();
		RSAPublicKey pub = (RSAPublicKey)pair.getPublic();

		PrivateKeyJWT privateKeyJWT = new PrivateKeyJWT(clientID, tokenEndpoint, JWSAlgorithm.RS256, priv, null, null);

		privateKeyJWT = PrivateKeyJWT.parse(privateKeyJWT.toParameters());

		assertTrue(privateKeyJWT.getClientAssertion().verify(new RSASSAVerifier(pub)));

		assertEquals(clientID, privateKeyJWT.getJWTAuthenticationClaimsSet().getClientID());
		assertEquals(clientID.getValue(), privateKeyJWT.getJWTAuthenticationClaimsSet().getIssuer().getValue());
		assertEquals(clientID.getValue(), privateKeyJWT.getJWTAuthenticationClaimsSet().getSubject().getValue());
		assertEquals(tokenEndpoint.toString(), privateKeyJWT.getJWTAuthenticationClaimsSet().getAudience().get(0).getValue());

		// 4 min < exp < 6 min
		final long now = new Date().getTime();
		final Date fourMinutesFromNow = new Date(now + 4*60*1000l);
		final Date sixMinutesFromNow = new Date(now + 6*60*1000l);
		assertTrue(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().after(fourMinutesFromNow));
		assertTrue(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().before(sixMinutesFromNow));
		assertNotNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getJWTID());
		assertNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getIssueTime());
		assertNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getNotBeforeTime());
	}


	public void testWithRS256AndKeyID()
		throws Exception {

		ClientID clientID = new ClientID("123");
		URI tokenEndpoint = new URI("https://c2id.com/token");

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		KeyPair pair = keyGen.generateKeyPair();
		RSAPrivateKey priv = (RSAPrivateKey)pair.getPrivate();
		RSAPublicKey pub = (RSAPublicKey)pair.getPublic();

		PrivateKeyJWT privateKeyJWT = new PrivateKeyJWT(clientID, tokenEndpoint, JWSAlgorithm.RS256, priv, "1", null);
		assertEquals("1", privateKeyJWT.getClientAssertion().getHeader().getKeyID());

		privateKeyJWT = PrivateKeyJWT.parse(privateKeyJWT.toParameters());

		assertEquals("1", privateKeyJWT.getClientAssertion().getHeader().getKeyID());

		assertTrue(privateKeyJWT.getClientAssertion().verify(new RSASSAVerifier(pub)));

		assertEquals(clientID, privateKeyJWT.getJWTAuthenticationClaimsSet().getClientID());
		assertEquals(clientID.getValue(), privateKeyJWT.getJWTAuthenticationClaimsSet().getIssuer().getValue());
		assertEquals(clientID.getValue(), privateKeyJWT.getJWTAuthenticationClaimsSet().getSubject().getValue());
		assertEquals(tokenEndpoint.toString(), privateKeyJWT.getJWTAuthenticationClaimsSet().getAudience().get(0).getValue());

		// 4 min < exp < 6 min
		final long now = new Date().getTime();
		final Date fourMinutesFromNow = new Date(now + 4*60*1000l);
		final Date sixMinutesFromNow = new Date(now + 6*60*1000l);
		assertTrue(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().after(fourMinutesFromNow));
		assertTrue(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().before(sixMinutesFromNow));
		assertNotNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getJWTID());
		assertNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getIssueTime());
		assertNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getNotBeforeTime());
	}


	public void testWithES256()
		throws Exception {

		ClientID clientID = new ClientID("123");
		URI tokenEndpoint = new URI("https://c2id.com/token");

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
		KeyPair pair = keyGen.generateKeyPair();
		ECPrivateKey priv = (ECPrivateKey)pair.getPrivate();
		ECPublicKey pub = (ECPublicKey)pair.getPublic();

		PrivateKeyJWT privateKeyJWT = new PrivateKeyJWT(clientID, tokenEndpoint, JWSAlgorithm.ES256, priv, null, null);

		privateKeyJWT = PrivateKeyJWT.parse(privateKeyJWT.toParameters());

		assertTrue(privateKeyJWT.getClientAssertion().verify(new ECDSAVerifier(pub)));

		assertEquals(clientID, privateKeyJWT.getJWTAuthenticationClaimsSet().getClientID());
		assertEquals(clientID.getValue(), privateKeyJWT.getJWTAuthenticationClaimsSet().getIssuer().getValue());
		assertEquals(clientID.getValue(), privateKeyJWT.getJWTAuthenticationClaimsSet().getSubject().getValue());
		assertEquals(tokenEndpoint.toString(), privateKeyJWT.getJWTAuthenticationClaimsSet().getAudience().get(0).getValue());

		// 4 min < exp < 6 min
		final long now = new Date().getTime();
		final Date fourMinutesFromNow = new Date(now + 4*60*1000l);
		final Date sixMinutesFromNow = new Date(now + 6*60*1000l);
		assertTrue(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().after(fourMinutesFromNow));
		assertTrue(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().before(sixMinutesFromNow));
		assertNotNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getJWTID());
		assertNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getIssueTime());
		assertNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getNotBeforeTime());
	}


	public void testWithES256AndKeyID()
		throws Exception {

		ClientID clientID = new ClientID("123");
		URI tokenEndpoint = new URI("https://c2id.com/token");

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
		KeyPair pair = keyGen.generateKeyPair();
		ECPrivateKey priv = (ECPrivateKey)pair.getPrivate();
		ECPublicKey pub = (ECPublicKey)pair.getPublic();

		PrivateKeyJWT privateKeyJWT = new PrivateKeyJWT(clientID, tokenEndpoint, JWSAlgorithm.ES256, priv, "1", null);
		assertEquals("1", privateKeyJWT.getClientAssertion().getHeader().getKeyID());

		privateKeyJWT = PrivateKeyJWT.parse(privateKeyJWT.toParameters());

		assertEquals("1", privateKeyJWT.getClientAssertion().getHeader().getKeyID());

		assertTrue(privateKeyJWT.getClientAssertion().verify(new ECDSAVerifier(pub)));

		assertEquals(clientID, privateKeyJWT.getJWTAuthenticationClaimsSet().getClientID());
		assertEquals(clientID.getValue(), privateKeyJWT.getJWTAuthenticationClaimsSet().getIssuer().getValue());
		assertEquals(clientID.getValue(), privateKeyJWT.getJWTAuthenticationClaimsSet().getSubject().getValue());
		assertEquals(tokenEndpoint.toString(), privateKeyJWT.getJWTAuthenticationClaimsSet().getAudience().get(0).getValue());

		// 4 min < exp < 6 min
		final long now = new Date().getTime();
		final Date fourMinutesFromNow = new Date(now + 4*60*1000l);
		final Date sixMinutesFromNow = new Date(now + 6*60*1000l);
		assertTrue(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().after(fourMinutesFromNow));
		assertTrue(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().before(sixMinutesFromNow));
		assertNotNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getJWTID());
		assertNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getIssueTime());
		assertNull(privateKeyJWT.getJWTAuthenticationClaimsSet().getNotBeforeTime());
	}
	
	
	public void testParse_clientIDMismatch()
		throws Exception {
		
		ClientID clientID = new ClientID("123");
		URI tokenEndpoint = new URI("https://c2id.com/token");
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		KeyPair pair = keyGen.generateKeyPair();
		RSAPrivateKey priv = (RSAPrivateKey)pair.getPrivate();
		RSAPublicKey pub = (RSAPublicKey)pair.getPublic();
		
		PrivateKeyJWT privateKeyJWT = new PrivateKeyJWT(clientID, tokenEndpoint, JWSAlgorithm.RS256, priv, null, null);
		
		Map<String,List<String>> params = privateKeyJWT.toParameters();
		
		assertNull(params.get("client_id"));
		
		params.put("client_id", Collections.singletonList("456")); // different client_id
		
		try {
			PrivateKeyJWT.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid private key JWT authentication: The client identifier doesn't match the client assertion subject / issuer", e.getMessage());
		}
		
	}
}
