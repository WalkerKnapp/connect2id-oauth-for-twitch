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
import java.util.*;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;


/**
 * Tests the client secret JWT authentication class.
 */
public class ClientSecretJWTTest extends TestCase {


	public void testSupportedJWAs() {

		Set<JWSAlgorithm> algs = ClientSecretJWT.supportedJWAs();

		assertTrue(algs.contains(JWSAlgorithm.HS256));
		assertTrue(algs.contains(JWSAlgorithm.HS384));
		assertTrue(algs.contains(JWSAlgorithm.HS512));
		assertEquals(3, algs.size());
	}


	public void testLifeCycle()
		throws Exception {
		
		Issuer iss = new Issuer("https://sts.c2id.com");
		ClientID clientID = new ClientID("https://client.com");
		Audience audience = new Audience("https://server.c2id.com");
		Date exp = DateUtils.fromSecondsSinceEpoch(new Date().getTime() / 1000 + 3600);
		Date nbf = DateUtils.fromSecondsSinceEpoch(new Date().getTime() / 1000);
		Date iat = DateUtils.fromSecondsSinceEpoch(new Date().getTime() / 1000);
		JWTID jti = new JWTID();

		for (boolean issAndSubSame: Arrays.asList(true, false)) {
			
			JWTAuthenticationClaimsSet assertion;
			
			if (issAndSubSame) {
				assertion = new JWTAuthenticationClaimsSet(clientID, audience.toSingleAudienceList(), exp, nbf, iat, jti);
			} else {
				assertion = new JWTAuthenticationClaimsSet(iss, clientID, audience.toSingleAudienceList(), exp, nbf, iat, jti);
			}
			
			JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);
			
			SignedJWT jwt = new SignedJWT(jwsHeader, assertion.toJWTClaimsSet());
			
			Secret secret = new Secret();
			
			MACSigner signer = new MACSigner(secret.getValueBytes());
			
			jwt.sign(signer);
			
			ClientSecretJWT clientSecretJWT = new ClientSecretJWT(jwt);
			
			Map<String, List<String>> params = clientSecretJWT.toParameters();
			params.put("client_id", Collections.singletonList(clientID.getValue())); // add optional client_id to test parser
			
			clientSecretJWT = ClientSecretJWT.parse(params);
			
			assertEquals("https://client.com", clientSecretJWT.getClientID().getValue());
			
			jwt = clientSecretJWT.getClientAssertion();
			
			assertEquals(jwt.getState(), JWSObject.State.SIGNED);
			
			MACVerifier verifier = new MACVerifier(secret.getValueBytes());
			
			boolean verified = jwt.verify(verifier);
			
			assertTrue(verified);
			
			assertion = clientSecretJWT.getJWTAuthenticationClaimsSet();
			
			if (issAndSubSame) {
				assertEquals(clientID.getValue(), assertion.getIssuer().getValue());
			} else {
				assertEquals(iss, assertion.getIssuer());
			}
			
			assertEquals(clientID.getValue(), assertion.getClientID().getValue());
			assertEquals(clientID.getValue(), assertion.getSubject().getValue());
			assertEquals(audience.getValue(), assertion.getAudience().get(0).getValue());
			assertEquals(exp.getTime(), assertion.getExpirationTime().getTime());
			assertEquals(nbf.getTime(), assertion.getNotBeforeTime().getTime());
			assertEquals(iat.getTime(), assertion.getIssueTime().getTime());
			assertEquals(jti.getValue(), assertion.getJWTID().getValue());
		}
	}


	public void testWithJWTHelper()
		throws Exception {
		
		Issuer iss = new Issuer("https://sts.c2id.com");
		ClientID clientID = new ClientID("123");
		URI opIssuerURL = new URI("https://server.c2id.com");
		Secret secret = new Secret(256 / 8); // generate 256 bit secret
		
		for (boolean issAndSubSame: Arrays.asList(true, false)) {
			
			ClientSecretJWT clientSecretJWT;
			if (issAndSubSame) {
				clientSecretJWT = new ClientSecretJWT(clientID, opIssuerURL, JWSAlgorithm.HS256, secret);
			} else {
				clientSecretJWT = new ClientSecretJWT(iss, clientID, opIssuerURL, JWSAlgorithm.HS256, secret);
			}
			
			clientSecretJWT = ClientSecretJWT.parse(clientSecretJWT.toParameters());
			
			assertTrue(clientSecretJWT.getClientAssertion().verify(new MACVerifier(secret.getValueBytes())));
			
			if (issAndSubSame) {
				assertEquals(clientID.getValue(), clientSecretJWT.getJWTAuthenticationClaimsSet().getIssuer().getValue());
			} else {
				assertEquals(iss, clientSecretJWT.getJWTAuthenticationClaimsSet().getIssuer());
			}
			assertEquals(clientID, clientSecretJWT.getJWTAuthenticationClaimsSet().getClientID());
			assertEquals(clientID.getValue(), clientSecretJWT.getJWTAuthenticationClaimsSet().getSubject().getValue());
			assertEquals(opIssuerURL.toString(), clientSecretJWT.getJWTAuthenticationClaimsSet().getAudience().get(0).getValue());
			
			// 55s < exp < 65s
			final long now = new Date().getTime();
			final Date minFromNow = new Date(now + 55_000L);
			final Date maxFromNow = new Date(now + 65_000L);
			assertTrue(clientSecretJWT.getJWTAuthenticationClaimsSet().getExpirationTime().after(minFromNow));
			assertTrue(clientSecretJWT.getJWTAuthenticationClaimsSet().getExpirationTime().before(maxFromNow));
			assertNotNull(clientSecretJWT.getJWTAuthenticationClaimsSet().getJWTID());
			assertNull(clientSecretJWT.getJWTAuthenticationClaimsSet().getIssueTime());
			assertNull(clientSecretJWT.getJWTAuthenticationClaimsSet().getNotBeforeTime());
		}
	}
	
	
	public void testParse_clientIDMismatch()
		throws Exception {
		
		ClientID clientID = new ClientID("123");
		URI opIssuerURL = new URI("https://server.c2id.com");
		Secret secret = new Secret(256 / 8); // generate 256 bit secret
		
		ClientSecretJWT clientSecretJWT = new ClientSecretJWT(clientID, opIssuerURL, JWSAlgorithm.HS256, secret);
		
		Map<String,List<String>> params = clientSecretJWT.toParameters();
		
		assertNull(params.get("client_id"));
		
		params.put("client_id", Collections.singletonList("456")); // different client_id
		
		try {
			ClientSecretJWT.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid client secret JWT authentication: The client identifier doesn't match the client assertion subject", e.getMessage());
		}
			
	}
}
