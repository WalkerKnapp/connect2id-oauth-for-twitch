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
import java.util.Date;
import java.util.Map;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.util.DateUtils;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import junit.framework.TestCase;


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


	public void testRun()
		throws Exception {

		ClientID clientID = new ClientID("http://client.com");
		Audience audience = new Audience("http://idp.com");
		Date exp = DateUtils.fromSecondsSinceEpoch(new Date().getTime() / 1000 + 3600);
		Date nbf = DateUtils.fromSecondsSinceEpoch(new Date().getTime() / 1000);
		Date iat = DateUtils.fromSecondsSinceEpoch(new Date().getTime() / 1000);
		JWTID jti = new JWTID();

		JWTAuthenticationClaimsSet assertion = new JWTAuthenticationClaimsSet(clientID, audience.toSingleAudienceList(), exp, nbf, iat, jti);

		System.out.println("Client secret JWT claims set: " + assertion.toJSONObject());


		JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);

		SignedJWT jwt = new SignedJWT(jwsHeader, assertion.toJWTClaimsSet());

		Secret secret = new Secret();

		MACSigner signer = new MACSigner(secret.getValueBytes());

		jwt.sign(signer);

		ClientSecretJWT clientSecretJWT = new ClientSecretJWT(jwt);

		Map<String,String> params = clientSecretJWT.toParameters();
		params.put("client_id", clientID.getValue()); // add optional client_id to test parser

		System.out.println("Client secret JWT: " + params);

		clientSecretJWT = ClientSecretJWT.parse(params);

		assertEquals("http://client.com", clientSecretJWT.getClientID().getValue());

		jwt = clientSecretJWT.getClientAssertion();

		assertTrue(jwt.getState().equals(JWSObject.State.SIGNED));

		MACVerifier verifier = new MACVerifier(secret.getValueBytes());

		boolean verified = jwt.verify(verifier);

		assertTrue(verified);

		assertion = clientSecretJWT.getJWTAuthenticationClaimsSet();

		assertEquals(clientID.getValue(), assertion.getClientID().getValue());
		assertEquals(clientID.getValue(), assertion.getIssuer().getValue());
		assertEquals(clientID.getValue(), assertion.getSubject().getValue());
		assertEquals(audience.getValue(), assertion.getAudience().get(0).getValue());
		assertEquals(exp.getTime(), assertion.getExpirationTime().getTime());
		assertEquals(nbf.getTime(), assertion.getNotBeforeTime().getTime());
		assertEquals(iat.getTime(), assertion.getIssueTime().getTime());
		assertEquals(jti.getValue(), assertion.getJWTID().getValue());
	}


	public void testWithJWTHelper()
		throws Exception {

		ClientID clientID = new ClientID("123");
		URI tokenEndpoint = new URI("https://c2id.com/token");
		Secret secret = new Secret(256 / 8); // generate 256 bit secret

		ClientSecretJWT clientSecretJWT = new ClientSecretJWT(clientID, tokenEndpoint, JWSAlgorithm.HS256, secret);

		clientSecretJWT = ClientSecretJWT.parse(clientSecretJWT.toParameters());

		assertTrue(clientSecretJWT.getClientAssertion().verify(new MACVerifier(secret.getValueBytes())));

		assertEquals(clientID, clientSecretJWT.getJWTAuthenticationClaimsSet().getClientID());
		assertEquals(clientID.getValue(), clientSecretJWT.getJWTAuthenticationClaimsSet().getIssuer().getValue());
		assertEquals(clientID.getValue(), clientSecretJWT.getJWTAuthenticationClaimsSet().getSubject().getValue());
		assertEquals(tokenEndpoint.toString(), clientSecretJWT.getJWTAuthenticationClaimsSet().getAudience().get(0).getValue());

		// 4 min < exp < 6 min
		final long now = new Date().getTime();
		final Date fourMinutesFromNow = new Date(now + 4*60*1000l);
		final Date sixMinutesFromNow = new Date(now + 6*60*1000l);
		assertTrue(clientSecretJWT.getJWTAuthenticationClaimsSet().getExpirationTime().after(fourMinutesFromNow));
		assertTrue(clientSecretJWT.getJWTAuthenticationClaimsSet().getExpirationTime().before(sixMinutesFromNow));
		assertNotNull(clientSecretJWT.getJWTAuthenticationClaimsSet().getJWTID());
		assertNull(clientSecretJWT.getJWTAuthenticationClaimsSet().getIssueTime());
		assertNull(clientSecretJWT.getJWTAuthenticationClaimsSet().getNotBeforeTime());
	}
	
	
	public void testParse_clientIDMismatch()
		throws Exception {
		
		ClientID clientID = new ClientID("123");
		URI tokenEndpoint = new URI("https://c2id.com/token");
		Secret secret = new Secret(256 / 8); // generate 256 bit secret
		
		ClientSecretJWT clientSecretJWT = new ClientSecretJWT(clientID, tokenEndpoint, JWSAlgorithm.HS256, secret);
		
		Map<String,String> params = clientSecretJWT.toParameters();
		
		assertNull(params.get("client_id"));
		
		params.put("client_id", "456"); // different client_id
		
		try {
			ClientSecretJWT.parse(params);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid client secret JWT authentication: The client identifier doesn't match the client assertion subject / issuer", e.getMessage());
		}
			
	}
}
