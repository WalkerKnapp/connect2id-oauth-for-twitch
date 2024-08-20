/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.rp.statement;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.SoftwareID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;


public class SoftwareStatementProcessorTest {
	
	
	private static final RSAKey RSA_JWK;
	
	
	private static final RSAKey OTHER_RSA_JWK;
	
	
	static {
		try {
			RSA_JWK = new RSAKeyGenerator(2048)
				.keyIDFromThumbprint(true)
				.generate();
			
			OTHER_RSA_JWK = new RSAKeyGenerator(2048)
				.keyIDFromThumbprint(true)
				.generate();
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}
	
	
	@Before
	public void setUp() {
		initJadler();
	}
	
	
	@After
	public void tearDown() {
		closeJadler();
	}


	@Test
	public void testRS256_jwkSet()
		throws Exception {
		
		Issuer issuer = new Issuer("https://issuer.com");
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		URI redirectURI = URI.create("https://example.com/cb");
		clientMetadata.setRedirectionURI(redirectURI);
		
		ClientMetadata signedClientMetadata = new ClientMetadata();
		SoftwareID softwareID = new SoftwareID("4NRB1-0XZABZI9E6-5SM3R");
		signedClientMetadata.setSoftwareID(softwareID);
		String name = "Example Statement-based Client";
		signedClientMetadata.setName(name);
		URI uri = URI.create("https://client.example.net/");
		signedClientMetadata.setURI(uri);
		
		SignedJWT softwareStatement = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(RSA_JWK.getKeyID()).build(),
			new JWTClaimsSet.Builder(JWTClaimsSet.parse(signedClientMetadata.toJSONObject()))
				.issuer(issuer.getValue())
				.build());
		softwareStatement.sign(new RSASSASigner(RSA_JWK));
		clientMetadata.setSoftwareStatement(softwareStatement);
		
		for (boolean required: Arrays.asList(true, false)) {
			
			SoftwareStatementProcessor processor = new SoftwareStatementProcessor(
				issuer,
				required,
				Collections.singleton(JWSAlgorithm.RS256),
				new JWKSet(RSA_JWK.toPublicJWK()));
			
			OIDCClientMetadata out = processor.process(clientMetadata);
			assertEquals(Collections.singleton(redirectURI), out.getRedirectionURIs());
			assertEquals(softwareID, out.getSoftwareID());
			assertEquals(name, out.getName());
			assertEquals(uri, out.getURI());
			assertEquals(4, out.toJSONObject().size());
		}
	}


	@Test
	public void testRS256_jwkSetURI()
		throws Exception {
		
		Issuer issuer = new Issuer("https://issuer.com");
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		URI redirectURI = URI.create("https://example.com/cb");
		clientMetadata.setRedirectionURI(redirectURI);
		
		ClientMetadata signedClientMetadata = new ClientMetadata();
		SoftwareID softwareID = new SoftwareID("4NRB1-0XZABZI9E6-5SM3R");
		signedClientMetadata.setSoftwareID(softwareID);
		String name = "Example Statement-based Client";
		signedClientMetadata.setName(name);
		URI uri = URI.create("https://client.example.net/");
		signedClientMetadata.setURI(uri);
		
		SignedJWT softwareStatement = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(RSA_JWK.getKeyID()).build(),
			new JWTClaimsSet.Builder(JWTClaimsSet.parse(signedClientMetadata.toJSONObject()))
				.issuer(issuer.getValue())
				.build());
		softwareStatement.sign(new RSASSASigner(RSA_JWK));
		clientMetadata.setSoftwareStatement(softwareStatement);
		
		URL jwkSetURL = new URL("http://localhost:" + port());
		
		onRequest()
			.havingMethodEqualTo("GET")
			.respond()
			.withStatus(200)
			.withContentType("application/json")
			.withBody(new JWKSet(RSA_JWK.toPublicJWK()).toString());
		
		for (boolean required: Arrays.asList(true, false)) {
			
			SoftwareStatementProcessor processor = new SoftwareStatementProcessor(
				issuer,
				required,
				Collections.singleton(JWSAlgorithm.RS256),
				jwkSetURL,
				250,
				250,
				10_000);
			
			OIDCClientMetadata out = processor.process(clientMetadata);
			assertEquals(Collections.singleton(redirectURI), out.getRedirectionURIs());
			assertEquals(softwareID, out.getSoftwareID());
			assertEquals(name, out.getName());
			assertEquals(uri, out.getURI());
			assertEquals(4, out.toJSONObject().size());
		}
	}


	@Test
	public void testRS256_jwkSetURI_additionalRequiredClaims_iat_jti()
		throws Exception {
		
		Issuer issuer = new Issuer("https://issuer.com");
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		URI redirectURI = URI.create("https://example.com/cb");
		clientMetadata.setRedirectionURI(redirectURI);
		
		ClientMetadata signedClientMetadata = new ClientMetadata();
		SoftwareID softwareID = new SoftwareID("4NRB1-0XZABZI9E6-5SM3R");
		signedClientMetadata.setSoftwareID(softwareID);
		String name = "Example Statement-based Client";
		signedClientMetadata.setName(name);
		URI uri = URI.create("https://client.example.net/");
		signedClientMetadata.setURI(uri);
		
		// Missing required iat, jti
		SignedJWT softwareStatement = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(RSA_JWK.getKeyID()).build(),
			new JWTClaimsSet.Builder(JWTClaimsSet.parse(signedClientMetadata.toJSONObject()))
				.issuer(issuer.getValue())
				.build());
		softwareStatement.sign(new RSASSASigner(RSA_JWK));
		clientMetadata.setSoftwareStatement(softwareStatement);
		
		URL jwkSetURL = new URL("http://localhost:" + port());
		
		onRequest()
			.havingMethodEqualTo("GET")
			.respond()
			.withStatus(200)
			.withContentType("application/json")
			.withBody(new JWKSet(RSA_JWK.toPublicJWK()).toString());
		
		SoftwareStatementProcessor<?> processor = new SoftwareStatementProcessor<>(
			issuer,
			true,
			Collections.singleton(JWSAlgorithm.RS256),
			new RemoteJWKSet(jwkSetURL),
			new HashSet<>(Arrays.asList("iat", "jti")));
		
		try {
			processor.process(clientMetadata);
			fail();
		} catch (InvalidSoftwareStatementException e) {
			assertEquals("Invalid software statement JWT: JWT missing required claims: [iat, jti]", e.getMessage());
		}
		
		
		// Add required iat, jti
		softwareStatement = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(RSA_JWK.getKeyID()).build(),
			new JWTClaimsSet.Builder(JWTClaimsSet.parse(signedClientMetadata.toJSONObject()))
				.issuer(issuer.getValue())
				.issueTime(new Date())
				.jwtID("34f8774a-1ede-45be-9b68-595f91a0ab35")
				.build());
		softwareStatement.sign(new RSASSASigner(RSA_JWK));
		clientMetadata.setSoftwareStatement(softwareStatement);
		
		OIDCClientMetadata out = processor.process(clientMetadata);
		assertEquals(Collections.singleton(redirectURI), out.getRedirectionURIs());
		assertEquals(softwareID, out.getSoftwareID());
		assertEquals(name, out.getName());
		assertEquals(uri, out.getURI());
		assertNotNull(out.getCustomField("iat"));
		assertEquals("34f8774a-1ede-45be-9b68-595f91a0ab35", out.getCustomField("jti"));
		assertEquals(6, out.toJSONObject().size());
	}


	@Test
	public void testRS256_jwkSetURI_missingRequired()
		throws Exception {
		
		Issuer issuer = new Issuer("https://issuer.com");
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		URI redirectURI = URI.create("https://example.com/cb");
		clientMetadata.setRedirectionURI(redirectURI);
		
		URL jwkSetURL = new URL("http://localhost:" + port());
		
		onRequest()
			.havingMethodEqualTo("GET")
			.respond()
			.withStatus(200)
			.withContentType("application/json")
			.withBody(new JWKSet(RSA_JWK.toPublicJWK()).toString());
		
		SoftwareStatementProcessor processor = new SoftwareStatementProcessor(
			issuer,
			true,
			Collections.singleton(JWSAlgorithm.RS256),
			jwkSetURL,
			250,
			250,
			10_000);
		
		try {
			processor.process(clientMetadata);
			fail();
		} catch (InvalidSoftwareStatementException e) {
			assertEquals("Missing required software statement", e.getMessage());
		}
	}


	@Test
	public void testRS256_jwtType_explicitJWT()
		throws Exception {

		Issuer issuer = new Issuer("https://issuer.com");

		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		URI redirectURI = URI.create("https://example.com/cb");
		clientMetadata.setRedirectionURI(redirectURI);

		ClientMetadata signedClientMetadata = new ClientMetadata();
		SoftwareID softwareID = new SoftwareID("4NRB1-0XZABZI9E6-5SM3R");
		signedClientMetadata.setSoftwareID(softwareID);
		String name = "Example Statement-based Client";
		signedClientMetadata.setName(name);
		URI uri = URI.create("https://client.example.net/");
		signedClientMetadata.setURI(uri);

		SignedJWT softwareStatement = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(JOSEObjectType.JWT)
				.keyID(RSA_JWK.getKeyID())
				.build(),
			new JWTClaimsSet.Builder(JWTClaimsSet.parse(signedClientMetadata.toJSONObject()))
				.issuer(issuer.getValue())
				.build());
		softwareStatement.sign(new RSASSASigner(RSA_JWK));
		clientMetadata.setSoftwareStatement(softwareStatement);

		for (boolean required: Arrays.asList(true, false)) {

			SoftwareStatementProcessor processor = new SoftwareStatementProcessor(
				issuer,
				required,
				Collections.singleton(JWSAlgorithm.RS256),
				new JWKSet(RSA_JWK.toPublicJWK()));

			OIDCClientMetadata out = processor.process(clientMetadata);
			assertEquals(Collections.singleton(redirectURI), out.getRedirectionURIs());
			assertEquals(softwareID, out.getSoftwareID());
			assertEquals(name, out.getName());
			assertEquals(uri, out.getURI());
			assertEquals(4, out.toJSONObject().size());
		}
	}


	@Test
	public void testRS256_jwtType_explicitNotJWT()
		throws Exception {

		Issuer issuer = new Issuer("https://issuer.com");

		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		URI redirectURI = URI.create("https://example.com/cb");
		clientMetadata.setRedirectionURI(redirectURI);

		ClientMetadata signedClientMetadata = new ClientMetadata();
		SoftwareID softwareID = new SoftwareID("4NRB1-0XZABZI9E6-5SM3R");
		signedClientMetadata.setSoftwareID(softwareID);
		String name = "Example Statement-based Client";
		signedClientMetadata.setName(name);
		URI uri = URI.create("https://client.example.net/");
		signedClientMetadata.setURI(uri);

		SignedJWT softwareStatement = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(new JOSEObjectType("some-jwt-type"))
				.keyID(RSA_JWK.getKeyID())
				.build(),
			new JWTClaimsSet.Builder(JWTClaimsSet.parse(signedClientMetadata.toJSONObject()))
				.issuer(issuer.getValue())
				.build());
		softwareStatement.sign(new RSASSASigner(RSA_JWK));
		clientMetadata.setSoftwareStatement(softwareStatement);

		for (boolean required: Arrays.asList(true, false)) {

			SoftwareStatementProcessor processor = new SoftwareStatementProcessor(
				issuer,
				required,
				Collections.singleton(JWSAlgorithm.RS256),
				new JWKSet(RSA_JWK.toPublicJWK()));

			try {
				processor.process(clientMetadata);
				fail();
			} catch (InvalidSoftwareStatementException e) {
				assertEquals("Invalid software statement JWT: JOSE header typ (type) some-jwt-type not allowed", e.getMessage());
			}
		}
	}


	@Test
	public void testRS256_jwtType_explicitCustom()
		throws Exception {

		Issuer issuer = new Issuer("https://issuer.com");

		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		URI redirectURI = URI.create("https://example.com/cb");
		clientMetadata.setRedirectionURI(redirectURI);

		ClientMetadata signedClientMetadata = new ClientMetadata();
		SoftwareID softwareID = new SoftwareID("4NRB1-0XZABZI9E6-5SM3R");
		signedClientMetadata.setSoftwareID(softwareID);
		String name = "Example Statement-based Client";
		signedClientMetadata.setName(name);
		URI uri = URI.create("https://client.example.net/");
		signedClientMetadata.setURI(uri);

		SignedJWT softwareStatement = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(new JOSEObjectType("software-statement+jwt"))
				.keyID(RSA_JWK.getKeyID())
				.build(),
			new JWTClaimsSet.Builder(JWTClaimsSet.parse(signedClientMetadata.toJSONObject()))
				.issuer(issuer.getValue())
				.build());
		softwareStatement.sign(new RSASSASigner(RSA_JWK));
		clientMetadata.setSoftwareStatement(softwareStatement);

		for (boolean required: Arrays.asList(true, false)) {

			SoftwareStatementProcessor processor = new SoftwareStatementProcessor(
				issuer,
				required,
				Collections.singleton(JWSAlgorithm.RS256),
				Collections.singleton(new JOSEObjectType("software-statement+jwt")),
				new ImmutableJWKSet(new JWKSet(RSA_JWK.toPublicJWK())),
				null);

			OIDCClientMetadata out = processor.process(clientMetadata);
			assertEquals(Collections.singleton(redirectURI), out.getRedirectionURIs());
			assertEquals(softwareID, out.getSoftwareID());
			assertEquals(name, out.getName());
			assertEquals(uri, out.getURI());
			assertEquals(4, out.toJSONObject().size());
		}
	}


	@Test
	public void testRS256_jwtType_explicitCustomNotAllowed()
		throws Exception {

		Issuer issuer = new Issuer("https://issuer.com");

		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		URI redirectURI = URI.create("https://example.com/cb");
		clientMetadata.setRedirectionURI(redirectURI);

		ClientMetadata signedClientMetadata = new ClientMetadata();
		SoftwareID softwareID = new SoftwareID("4NRB1-0XZABZI9E6-5SM3R");
		signedClientMetadata.setSoftwareID(softwareID);
		String name = "Example Statement-based Client";
		signedClientMetadata.setName(name);
		URI uri = URI.create("https://client.example.net/");
		signedClientMetadata.setURI(uri);

		SignedJWT softwareStatement = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256)
				.type(new JOSEObjectType("some-jwt-type"))
				.keyID(RSA_JWK.getKeyID())
				.build(),
			new JWTClaimsSet.Builder(JWTClaimsSet.parse(signedClientMetadata.toJSONObject()))
				.issuer(issuer.getValue())
				.build());
		softwareStatement.sign(new RSASSASigner(RSA_JWK));
		clientMetadata.setSoftwareStatement(softwareStatement);

		for (boolean required: Arrays.asList(true, false)) {

			SoftwareStatementProcessor processor = new SoftwareStatementProcessor(
				issuer,
				required,
				Collections.singleton(JWSAlgorithm.RS256),
				Collections.singleton(new JOSEObjectType("software-statement+jwt")),
				new ImmutableJWKSet(new JWKSet(RSA_JWK.toPublicJWK())),
				null);

			try {
				processor.process(clientMetadata);
				fail();
			} catch (InvalidSoftwareStatementException e) {
				assertEquals("Invalid software statement JWT: JOSE header typ (type) some-jwt-type not allowed", e.getMessage());
			}
		}
	}


	@Test
	public void testRS256_jwkSet_invalidSignature()
		throws Exception {
		
		Issuer issuer = new Issuer("https://issuer.com");
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		URI redirectURI = URI.create("https://example.com/cb");
		clientMetadata.setRedirectionURI(redirectURI);
		
		ClientMetadata signedClientMetadata = new ClientMetadata();
		SoftwareID softwareID = new SoftwareID("4NRB1-0XZABZI9E6-5SM3R");
		signedClientMetadata.setSoftwareID(softwareID);
		String name = "Example Statement-based Client";
		signedClientMetadata.setName(name);
		URI uri = URI.create("https://client.example.net/");
		signedClientMetadata.setURI(uri);
		
		SignedJWT softwareStatement = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(RSA_JWK.getKeyID()).build(),
			new JWTClaimsSet.Builder(JWTClaimsSet.parse(signedClientMetadata.toJSONObject()))
				.issuer(issuer.getValue())
				.build());
		softwareStatement.sign(new RSASSASigner(OTHER_RSA_JWK));
		clientMetadata.setSoftwareStatement(softwareStatement);
		
		SoftwareStatementProcessor processor = new SoftwareStatementProcessor(
			issuer,
			true,
			Collections.singleton(JWSAlgorithm.RS256),
			new JWKSet(RSA_JWK.toPublicJWK()));
		
		try {
			processor.process(clientMetadata);
			fail();
		} catch (InvalidSoftwareStatementException e) {
			assertEquals("Invalid software statement JWT: Signed JWT rejected: Invalid signature", e.getMessage());
		}
	}


	@Test
	public void testRS256_jwkSet_404()
		throws Exception {
		
		Issuer issuer = new Issuer("https://issuer.com");
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		URI redirectURI = URI.create("https://example.com/cb");
		clientMetadata.setRedirectionURI(redirectURI);
		
		ClientMetadata signedClientMetadata = new ClientMetadata();
		SoftwareID softwareID = new SoftwareID("4NRB1-0XZABZI9E6-5SM3R");
		signedClientMetadata.setSoftwareID(softwareID);
		String name = "Example Statement-based Client";
		signedClientMetadata.setName(name);
		URI uri = URI.create("https://client.example.net/");
		signedClientMetadata.setURI(uri);
		
		SignedJWT softwareStatement = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(RSA_JWK.getKeyID()).build(),
			new JWTClaimsSet.Builder(JWTClaimsSet.parse(signedClientMetadata.toJSONObject()))
				.issuer(issuer.getValue())
				.build());
		softwareStatement.sign(new RSASSASigner(RSA_JWK));
		clientMetadata.setSoftwareStatement(softwareStatement);
		
		URL jwkSetURL = new URL("http://localhost:" + port());
		
		onRequest()
			.havingMethodEqualTo("GET")
			.respond()
			.withStatus(404);
		
		SoftwareStatementProcessor processor = new SoftwareStatementProcessor(
			issuer,
			true,
			Collections.singleton(JWSAlgorithm.RS256),
			jwkSetURL,
			250,
			250,
			10_000);
		
		try {
			processor.process(clientMetadata);
			fail();
		} catch (InvalidSoftwareStatementException e) {
			assertEquals("Software statement JWT validation failed: Couldn't retrieve remote JWK set: http://localhost:" + port(), e.getMessage());
		}
	}


	@Test
	public void testRS256_jwkSet_issuerChecks()
		throws Exception {
		
		Issuer issuer = new Issuer("https://issuer.com");
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		URI redirectURI = URI.create("https://example.com/cb");
		clientMetadata.setRedirectionURI(redirectURI);
		
		ClientMetadata signedClientMetadata = new ClientMetadata();
		SoftwareID softwareID = new SoftwareID("4NRB1-0XZABZI9E6-5SM3R");
		signedClientMetadata.setSoftwareID(softwareID);
		String name = "Example Statement-based Client";
		signedClientMetadata.setName(name);
		URI uri = URI.create("https://client.example.net/");
		signedClientMetadata.setURI(uri);
		
		SoftwareStatementProcessor processor = new SoftwareStatementProcessor(
			issuer,
			true,
			Collections.singleton(JWSAlgorithm.RS256),
			new JWKSet(RSA_JWK.toPublicJWK()));
		
		SignedJWT softwareStatement = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(RSA_JWK.getKeyID()).build(),
			new JWTClaimsSet.Builder(JWTClaimsSet.parse(signedClientMetadata.toJSONObject()))
				.build()); // no iss!
		softwareStatement.sign(new RSASSASigner(RSA_JWK));
		clientMetadata.setSoftwareStatement(softwareStatement);
		
		try {
			processor.process(clientMetadata);
			fail();
		} catch (InvalidSoftwareStatementException e) {
			assertEquals("Invalid software statement JWT: JWT missing required claims: [iss]", e.getMessage());
		}
		
		softwareStatement = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(RSA_JWK.getKeyID()).build(),
			new JWTClaimsSet.Builder(JWTClaimsSet.parse(signedClientMetadata.toJSONObject()))
				.issuer("https://some-other-issuer.com")
				.build());
		softwareStatement.sign(new RSASSASigner(RSA_JWK));
		clientMetadata.setSoftwareStatement(softwareStatement);
		
		try {
			processor.process(clientMetadata);
			fail();
		} catch (InvalidSoftwareStatementException e) {
			assertEquals("Invalid software statement JWT: JWT iss claim has value https://some-other-issuer.com, must be https://issuer.com", e.getMessage());
		}
	}
}
