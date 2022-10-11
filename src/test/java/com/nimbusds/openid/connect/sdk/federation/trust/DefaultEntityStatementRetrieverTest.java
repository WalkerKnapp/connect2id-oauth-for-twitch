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

package com.nimbusds.openid.connect.sdk.federation.trust;


import java.net.URI;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.federation.api.FederationAPIError;
import com.nimbusds.openid.connect.sdk.federation.config.FederationEntityConfigurationRequest;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementClaimsSet;
import com.nimbusds.openid.connect.sdk.federation.entities.FederationEntityMetadata;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;


public class DefaultEntityStatementRetrieverTest {
	
	
	private static final RSAKey OP_JWK;
	
	
	private static final JWKSet OP_JWK_SET;
	
	
	private static final RSAKey INTERMEDIATE_JWK;
	
	
	private static final JWKSet INTERMEDIATE_JWK_SET;
	
	
	static {
		try {
			OP_JWK = new RSAKeyGenerator(2048)
				.keyIDFromThumbprint(true)
				.keyUse(KeyUse.SIGNATURE)
				.generate();
			OP_JWK_SET = new JWKSet(OP_JWK.toPublicJWK());
			
			INTERMEDIATE_JWK = new RSAKeyGenerator(2048)
				.keyIDFromThumbprint(true)
				.keyUse(KeyUse.SIGNATURE)
				.generate();
			INTERMEDIATE_JWK_SET = new JWKSet(INTERMEDIATE_JWK.toPublicJWK());
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}
	
	
	private static OIDCProviderMetadata createOPMetadata(final Issuer issuer) {
		
		OIDCProviderMetadata opMetadata = new OIDCProviderMetadata(
			issuer,
			Collections.singletonList(SubjectType.PAIRWISE),
			URI.create(issuer + "/jwks.json"));
		opMetadata.setAuthorizationEndpointURI(URI.create(issuer + "/login"));
		opMetadata.setTokenEndpointURI(URI.create(issuer + "/token"));
		opMetadata.setFederationRegistrationEndpointURI(URI.create(issuer + "/clients/federation"));
		opMetadata.applyDefaults();
		return opMetadata;
	}
	
	
	private static EntityStatementClaimsSet createOPStatementClaimsSet(final Issuer issuer, final Issuer opIssuer) {
		
		Date now = new Date();
		long nowTS = DateUtils.toSecondsSinceEpoch(now);
		Date iat = DateUtils.fromSecondsSinceEpoch(nowTS);
		Date exp = DateUtils.fromSecondsSinceEpoch(nowTS + 60);
		
		Subject subject = new Subject(opIssuer.getValue());
		List<EntityID> authorityHints = Collections.singletonList(new EntityID("https://some-org.example.com"));
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			issuer,
			subject,
			iat,
			exp,
			OP_JWK_SET);
		stmt.setAuthorityHints(authorityHints);
		
		FederationEntityMetadata federationEntityMetadata = new FederationEntityMetadata(URI.create(opIssuer + "/federation"));
		federationEntityMetadata.setOrganizationName("Federated OpenID Provider");
		stmt.setFederationEntityMetadata(federationEntityMetadata);
		
		stmt.setOPMetadata(createOPMetadata(opIssuer));
		
		return stmt;
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
	public void testDefaultConstructor() {
		
		DefaultEntityStatementRetriever retriever = new DefaultEntityStatementRetriever();
		assertEquals(DefaultEntityStatementRetriever.DEFAULT_HTTP_CONNECT_TIMEOUT_MS, retriever.getHTTPConnectTimeout());
		assertEquals(DefaultEntityStatementRetriever.DEFAULT_HTTP_READ_TIMEOUT_MS, retriever.getHTTPReadTimeout());
	}
	
	
	@Test
	public void testFetchSelfIssuedEntityStatement_noPathInIssuer()
		throws Exception {
		
		Issuer issuer = new Issuer("http://localhost:" + port());
		
		EntityStatementClaimsSet claimsSet = createOPStatementClaimsSet(issuer, issuer);
		EntityStatement entityStatement = EntityStatement.sign(claimsSet, OP_JWK);
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo(FederationEntityConfigurationRequest.OPENID_FEDERATION_ENTITY_WELL_KNOWN_PATH)
			.respond()
			.withStatus(200)
			.withContentType(EntityStatement.CONTENT_TYPE.toString())
			.withBody(entityStatement.getSignedStatement().serialize());
		
		DefaultEntityStatementRetriever retriever = new DefaultEntityStatementRetriever();
		
		EntityStatement out = retriever.fetchSelfIssuedEntityStatement(new EntityID(issuer.getValue()));
		
		out.verifySignatureOfSelfStatement();
		
		assertEquals(entityStatement.getClaimsSet().toJWTClaimsSet().getClaims(), out.getClaimsSet().toJWTClaimsSet().getClaims());
		
		assertEquals(Collections.singletonList(URI.create(issuer + "/.well-known/openid-federation")), retriever.getRecordedRequests());
	}
	
	
	@Test
	public void testFetchSelfIssuedEntityStatement_wellKnownPostFix()
		throws Exception {
		
		Issuer issuer = new Issuer("http://localhost:" + port() + "/op");
		
		EntityStatementClaimsSet claimsSet = createOPStatementClaimsSet(issuer, issuer);
		EntityStatement entityStatement = EntityStatement.sign(claimsSet, OP_JWK);
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/op" + FederationEntityConfigurationRequest.OPENID_FEDERATION_ENTITY_WELL_KNOWN_PATH)
			.respond()
			.withStatus(200)
			.withContentType(EntityStatement.CONTENT_TYPE.toString())
			.withBody(entityStatement.getSignedStatement().serialize());
		
		DefaultEntityStatementRetriever retriever = new DefaultEntityStatementRetriever();
		
		EntityStatement out = retriever.fetchSelfIssuedEntityStatement(new EntityID(issuer.getValue()));
		
		out.verifySignatureOfSelfStatement();
		
		assertEquals(entityStatement.getClaimsSet().toJWTClaimsSet().getClaims(), out.getClaimsSet().toJWTClaimsSet().getClaims());
		
		assertEquals(Collections.singletonList(URI.create(issuer + "/.well-known/openid-federation")), retriever.getRecordedRequests());
	}
	
	
	@Test
	public void testFetchSelfIssuedEntityStatement_wellKnownInFix()
		throws Exception {
		
		Issuer issuer = new Issuer("http://localhost:" + port() + "/op");
		
		EntityStatementClaimsSet claimsSet = createOPStatementClaimsSet(issuer, issuer);
		EntityStatement entityStatement = EntityStatement.sign(claimsSet, OP_JWK);
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo(FederationEntityConfigurationRequest.OPENID_FEDERATION_ENTITY_WELL_KNOWN_PATH + "/op")
			.respond()
			.withStatus(200)
			.withContentType(EntityStatement.CONTENT_TYPE.toString())
			.withBody(entityStatement.getSignedStatement().serialize());
		
		DefaultEntityStatementRetriever retriever = new DefaultEntityStatementRetriever();
		
		EntityStatement out = retriever.fetchSelfIssuedEntityStatement(new EntityID(issuer.getValue()));
		
		out.verifySignatureOfSelfStatement();
		
		assertEquals(entityStatement.getClaimsSet().toJWTClaimsSet().getClaims(), out.getClaimsSet().toJWTClaimsSet().getClaims());
		
		assertEquals(
			Arrays.asList(
				URI.create("http://localhost:" + port() + "/op/.well-known/openid-federation"),
				URI.create("http://localhost:" + port() + "/.well-known/openid-federation/op")
			),
			retriever.getRecordedRequests()
		);
	}
	
	
	@Test
	public void testFetchSelfIssuedEntityStatement_error_404_noPathInEntityID() {
		
		Issuer issuer = new Issuer("http://localhost:" + port());
		
		final AtomicInteger numInvocations = new AtomicInteger();
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo(FederationEntityConfigurationRequest.OPENID_FEDERATION_ENTITY_WELL_KNOWN_PATH)
			.that(new BaseMatcher<Object>() {
				@Override
				public void describeTo(Description description) {
				
				}
				
				@Override
				public boolean matches(Object o) {
					numInvocations.incrementAndGet();
					return true;
				}
			})
			.respond()
			.withStatus(404);
		
		DefaultEntityStatementRetriever retriever = new DefaultEntityStatementRetriever();
		try {
			retriever.fetchSelfIssuedEntityStatement(new EntityID(issuer.getValue()));
			fail();
		} catch (ResolveException e) {
			assertEquals("Entity configuration error response from " + issuer + "/.well-known/openid-federation: 404", e.getMessage());
			assertEquals(404, e.getErrorObject().getHTTPStatusCode());
		}
		
		assertEquals("One HTTP GET with no path, postfix / infix strategy doesn't matter", 1, numInvocations.get());
		
		assertEquals(Collections.singletonList(URI.create(issuer + "/.well-known/openid-federation")), retriever.getRecordedRequests());
	}
	
	
	@Test
	public void testFetchSelfIssuedEntityStatement_error_404_pathInEntityID() {
		
		Issuer issuer = new Issuer("http://localhost:" + port() + "/rp");
		
		final AtomicInteger numPostfixInvocations = new AtomicInteger();
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/rp" + FederationEntityConfigurationRequest.OPENID_FEDERATION_ENTITY_WELL_KNOWN_PATH)
			.that(new BaseMatcher<Object>() {
				@Override
				public void describeTo(Description description) {
				
				}
				
				@Override
				public boolean matches(Object o) {
					numPostfixInvocations.incrementAndGet();
					return true;
				}
			})
			.respond()
			.withStatus(404);
		
		final AtomicInteger numInfixInvocations = new AtomicInteger();
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo(FederationEntityConfigurationRequest.OPENID_FEDERATION_ENTITY_WELL_KNOWN_PATH + "/rp")
			.that(new BaseMatcher<Object>() {
				@Override
				public void describeTo(Description description) {
				
				}
				
				@Override
				public boolean matches(Object o) {
					numInfixInvocations.incrementAndGet();
					return true;
				}
			})
			.respond()
			.withStatus(404);
		
		DefaultEntityStatementRetriever retriever = new DefaultEntityStatementRetriever();
		try {
			retriever.fetchSelfIssuedEntityStatement(new EntityID(issuer.getValue()));
			fail();
		} catch (ResolveException e) {
			assertEquals("Entity configuration error response from http://localhost:" + port() + "/.well-known/openid-federation/rp: 404", e.getMessage());
			assertEquals(404, e.getErrorObject().getHTTPStatusCode());
		}
		
		assertEquals(1, numPostfixInvocations.get());
		assertEquals(1, numInfixInvocations.get());
		
		assertEquals(
			Arrays.asList(
				URI.create("http://localhost:" + port() + "/rp/.well-known/openid-federation"),
				URI.create("http://localhost:" + port() + "/.well-known/openid-federation/rp")
			),
			retriever.getRecordedRequests()
		);
	}
	
	
	@Test
	public void testFetchEntityStatementFromIntermediateAboutOP()
		throws Exception {
		
		final Issuer issuer = new Issuer("http://localhost:" + port());
		
		final Issuer opIssuer = new Issuer("https://op.c2id.com");
		EntityStatementClaimsSet claimsSet = createOPStatementClaimsSet(issuer, opIssuer);
		EntityStatement intermediateStatementAboutOP = EntityStatement.sign(claimsSet, INTERMEDIATE_JWK);
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/federation")
			.havingQueryString(new BaseMatcher<String>() {
				@Override
				public boolean matches(Object o) {
					Map<String,List<String>> params = URLUtils.parseParameters(o.toString());
					return
						params.get("iss").equals(Collections.singletonList(issuer.getValue()))
							&&
						params.get("sub").equals(Collections.singletonList(opIssuer.getValue()));
				}
				@Override
				public void describeTo(Description description) {}
			})
			.respond()
			.withStatus(200)
			.withContentType(EntityStatement.CONTENT_TYPE.toString())
			.withBody(intermediateStatementAboutOP.getSignedStatement().serialize());
		
		DefaultEntityStatementRetriever retriever = new DefaultEntityStatementRetriever();
		
		EntityStatement out = retriever.fetchEntityStatement(URI.create(issuer + "/federation"), new EntityID(issuer.getValue()), new EntityID(opIssuer.getValue()));
		
		out.verifySignature(INTERMEDIATE_JWK_SET);
		
		assertEquals(intermediateStatementAboutOP.getClaimsSet().toJWTClaimsSet().getClaims(), out.getClaimsSet().toJWTClaimsSet().getClaims());
	
		URI fetchedURI = retriever.getRecordedRequests().get(0);
		
		assertTrue(fetchedURI.toString().startsWith("http://localhost:" + port() + "/federation?"));
		
		Map<String,List<String>> queryParams = URLUtils.parseParameters(fetchedURI.getQuery());
		assertEquals(Collections.singletonList(issuer.getValue()), queryParams.get("iss"));
		assertEquals(Collections.singletonList(opIssuer.getValue()), queryParams.get("sub"));
		assertEquals(2, queryParams.size());
		
		assertEquals(1, retriever.getRecordedRequests().size());
	}
	
	
	@Test
	public void testFetchEntityStatement_error_invalidSubject() {
		
		final Issuer issuer = new Issuer("http://localhost:" + port());
		final Issuer opIssuer = new Issuer("https://op.c2id.com");
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/federation")
			.havingQueryString(new BaseMatcher<String>() {
				@Override
				public boolean matches(Object o) {
					Map<String,List<String>> params = URLUtils.parseParameters(o.toString());
					return
						params.get("iss").equals(Collections.singletonList(issuer.getValue()))
							&&
						params.get("sub").equals(Collections.singletonList(opIssuer.getValue()));
				}
				@Override
				public void describeTo(Description description) {}
			})
			.respond()
			.withStatus(400)
			.withContentType("application/json")
			.withBody(new FederationAPIError("invalid_subject", "Invalid subject").toJSONObject().toJSONString());
		
		DefaultEntityStatementRetriever retriever = new DefaultEntityStatementRetriever();
		
		try {
			retriever.fetchEntityStatement(URI.create(issuer + "/federation"), new EntityID(issuer.getValue()), new EntityID(opIssuer.getValue()));
			fail();
		} catch (ResolveException e) {
			assertEquals("Entity statement error response from " + issuer + " at " + issuer + "/federation: 400 invalid_subject", e.getMessage());
			assertEquals("invalid_subject", e.getErrorObject().getCode());
			assertEquals("Invalid subject", e.getErrorObject().getDescription());
			assertEquals(400, e.getErrorObject().getHTTPStatusCode());
		}
	}
}
