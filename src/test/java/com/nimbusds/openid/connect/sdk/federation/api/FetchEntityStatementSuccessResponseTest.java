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

package com.nimbusds.openid.connect.sdk.federation.api;


import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import junit.framework.TestCase;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementClaimsSet;
import com.nimbusds.openid.connect.sdk.rp.ApplicationType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;


public class FetchEntityStatementSuccessResponseTest extends TestCase {
	
	
	static final RSAKey RSA_KEY;
	
	static {
		try {
			RSA_KEY = new RSAKeyGenerator(2048)
				.keyID("1")
				.algorithm(JWSAlgorithm.RS256)
				.keyUse(KeyUse.SIGNATURE)
				.keyOperations(Collections.singleton(KeyOperation.VERIFY))
				.generate();
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}
	
	
	static final JWKSet JWK_SET = new JWKSet(RSA_KEY.toPublicJWK());
	
	
	static EntityStatementClaimsSet createSampleEntityStatementClaimsSet() {
		
		EntityStatementClaimsSet claimsSet = new EntityStatementClaimsSet(
			new Issuer("https://openid.sunet.se"),
			new Subject("https://openid.sunet.se"),
			DateUtils.fromSecondsSinceEpoch(1516239022L),
			DateUtils.fromSecondsSinceEpoch(1516298022),
			JWK_SET);
		
		claimsSet.setAuthorityHints(Collections.singletonList(new EntityID("https://edugain.org/federation")));
		OIDCClientMetadata rpMetadata = new OIDCClientMetadata();
		rpMetadata.setApplicationType(ApplicationType.WEB);
		rpMetadata.setRedirectionURI(URI.create("https://openid.sunet.se/rp/callback"));
		rpMetadata.setOrganizationName("SUNET");
		rpMetadata.setLogoURI(URI.create("https://www.sunet.se/sunet/images/32x32.png"));
		rpMetadata.setGrantTypes(new HashSet<>(Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT)));
		rpMetadata.setJWKSetURI(URI.create("https://openid.sunet.se/rp/jwks.json"));
		claimsSet.setRPMetadata(rpMetadata);
		return claimsSet;
	}
	
	
	static SignedJWT createSignedEntityStatement() {
		
		try {
			JWSHeader jwsHeader = new JWSHeader.Builder((JWSAlgorithm) RSA_KEY.getAlgorithm())
				.keyID(RSA_KEY.getKeyID())
				.build();
			EntityStatementClaimsSet claimsSet = createSampleEntityStatementClaimsSet();
			SignedJWT signedStmt = new SignedJWT(jwsHeader, claimsSet.toJWTClaimsSet());
			signedStmt.sign(new RSASSASigner(RSA_KEY));
			return signedStmt;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public void testLifeCycle() throws Exception {
		
		SignedJWT signedStmt = createSignedEntityStatement();
		
		FetchEntityStatementSuccessResponse response = new FetchEntityStatementSuccessResponse(signedStmt);
		assertEquals(signedStmt, response.getSignedEntityStatement());
		assertTrue(response.indicatesSuccess());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertEquals(200, httpResponse.getStatusCode());
		assertEquals("application/jose; charset=UTF-8", httpResponse.getEntityContentType().toString());
		assertEquals(signedStmt.serialize(), httpResponse.getContent());
		
		response = FetchEntityStatementSuccessResponse.parse(httpResponse);
		assertEquals(signedStmt.serialize(), response.getSignedEntityStatement().getParsedString());
		assertTrue(response.indicatesSuccess());
		
		assertTrue(response.getSignedEntityStatement().verify(new RSASSAVerifier(RSA_KEY.toRSAPublicKey())));
		
		new EntityStatementClaimsSet(response.getSignedEntityStatement().getJWTClaimsSet());
	}
	
	
	public void testParseHTTPResponse_not200() {
		
		try {
			FetchEntityStatementSuccessResponse.parse(new HTTPResponse(404));
			fail();
		} catch (ParseException e) {
			assertEquals("Unexpected HTTP status code 404, must be [200]", e.getMessage());
		}
	}
	
	
	public void testParseHTTPResponse_notContentTypeJOSE() {
		
		HTTPResponse httpResponse = new HTTPResponse(200);
		httpResponse.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpResponse.setContent(createSignedEntityStatement().serialize());
		
		try {
			FetchEntityStatementSuccessResponse.parse(httpResponse);
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP Content-Type header must be application/jose; charset=UTF-8", e.getMessage());
		}
	}
	
	
	public void testParseHTTPResponse_contentNotSignedJWT() {
		
		HTTPResponse httpResponse = new HTTPResponse(200);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JOSE);
		httpResponse.setContent("invalid-signed-jwt");
		
		try {
			FetchEntityStatementSuccessResponse.parse(httpResponse);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid signed entity statement: Invalid serialized unsecured/JWS/JWE object: Missing part delimiters", e.getMessage());
		}
	}
}
