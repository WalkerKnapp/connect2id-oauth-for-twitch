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

package com.nimbusds.openid.connect.sdk.federation.registration;


import java.net.MalformedURLException;
import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatementClaimsSet;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;


public class ExplicitClientRegistrationRequestTest extends TestCase {
	
	
	public static final RSAKey PR_JWK;
	
	
	public static final JWKSet PR_JWK_SET;
	
	
	static {
		try {
			PR_JWK = new RSAKeyGenerator(2048)
				.keyIDFromThumbprint(true)
				.keyUse(KeyUse.SIGNATURE)
				.generate();
			PR_JWK_SET = new JWKSet(PR_JWK.toPublicJWK());
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public static EntityStatementClaimsSet createRPEntityStatementClaimsSet() {
		
		Date now = new Date();
		long nowTS = DateUtils.toSecondsSinceEpoch(now);
		Date iat = DateUtils.fromSecondsSinceEpoch(nowTS);
		Date exp = DateUtils.fromSecondsSinceEpoch(nowTS + 60);
		
		Issuer iss = new Issuer("https://example.com");
		Subject sub = new Subject(iss.getValue());
		List<EntityID> authorityHints = Collections.singletonList(new EntityID("https://federation.example.com"));
		
		EntityStatementClaimsSet stmt = new EntityStatementClaimsSet(
			iss,
			sub,
			iat,
			exp,
			PR_JWK_SET);
		
		OIDCClientMetadata rpMetadata = new OIDCClientMetadata();
		rpMetadata.setRedirectionURI(URI.create("https://example.com/cb"));
		rpMetadata.setClientRegistrationTypes(Collections.singletonList(ClientRegistrationType.EXPLICIT));
		rpMetadata.applyDefaults();
		
		stmt.setRPMetadata(rpMetadata);
		stmt.setAuthorityHints(authorityHints);
		return stmt;
	}
	
	
	public void testLifeCycle()
		throws Exception {
		
		EntityStatementClaimsSet claimsSet = createRPEntityStatementClaimsSet();
		EntityStatement entityStatement = EntityStatement.sign(claimsSet, PR_JWK);
		
		URI endpoint = URI.create("https://c2id.com/federation/clients");
		
		ExplicitClientRegistrationRequest request = new ExplicitClientRegistrationRequest(endpoint, entityStatement);
		
		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(entityStatement, request.getEntityStatement());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(endpoint, httpRequest.getURI());
		assertEquals(endpoint.toURL(), httpRequest.getURL());
		assertEquals(ContentType.APPLICATION_JOSE, httpRequest.getEntityContentType());
		assertEquals(entityStatement.getSignedStatement().serialize(), httpRequest.getQuery());
		
		request = ExplicitClientRegistrationRequest.parse(httpRequest);
		assertEquals(endpoint, request.getEndpointURI());
		assertEquals(entityStatement.getSignedStatement().serialize(), request.getEntityStatement().getSignedStatement().getParsedString());
	}
	
	
	public void testParse_methodNotPOST()
		throws MalformedURLException {
		
		try {
			ExplicitClientRegistrationRequest.parse(new HTTPRequest(HTTPRequest.Method.GET, URI.create("https://c2id.com/federation/clients").toURL()));
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP request method must be POST", e.getMessage());
		}
	}
	
	
	public void testParse_contentTypeHeaderMissing()
		throws Exception {
		
		EntityStatementClaimsSet claimsSet = createRPEntityStatementClaimsSet();
		EntityStatement entityStatement = EntityStatement.sign(claimsSet, PR_JWK);
		
		URI endpoint = URI.create("https://c2id.com/federation/clients");
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpoint.toURL());
		httpRequest.setBody(entityStatement.getSignedStatement().serialize());
		
		try {
			ExplicitClientRegistrationRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing HTTP Content-Type header", e.getMessage());
		}
	}
	
	
	public void testParse_contentTypeHeaderNotJOSE()
		throws Exception {
		
		EntityStatementClaimsSet claimsSet = createRPEntityStatementClaimsSet();
		EntityStatement entityStatement = EntityStatement.sign(claimsSet, PR_JWK);
		
		URI endpoint = URI.create("https://c2id.com/federation/clients");
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpoint.toURL());
		httpRequest.setEntityContentType(ContentType.APPLICATION_JWT);
		httpRequest.setBody(entityStatement.getSignedStatement().serialize());
		
		try {
			ExplicitClientRegistrationRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP Content-Type header must be application/jose, received application/jwt", e.getMessage());
		}
	}
	
	
	public void testParse_invalidSignedJWT()
		throws Exception {
		
		URI endpoint = URI.create("https://c2id.com/federation/clients");
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpoint.toURL());
		httpRequest.setEntityContentType(ContentType.APPLICATION_JOSE);
		httpRequest.setBody("not-a-jwt");
		
		try {
			ExplicitClientRegistrationRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid entity statement: Invalid serialized unsecured/JWS/JWE object: Missing part delimiters", e.getMessage());
		}
	}
}
