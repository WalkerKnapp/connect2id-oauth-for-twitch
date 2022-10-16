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
import java.util.Collections;
import java.util.Date;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;
import com.nimbusds.openid.connect.sdk.federation.registration.ClientRegistrationType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;


public class ResolveSuccessResponseTest extends TestCase {
	
	public static final RSAKey RSA_JWK;
	public static final JWKSet SIMPLE_JWK_SET;
	private static final Issuer ISS = new Issuer("https://abc-federation.c2id.com");
	private static final Subject SUB = new Subject("https://op.c2id.com");
	private static final Date NOW = new Date();
	private static final Date IAT = DateUtils.fromSecondsSinceEpoch(DateUtils.toSecondsSinceEpoch(NOW));
	private static final Date EXP = DateUtils.fromSecondsSinceEpoch(DateUtils.toSecondsSinceEpoch(NOW) + 3600);
	
	private static final OIDCProviderMetadata OP_METADATA = new OIDCProviderMetadata(
		new Issuer(SUB),
		Collections.singletonList(SubjectType.PAIRWISE),
		Collections.singletonList(ClientRegistrationType.AUTOMATIC),
		null,
		URI.create("https://op.c2id.com/jwks.jwt"),
		null);
	
	private static final JSONObject METADATA = new JSONObject();
	
	static {
		try {
			RSA_JWK = new RSAKeyGenerator(2048)
				.keyIDFromThumbprint(true)
				.keyUse(KeyUse.SIGNATURE)
				.generate();
			SIMPLE_JWK_SET = new JWKSet(RSA_JWK.toPublicJWK());
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
		METADATA.put(EntityType.OPENID_PROVIDER.getValue(), OP_METADATA.toJSONObject());
	}
	
	
	static ResolveStatement createSampleResolveStatement() {
		
		ResolveClaimsSet claimsSet = new ResolveClaimsSet(ISS, SUB, IAT, EXP, METADATA);
		
		try {
			return ResolveStatement.sign(claimsSet, RSA_JWK);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public void testLifecycle() throws Exception {
		
		ResolveStatement statement = createSampleResolveStatement();
		
		ResolveSuccessResponse response = new ResolveSuccessResponse(statement);
		assertEquals(statement, response.getResolveStatement());
		assertTrue(response.indicatesSuccess());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertEquals(200, httpResponse.getStatusCode());
		assertEquals(ResolveStatement.CONTENT_TYPE, httpResponse.getEntityContentType());
		
		response = ResolveSuccessResponse.parse(httpResponse);
		assertEquals(statement.getSignedStatement().serialize(), response.getResolveStatement().getSignedStatement().serialize());
		assertTrue(response.indicatesSuccess());
	}
	
	
	public void testRejectNotOK() {
		
		try {
			ResolveSuccessResponse.parse(new HTTPResponse(400));
			fail();
		} catch (ParseException e) {
			assertEquals("Unexpected HTTP status code 400, must be [200]", e.getMessage());
		}
	}
}
