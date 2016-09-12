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

package com.nimbusds.oauth2.sdk;


import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.nimbusds.oauth2.sdk.auth.Secret;


/**
 * Tests the abstract authorisation grant class.
 */
public class AuthorizationGrantTest extends TestCase {
	
	
	public void testParseCode()
		throws Exception {
		
		Map<String,String> params = new HashMap<>();
		params.put("grant_type", "authorization_code");
		params.put("code", "abc");
		params.put("redirect_uri", "https://client.com/in");
		
		AuthorizationCodeGrant grant = (AuthorizationCodeGrant)AuthorizationGrant.parse(params);
		
		assertEquals(GrantType.AUTHORIZATION_CODE, grant.getType());
		assertEquals("abc", grant.getAuthorizationCode().getValue());
		assertEquals("https://client.com/in", grant.getRedirectionURI().toString());
	}


	public void testParseRefreshToken()
		throws Exception {

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", "refresh_token");
		params.put("refresh_token", "abc123");

		RefreshTokenGrant grant = (RefreshTokenGrant)AuthorizationGrant.parse(params);

		assertEquals(GrantType.REFRESH_TOKEN, grant.getType());
		assertEquals("abc123", grant.getRefreshToken().getValue());
	}


	public void testParsePassword()
		throws Exception {

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", "password");
		params.put("username", "alice");
		params.put("password", "secret");

		ResourceOwnerPasswordCredentialsGrant grant = (ResourceOwnerPasswordCredentialsGrant)AuthorizationGrant.parse(params);

		assertEquals(GrantType.PASSWORD, grant.getType());
		assertEquals("alice", grant.getUsername());
		assertEquals("secret", grant.getPassword().getValue());
	}


	public void testParseClientCredentials()
		throws Exception {

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", "client_credentials");

		ClientCredentialsGrant grant = (ClientCredentialsGrant)AuthorizationGrant.parse(params);

		assertEquals(GrantType.CLIENT_CREDENTIALS, grant.getType());
	}


	public void testParseJWTBearer()
		throws Exception {

		// Claims set not verified
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		SignedJWT assertion = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
		assertion.sign(new MACSigner(new Secret().getValueBytes()));

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", GrantType.JWT_BEARER.getValue());
		params.put("assertion", assertion.serialize());

		JWTBearerGrant grant = (JWTBearerGrant)AuthorizationGrant.parse(params);

		assertEquals(GrantType.JWT_BEARER, grant.getType());
		assertEquals(assertion.serialize(), grant.getAssertion());
		assertEquals(JWSAlgorithm.HS256, grant.getJWTAssertion().getHeader().getAlgorithm());
	}


	public void testParseSAML2Bearer()
		throws Exception {

		Map<String,String> params = new HashMap<>();
		params.put("grant_type", GrantType.SAML2_BEARER.getValue());
		params.put("assertion", "abc");

		SAML2BearerGrant grant = (SAML2BearerGrant)AuthorizationGrant.parse(params);

		assertEquals(GrantType.SAML2_BEARER, grant.getType());
		assertEquals("abc", grant.getAssertion());
		assertEquals("abc", grant.getSAML2Assertion().toString());
	}
}
