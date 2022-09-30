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

package com.nimbusds.openid.connect.sdk.rp;


import java.net.URI;
import java.util.Date;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Tests the OpenID Connect client information class.
 */
public class OIDCClientInformationTest extends TestCase {


	public void testRegisteredParameters() {

		Set<String> paramNames = OIDCClientInformation.getRegisteredParameterNames();

		assertTrue(paramNames.contains("client_id"));
		assertTrue(paramNames.contains("client_id_issued_at"));
		assertTrue(paramNames.contains("registration_access_token"));
		assertTrue(paramNames.contains("registration_client_uri"));
		assertTrue(paramNames.contains("client_secret"));
		assertTrue(paramNames.contains("client_secret_expires_at"));

		assertTrue(paramNames.contains("redirect_uris"));
		assertTrue(paramNames.contains("client_name"));
		assertTrue(paramNames.contains("client_uri"));
		assertTrue(paramNames.contains("logo_uri"));
		assertTrue(paramNames.contains("contacts"));
		assertTrue(paramNames.contains("tos_uri"));
		assertTrue(paramNames.contains("policy_uri"));
		assertTrue(paramNames.contains("token_endpoint_auth_method"));
		assertTrue(paramNames.contains("scope"));
		assertTrue(paramNames.contains("grant_types"));
		assertTrue(paramNames.contains("response_types"));
		assertTrue(paramNames.contains("jwks_uri"));
		assertTrue(paramNames.contains("jwks"));
		assertTrue(paramNames.contains("software_id"));
		assertTrue(paramNames.contains("software_version"));
		assertTrue(paramNames.contains("software_statement"));
		assertTrue(paramNames.contains("tls_client_certificate_bound_access_tokens"));
		assertTrue(paramNames.contains("tls_client_auth_subject_dn"));
		assertTrue(paramNames.contains("tls_client_auth_san_dns"));
		assertTrue(paramNames.contains("tls_client_auth_san_uri"));
		assertTrue(paramNames.contains("tls_client_auth_san_ip"));
		assertTrue(paramNames.contains("tls_client_auth_san_email"));
		assertTrue(paramNames.contains("authorization_signed_response_alg"));
		assertTrue(paramNames.contains("authorization_encrypted_response_enc"));
		assertTrue(paramNames.contains("authorization_encrypted_response_enc"));
		assertTrue(paramNames.contains("require_pushed_authorization_requests"));
		
		// CIBA
		assertTrue(paramNames.contains("backchannel_token_delivery_mode"));
		assertTrue(paramNames.contains("backchannel_client_notification_endpoint"));
		assertTrue(paramNames.contains("backchannel_authentication_request_signing_alg"));
		assertTrue(paramNames.contains("backchannel_user_code_parameter"));

		// OIDC specific params
		assertTrue(paramNames.contains("application_type"));
		assertTrue(paramNames.contains("sector_identifier_uri"));
		assertTrue(paramNames.contains("subject_type"));
		assertTrue(paramNames.contains("id_token_signed_response_alg"));
		assertTrue(paramNames.contains("id_token_encrypted_response_alg"));
		assertTrue(paramNames.contains("id_token_encrypted_response_enc"));
		assertTrue(paramNames.contains("userinfo_signed_response_alg"));
		assertTrue(paramNames.contains("userinfo_encrypted_response_alg"));
		assertTrue(paramNames.contains("userinfo_encrypted_response_enc"));
		assertTrue(paramNames.contains("request_object_signing_alg"));
		assertTrue(paramNames.contains("token_endpoint_auth_signing_alg"));
		assertTrue(paramNames.contains("default_max_age"));
		assertTrue(paramNames.contains("require_auth_time"));
		assertTrue(paramNames.contains("default_acr_values"));
		assertTrue(paramNames.contains("initiate_login_uri"));
		assertTrue(paramNames.contains("request_uris"));
		assertTrue(paramNames.contains("post_logout_redirect_uris"));
		assertTrue(paramNames.contains("frontchannel_logout_uri"));
		assertTrue(paramNames.contains("frontchannel_logout_session_required"));
		assertTrue(paramNames.contains("backchannel_logout_uri"));
		assertTrue(paramNames.contains("backchannel_logout_session_required"));
		assertTrue(paramNames.contains("digest_algorithm"));
		assertTrue(paramNames.contains("organization_name"));
		assertTrue(paramNames.contains("signed_jwks_uri"));
		assertTrue(paramNames.contains("client_registration_types"));
		assertEquals(63, paramNames.size());
	}


	public void testMinimalConstructor()
		throws Exception {

		ClientID clientID = new ClientID("123");
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setName("Example app");

		OIDCClientInformation info = new OIDCClientInformation(clientID, metadata);
		
		assertEquals(clientID, info.getID());
		assertNull(info.getIDIssueDate());
		assertEquals(metadata, info.getMetadata());
		assertEquals("Example app", info.getMetadata().getName());
		assertNull(info.getSecret());
		assertNull(info.getRegistrationURI());
		assertNull(info.getRegistrationAccessToken());
		
		String json = info.toJSONObject().toJSONString();
		
		info = OIDCClientInformation.parse(JSONObjectUtils.parse(json));
		
		assertEquals(clientID, info.getID());
		assertNull(info.getIDIssueDate());
		assertEquals("Example app", info.getMetadata().getName());
		assertNull(info.getSecret());
		assertNull(info.getRegistrationURI());
		assertNull(info.getRegistrationAccessToken());
	}


	public void testConstructor()
		throws Exception {

		ClientID clientID = new ClientID("123");
		Date now = new Date(new Date().getTime() / 1000 * 1000);
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setName("Example app");
		Secret secret = new Secret("secret");
		URI regURI = new URI("https://c2id.com/client-reg/123");
		BearerAccessToken accessToken = new BearerAccessToken("xyz");

		OIDCClientInformation info = new OIDCClientInformation(clientID, now, metadata, secret, regURI, accessToken);

		assertEquals(clientID, info.getID());
		assertEquals(now, info.getIDIssueDate());
		assertEquals(metadata, info.getMetadata());
		assertEquals(metadata, info.getOIDCMetadata());
		assertEquals("Example app", info.getMetadata().getName());
		assertEquals(secret, info.getSecret());
		assertEquals(regURI, info.getRegistrationURI());
		assertEquals(accessToken, info.getRegistrationAccessToken());

		String json = info.toJSONObject().toJSONString();

		info = OIDCClientInformation.parse(JSONObjectUtils.parse(json));

		assertEquals(clientID, info.getID());
		assertEquals(now, info.getIDIssueDate());
		assertEquals("Example app", info.getMetadata().getName());
		assertEquals("Example app", info.getOIDCMetadata().getName());
		assertEquals(secret, info.getSecret());
		assertEquals(regURI, info.getRegistrationURI());
		assertEquals(accessToken, info.getRegistrationAccessToken());
	}


	public void testNoClientSecretExpiration()
		throws Exception {

		ClientID clientID = new ClientID("123");
		Date now = new Date(new Date().getTime() / 1000 * 1000);
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		Secret secret = new Secret("secret", null);
		URI regURI = new URI("https://c2id.com/client-reg/123");
		BearerAccessToken accessToken = new BearerAccessToken("xyz");

		OIDCClientInformation info = new OIDCClientInformation(clientID, now, metadata, secret, regURI, accessToken);

		assertFalse(info.getSecret().expired());

		String jsonString = info.toJSONObject().toJSONString();

		info = OIDCClientInformation.parse(JSONObjectUtils.parse(jsonString));

		assertFalse(info.getSecret().expired());
	}
}
