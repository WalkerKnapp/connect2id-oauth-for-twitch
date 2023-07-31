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

package com.nimbusds.oauth2.sdk.client;


import java.net.URI;
import java.util.Date;
import java.util.List;
import java.util.Set;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


public class ClientInformationTest extends TestCase {


	public void testRegisteredParameters() {

		Set<String> paramNames = ClientInformation.getRegisteredParameterNames();

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
		assertTrue(paramNames.contains("token_endpoint_auth_signing_alg"));
		assertTrue(paramNames.contains("scope"));
		assertTrue(paramNames.contains("grant_types"));
		assertTrue(paramNames.contains("response_types"));
		assertTrue(paramNames.contains("jwks_uri"));
		assertTrue(paramNames.contains("jwks"));
		assertTrue(paramNames.contains("request_uris"));
		assertTrue(paramNames.contains("request_object_signing_alg"));
		assertTrue(paramNames.contains("request_object_encryption_alg"));
		assertTrue(paramNames.contains("request_object_encryption_enc"));
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
		assertTrue(paramNames.contains("authorization_details_types"));
		assertTrue(paramNames.contains("backchannel_token_delivery_mode"));
		assertTrue(paramNames.contains("backchannel_client_notification_endpoint"));
		assertTrue(paramNames.contains("backchannel_authentication_request_signing_alg"));
		assertTrue(paramNames.contains("backchannel_user_code_parameter"));
		assertTrue(paramNames.contains("organization_name"));
		assertTrue(paramNames.contains("signed_jwks_uri"));
		assertTrue(paramNames.contains("client_registration_types"));

		assertEquals(45, paramNames.size());
	}
	
	
	public void testSuperMinimalConstructor()
		throws Exception {
		
		ClientID clientID = new ClientID("123");
		ClientMetadata metadata = new ClientMetadata();
		metadata.setName("Example app");
		
		ClientInformation info = new ClientInformation(clientID, metadata);
		
		assertEquals(clientID, info.getID());
		assertNull(info.getIDIssueDate());
		assertEquals(metadata, info.getMetadata());
		assertEquals("Example app", info.getMetadata().getName());
		assertNull(info.getSecret());
		assertNull(info.getRegistrationURI());
		assertNull(info.getRegistrationAccessToken());
		
		String json = info.toJSONObject().toJSONString();
		
		info = ClientInformation.parse(JSONObjectUtils.parse(json));
		
		assertEquals(clientID, info.getID());
		assertNull(info.getIDIssueDate());
		assertEquals("Example app", info.getMetadata().getName());
		assertNull(info.getSecret());
		assertNull(info.getRegistrationURI());
		assertNull(info.getRegistrationAccessToken());
	}


	public void testMinimalConstructor()
		throws Exception {

		ClientID clientID = new ClientID("123");
		ClientMetadata metadata = new ClientMetadata();
		metadata.setName("Example app");

		ClientInformation info = new ClientInformation(clientID, null, metadata, null);

		assertEquals(clientID, info.getID());
		assertNull(info.getIDIssueDate());
		assertEquals(metadata, info.getMetadata());
		assertEquals("Example app", info.getMetadata().getName());
		assertNull(info.getSecret());
		assertNull(info.getRegistrationURI());
		assertNull(info.getRegistrationAccessToken());

		String json = info.toJSONObject().toJSONString();

		info = ClientInformation.parse(JSONObjectUtils.parse(json));

		assertEquals(clientID, info.getID());
		assertNull(info.getIDIssueDate());
		assertEquals("Example app", info.getMetadata().getName());
		assertNull(info.getSecret());
		assertNull(info.getRegistrationURI());
		assertNull(info.getRegistrationAccessToken());

		Date now = new Date(new Date().getTime() / 1000 * 1000);
		Secret secret = new Secret("secret");

		info = new ClientInformation(clientID, now, metadata, secret);

		assertEquals(clientID, info.getID());
		assertEquals(now, info.getIDIssueDate());
		assertEquals(metadata, info.getMetadata());
		assertEquals("Example app", info.getMetadata().getName());
		assertEquals(secret, info.getSecret());
		assertNull(info.getRegistrationURI());
		assertNull(info.getRegistrationAccessToken());

		json = info.toJSONObject().toJSONString();

		info = ClientInformation.parse(JSONObjectUtils.parse(json));

		assertEquals(clientID, info.getID());
		assertEquals(now, info.getIDIssueDate());
		assertEquals("Example app", info.getMetadata().getName());
		assertEquals(secret, info.getSecret());
		assertNull(info.getRegistrationURI());
		assertNull(info.getRegistrationAccessToken());
	}


	public void testFullConstructor()
		throws Exception {

		ClientID clientID = new ClientID("123");
		ClientMetadata metadata = new ClientMetadata();
		metadata.setName("Example app");

		ClientInformation info = new ClientInformation(clientID, null, metadata, null, null, null);

		assertEquals(clientID, info.getID());
		assertNull(info.getIDIssueDate());
		assertEquals(metadata, info.getMetadata());
		assertEquals("Example app", info.getMetadata().getName());
		assertNull(info.getSecret());
		assertNull(info.getRegistrationURI());
		assertNull(info.getRegistrationAccessToken());

		String json = info.toJSONObject().toJSONString();

		info = ClientInformation.parse(JSONObjectUtils.parse(json));

		assertEquals(clientID, info.getID());
		assertNull(info.getIDIssueDate());
		assertEquals("Example app", info.getMetadata().getName());
		assertNull(info.getSecret());
		assertNull(info.getRegistrationURI());
		assertNull(info.getRegistrationAccessToken());

		Date now = new Date(new Date().getTime() / 1000 * 1000);
		Secret secret = new Secret("secret");
		URI regURI = new URI("https://c2id.com/client-reg/123");
		BearerAccessToken accessToken = new BearerAccessToken("xyz");

		info = new ClientInformation(clientID, now, metadata, secret, regURI, accessToken);

		assertEquals(clientID, info.getID());
		assertEquals(now, info.getIDIssueDate());
		assertEquals(metadata, info.getMetadata());
		assertEquals("Example app", info.getMetadata().getName());
		assertEquals(secret, info.getSecret());
		assertEquals(regURI, info.getRegistrationURI());
		assertEquals(accessToken, info.getRegistrationAccessToken());

		json = info.toJSONObject().toJSONString();

		info = ClientInformation.parse(JSONObjectUtils.parse(json));

		assertEquals(clientID, info.getID());
		assertEquals(now, info.getIDIssueDate());
		assertEquals("Example app", info.getMetadata().getName());
		assertEquals(secret, info.getSecret());
		assertEquals(regURI, info.getRegistrationURI());
		assertEquals(accessToken, info.getRegistrationAccessToken());
	}


	public void testNoSecretExpiration()
		throws Exception {

		ClientID clientID = new ClientID("123");
		ClientMetadata metadata = new ClientMetadata();
		metadata.setRedirectionURI(new URI("https://example.com/in"));
		Secret secret = new Secret("secret");
		assertFalse(secret.expired());

		ClientInformation clientInfo = new ClientInformation(clientID, null, metadata, secret);

		assertEquals(clientID, clientInfo.getID());
		assertNull(clientInfo.getIDIssueDate());
		assertEquals(metadata, clientInfo.getMetadata());
		assertEquals(secret, clientInfo.getSecret());
		assertFalse(clientInfo.getSecret().expired());
		assertNull(clientInfo.getRegistrationURI());
		assertNull(clientInfo.getRegistrationAccessToken());

		JSONObject o = clientInfo.toJSONObject();
		assertEquals("123", (String)o.get("client_id"));
		assertEquals("https://example.com/in", ((List<String>)o.get("redirect_uris")).get(0));
		assertEquals("secret", (String)o.get("client_secret"));
		assertEquals(0L, ((Long)o.get("client_secret_expires_at")).longValue());
		assertEquals(4, o.size());

		String jsonString = o.toJSONString();

		o = JSONObjectUtils.parse(jsonString);

		clientInfo = ClientInformation.parse(o);

		assertEquals("123", clientInfo.getID().toString());
		assertNull(clientInfo.getIDIssueDate());
		assertEquals("https://example.com/in", clientInfo.getMetadata().getRedirectionURIs().iterator().next().toString());
		assertEquals("secret", clientInfo.getSecret().getValue());
		assertFalse(clientInfo.getSecret().expired());
		assertNull(clientInfo.getSecret().getExpirationDate());
		assertNull(clientInfo.getRegistrationURI());
		assertNull(clientInfo.getRegistrationAccessToken());
	}


	public void testNoSecretExpirationAlt()
		throws Exception {

		ClientID clientID = new ClientID("123");
		ClientMetadata metadata = new ClientMetadata();
		metadata.setRedirectionURI(new URI("https://example.com/in"));
		Secret secret = new Secret("secret", null);
		assertFalse(secret.expired());

		ClientInformation clientInfo = new ClientInformation(clientID, null, metadata, secret);

		assertEquals(clientID, clientInfo.getID());
		assertNull(clientInfo.getIDIssueDate());
		assertEquals(metadata, clientInfo.getMetadata());
		assertEquals(secret, clientInfo.getSecret());
		assertFalse(clientInfo.getSecret().expired());
		assertNull(clientInfo.getRegistrationURI());
		assertNull(clientInfo.getRegistrationAccessToken());

		JSONObject o = clientInfo.toJSONObject();
		assertEquals("123", (String)o.get("client_id"));
		assertEquals("https://example.com/in", ((List<String>)o.get("redirect_uris")).get(0));
		assertEquals("secret", (String)o.get("client_secret"));
		assertEquals(0L, ((Long)o.get("client_secret_expires_at")).longValue());
		assertEquals(4, o.size());

		String jsonString = o.toJSONString();

		o = JSONObjectUtils.parse(jsonString);

		clientInfo = ClientInformation.parse(o);

		assertEquals("123", clientInfo.getID().toString());
		assertNull(clientInfo.getIDIssueDate());
		assertEquals("https://example.com/in", clientInfo.getMetadata().getRedirectionURIs().iterator().next().toString());
		assertEquals("secret", clientInfo.getSecret().getValue());
		assertNull(clientInfo.getSecret().getExpirationDate());
		assertFalse(clientInfo.getSecret().expired());
		assertNull(clientInfo.getRegistrationURI());
		assertNull(clientInfo.getRegistrationAccessToken());
	}


	public void testInferConfidentialClientType() {

		ClientID clientID = new ClientID();
		Date issueDate = new Date();
		ClientMetadata metadata = new ClientMetadata();
		metadata.applyDefaults();
		Secret secret = new Secret();


		ClientInformation client;

		// default
		client = new ClientInformation(clientID, issueDate, metadata, secret);
		assertEquals(ClientType.CONFIDENTIAL, client.inferClientType());

		// basic auth
		metadata = new ClientMetadata();
		metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		metadata.applyDefaults();

		client = new ClientInformation(clientID, issueDate, metadata, secret);
		assertEquals(ClientType.CONFIDENTIAL, client.inferClientType());

		// basic post auth
		metadata = new ClientMetadata();
		metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
		metadata.applyDefaults();

		client = new ClientInformation(clientID, issueDate, metadata, secret);
		assertEquals(ClientType.CONFIDENTIAL, client.inferClientType());

		// secret JWT auth
		metadata = new ClientMetadata();
		metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
		metadata.applyDefaults();

		client = new ClientInformation(clientID, issueDate, metadata, secret);
		assertEquals(ClientType.CONFIDENTIAL, client.inferClientType());

		// private key JWT auth - JWK by ref
		metadata = new ClientMetadata();
		metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
		metadata.setJWKSetURI(URI.create("https://example.com/jwks.json"));
		metadata.applyDefaults();

		client = new ClientInformation(clientID, issueDate, metadata, secret);
		assertEquals(ClientType.CONFIDENTIAL, client.inferClientType());

		// private key JWT auth - JWK by value
		metadata = new ClientMetadata();
		metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
		metadata.setJWKSet(new JWKSet());
		metadata.applyDefaults();

		client = new ClientInformation(clientID, issueDate, metadata, secret);
		assertEquals(ClientType.CONFIDENTIAL, client.inferClientType());

		// private key JWT auth - unspecified key source
		metadata = new ClientMetadata();
		metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
		metadata.setJWKSet(new JWKSet());
		metadata.applyDefaults();

		client = new ClientInformation(clientID, issueDate, metadata, secret);
		assertEquals(ClientType.CONFIDENTIAL, client.inferClientType());

		// secret set, but token endpoint auth method = null
		metadata = new ClientMetadata();

		client = new ClientInformation(clientID, issueDate, metadata, secret);
		assertEquals(ClientType.CONFIDENTIAL, client.inferClientType());

		// secret = null, token endpoint auth method = null
		metadata = new ClientMetadata();

		client = new ClientInformation(clientID, issueDate, metadata, null);
		assertEquals(ClientType.CONFIDENTIAL, client.inferClientType());
	}


	public void testInferPublicClientType() {

		ClientID clientID = new ClientID();
		Date issueDate = new Date();
		ClientMetadata metadata = new ClientMetadata();
		metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.NONE);
		metadata.applyDefaults();
		Secret secret = null;

		ClientInformation client;

		client = new ClientInformation(clientID, issueDate, metadata, secret);
		assertEquals(ClientType.PUBLIC, client.inferClientType());
	}
}
