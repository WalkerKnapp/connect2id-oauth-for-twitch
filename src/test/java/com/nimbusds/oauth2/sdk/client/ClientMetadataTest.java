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
import java.net.URISyntaxException;
import java.util.*;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;
import org.apache.commons.math3.util.Combinations;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.ciba.BackChannelTokenDeliveryMode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.SoftwareID;
import com.nimbusds.oauth2.sdk.id.SoftwareVersion;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.federation.registration.ClientRegistrationType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;


public class ClientMetadataTest extends TestCase {


	public void testRegisteredParameters() {

		Set<String> paramNames = ClientMetadata.getRegisteredParameterNames();

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
		assertTrue(paramNames.contains("backchannel_token_delivery_mode"));
		assertTrue(paramNames.contains("backchannel_client_notification_endpoint"));
		assertTrue(paramNames.contains("backchannel_authentication_request_signing_alg"));
		assertTrue(paramNames.contains("backchannel_user_code_parameter"));
		assertTrue(paramNames.contains("organization_name"));
		assertTrue(paramNames.contains("signed_jwks_uri"));
		assertTrue(paramNames.contains("client_registration_types"));
		assertEquals(38, ClientMetadata.getRegisteredParameterNames().size());
	}
	
	
	public void testProhibitedRedirectURISchemes() {
		
		assertTrue(ClientMetadata.PROHIBITED_REDIRECT_URI_SCHEMES.contains("data"));
		assertTrue(ClientMetadata.PROHIBITED_REDIRECT_URI_SCHEMES.contains("javascript"));
		assertTrue(ClientMetadata.PROHIBITED_REDIRECT_URI_SCHEMES.contains("vbscript"));
		assertEquals(3, ClientMetadata.PROHIBITED_REDIRECT_URI_SCHEMES.size());
	}
	
	
	public void testSerializeAndParse()
		throws Exception {
		
		ClientMetadata meta = new ClientMetadata();
		
		Set<URI> redirectURIs = new HashSet<>();
		redirectURIs.add(new URI("http://example.com/1"));
		redirectURIs.add(new URI("http://example.com/2"));
		meta.setRedirectionURIs(redirectURIs);
		
		Scope scope = Scope.parse("read write");
		assertFalse(meta.hasScopeValue(new Scope.Value("read")));
		meta.setScope(scope);
		assertTrue(meta.hasScopeValue(new Scope.Value("read")));
		assertTrue(meta.hasScopeValue(new Scope.Value("write")));

		Set<ResponseType> rts = new HashSet<>();
		rts.add(ResponseType.parse("code id_token"));
		meta.setResponseTypes(rts);
		
		Set<GrantType> grantTypes = new HashSet<>();
		grantTypes.add(GrantType.AUTHORIZATION_CODE);
		grantTypes.add(GrantType.REFRESH_TOKEN);
		meta.setGrantTypes(grantTypes);
		
		List<String> contacts = new LinkedList<>();
		contacts.add("alice@wonderland.net");
		contacts.add("admin@wonderland.net");
		meta.setEmailContacts(contacts);
		
		String name = "My Example App";
		meta.setName(name);
		
		String nameDE = "Mein Beispiel App";
		meta.setName(nameDE, LangTag.parse("de"));
		
		URI logo = new URI("http://example.com/logo.png");
		meta.setLogoURI(logo);
		
		URI logoDE = new URI("http://example.com/de/logo.png");
		meta.setLogoURI(logoDE, LangTag.parse("de"));
		
		URI uri = new URI("http://example.com");
		meta.setURI(uri);
		
		URI uriDE = new URI("http://example.com/de");
		meta.setURI(uriDE, LangTag.parse("de"));
		
		URI policy = new URI("http://example.com/policy");
		meta.setPolicyURI(policy);
		
		URI policyDE = new URI("http://example.com/de/policy");
		meta.setPolicyURI(policyDE, LangTag.parse("de"));
		
		URI tos = new URI("http://example.com/tos");
		meta.setTermsOfServiceURI(tos);
		
		URI tosDE = new URI("http://example.com/de/tos");
		meta.setTermsOfServiceURI(tosDE, LangTag.parse("de"));
		
		ClientAuthenticationMethod authMethod = ClientAuthenticationMethod.CLIENT_SECRET_JWT;
		meta.setTokenEndpointAuthMethod(authMethod);

		JWSAlgorithm authJWSAlg = JWSAlgorithm.HS256;
		meta.setTokenEndpointAuthJWSAlg(authJWSAlg);
		
		URI jwksURI = new URI("http://example.com/jwks.json");
		meta.setJWKSetURI(jwksURI);

		RSAKey rsaKey = new RSAKey.Builder(new Base64URL("nabc"), new Base64URL("eabc")).build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		meta.setJWKSet(jwkSet);
		
		Set<URI> requestObjURIs = Collections.singleton(new URI("http://client.com/reqobj"));
		meta.setRequestObjectURIs(requestObjURIs);
		meta.setRequestObjectJWSAlg(JWSAlgorithm.HS512);
		meta.setRequestObjectJWEAlg(JWEAlgorithm.A128KW);
		meta.setRequestObjectJWEEnc(EncryptionMethod.A128GCM);

		SoftwareID softwareID = new SoftwareID();
		meta.setSoftwareID(softwareID);

		SoftwareVersion softwareVersion = new SoftwareVersion("1.0");
		meta.setSoftwareVersion(softwareVersion);
		
		meta.setBackChannelTokenDeliveryMode(BackChannelTokenDeliveryMode.PUSH);
		URI cibaEndpoint = new URI("http://example.com/ciba");
		meta.setBackChannelClientNotificationEndpoint(cibaEndpoint);
		meta.setBackChannelAuthRequestJWSAlg(JWSAlgorithm.RS256);
		meta.setSupportsBackChannelUserCodeParam(true);
		
		assertFalse(meta.getTLSClientCertificateBoundAccessTokens());
		assertFalse(meta.getMutualTLSSenderConstrainedAccessTokens());
		meta.setTLSClientCertificateBoundAccessTokens(true);
		
		assertNull(meta.getTLSClientAuthSubjectDN());
		String subjectDN = "cn=123";
		meta.setTLSClientAuthSubjectDN(subjectDN);
		
		assertNull(meta.getTLSClientAuthSanDNS());
		String sanDNS = "example.com";
		meta.setTLSClientAuthSanDNS(sanDNS);
		
		assertNull(meta.getTLSClientAuthSanURI());
		String sanURI = "http://example.com/";
		meta.setTLSClientAuthSanURI(sanURI);
		
		assertNull(meta.getTLSClientAuthSanIP());
		String sanIP = "1.2.3.4";
		meta.setTLSClientAuthSanIP(sanIP);
		
		assertNull(meta.getTLSClientAuthSanEmail());
		String sanEmail= "me@example.com";
		meta.setTLSClientAuthSanEmail(sanEmail);

		
		JWSAlgorithm authzJWSAlg = JWSAlgorithm.ES512;
		meta.setAuthorizationJWSAlg(authzJWSAlg);
		assertEquals(authzJWSAlg, meta.getAuthorizationJWSAlg());
		
		JWEAlgorithm authzJWEAlg = JWEAlgorithm.ECDH_ES_A256KW;
		meta.setAuthorizationJWEAlg(authzJWEAlg);
		assertEquals(authzJWEAlg, meta.getAuthorizationJWEAlg());
		
		EncryptionMethod authzJWEEnc = EncryptionMethod.A256GCM;
		meta.setAuthorizationJWEEnc(authzJWEEnc);
		assertEquals(authzJWEEnc, meta.getAuthorizationJWEEnc());
		
		// Test getters
		assertEquals(redirectURIs, meta.getRedirectionURIs());
		assertEquals(scope, meta.getScope());
		assertEquals(grantTypes, meta.getGrantTypes());
		assertEquals(contacts, meta.getEmailContacts());
		assertEquals(name, meta.getName());
		assertEquals(nameDE, meta.getName(LangTag.parse("de")));
		assertEquals(2, meta.getNameEntries().size());
		assertEquals(logo, meta.getLogoURI());
		assertEquals(logoDE, meta.getLogoURI(LangTag.parse("de")));
		assertEquals(2, meta.getLogoURIEntries().size());
		assertEquals(uri, meta.getURI());
		assertEquals(uriDE, meta.getURI(LangTag.parse("de")));
		assertEquals(2, meta.getURIEntries().size());
		assertEquals(policy, meta.getPolicyURI());
		assertEquals(policyDE, meta.getPolicyURI(LangTag.parse("de")));
		assertEquals(2, meta.getPolicyURIEntries().size());
		assertEquals(tos, meta.getTermsOfServiceURI());
		assertEquals(tosDE, meta.getTermsOfServiceURI(LangTag.parse("de")));
		assertEquals(2, meta.getTermsOfServiceURIEntries().size());
		assertEquals(authMethod, meta.getTokenEndpointAuthMethod());
		assertEquals(authJWSAlg, meta.getTokenEndpointAuthJWSAlg());
		assertEquals(jwksURI, meta.getJWKSetURI());
		assertEquals("nabc", ((RSAKey)meta.getJWKSet().getKeys().get(0)).getModulus().toString());
		assertEquals("eabc", ((RSAKey)meta.getJWKSet().getKeys().get(0)).getPublicExponent().toString());
		assertEquals(requestObjURIs, meta.getRequestObjectURIs());
		assertEquals(JWSAlgorithm.HS512, meta.getRequestObjectJWSAlg());
		assertEquals(JWEAlgorithm.A128KW, meta.getRequestObjectJWEAlg());
		assertEquals(EncryptionMethod.A128GCM, meta.getRequestObjectJWEEnc());
		assertEquals(1, meta.getJWKSet().getKeys().size());
		assertEquals(softwareID, meta.getSoftwareID());
		assertEquals(softwareVersion, meta.getSoftwareVersion());
		assertTrue(meta.getTLSClientCertificateBoundAccessTokens());
		assertTrue(meta.getMutualTLSSenderConstrainedAccessTokens());
		assertEquals(subjectDN, meta.getTLSClientAuthSubjectDN());
		assertEquals(sanDNS, meta.getTLSClientAuthSanDNS());
		assertEquals(sanURI, meta.getTLSClientAuthSanURI());
		assertEquals(sanIP, meta.getTLSClientAuthSanIP());
		assertEquals(sanEmail, meta.getTLSClientAuthSanEmail());
		assertEquals(authzJWSAlg, meta.getAuthorizationJWSAlg());
		assertEquals(authzJWEAlg, meta.getAuthorizationJWEAlg());
		assertEquals(authzJWEEnc, meta.getAuthorizationJWEEnc());
		assertTrue(meta.getCustomFields().isEmpty());
		
		assertEquals(cibaEndpoint, meta.getBackChannelClientNotificationEndpoint());
		assertTrue(meta.supportsBackChannelUserCodeParam());
		assertEquals(BackChannelTokenDeliveryMode.PUSH, meta.getBackChannelTokenDeliveryMode());
		assertEquals(JWSAlgorithm.RS256, meta.getBackChannelAuthRequestJWSAlg());
		
		String json = meta.toJSONObject().toJSONString();
		
		JSONObject jsonObject = JSONObjectUtils.parse(json);
		
		meta = ClientMetadata.parse(jsonObject);
		
		// Test getters
		assertEquals(redirectURIs, meta.getRedirectionURIs());
		assertEquals(scope, meta.getScope());
		assertTrue(meta.hasScopeValue(new Scope.Value("read")));
		assertTrue(meta.hasScopeValue(new Scope.Value("write")));
		assertEquals(grantTypes, meta.getGrantTypes());
		assertEquals(contacts, meta.getEmailContacts());
		assertEquals(name, meta.getName());
		assertEquals(nameDE, meta.getName(LangTag.parse("de")));
		assertEquals(2, meta.getNameEntries().size());
		assertEquals(logo, meta.getLogoURI());
		assertEquals(logoDE, meta.getLogoURI(LangTag.parse("de")));
		assertEquals(2, meta.getLogoURIEntries().size());
		assertEquals(uri, meta.getURI());
		assertEquals(uriDE, meta.getURI(LangTag.parse("de")));
		assertEquals(2, meta.getURIEntries().size());
		assertEquals(policy, meta.getPolicyURI());
		assertEquals(policyDE, meta.getPolicyURI(LangTag.parse("de")));
		assertEquals(2, meta.getPolicyURIEntries().size());
		assertEquals(tos, meta.getTermsOfServiceURI());
		assertEquals(tosDE, meta.getTermsOfServiceURI(LangTag.parse("de")));
		assertEquals(2, meta.getTermsOfServiceURIEntries().size());
		assertEquals(authMethod, meta.getTokenEndpointAuthMethod());
		assertEquals(authJWSAlg, meta.getTokenEndpointAuthJWSAlg());
		assertEquals(jwksURI, meta.getJWKSetURI());
		assertEquals("nabc", ((RSAKey)meta.getJWKSet().getKeys().get(0)).getModulus().toString());
		assertEquals("eabc", ((RSAKey)meta.getJWKSet().getKeys().get(0)).getPublicExponent().toString());
		assertEquals(1, meta.getJWKSet().getKeys().size());
		assertEquals(requestObjURIs, meta.getRequestObjectURIs());
		assertEquals(JWSAlgorithm.HS512, meta.getRequestObjectJWSAlg());
		assertEquals(JWEAlgorithm.A128KW, meta.getRequestObjectJWEAlg());
		assertEquals(EncryptionMethod.A128GCM, meta.getRequestObjectJWEEnc());
		assertEquals(softwareID, meta.getSoftwareID());
		assertEquals(softwareVersion, meta.getSoftwareVersion());
		assertTrue(meta.getTLSClientCertificateBoundAccessTokens());
		assertTrue(meta.getMutualTLSSenderConstrainedAccessTokens());
		assertEquals(subjectDN, meta.getTLSClientAuthSubjectDN());
		assertEquals(authzJWSAlg, meta.getAuthorizationJWSAlg());
		assertEquals(authzJWEAlg, meta.getAuthorizationJWEAlg());
		assertEquals(authzJWEEnc, meta.getAuthorizationJWEEnc());
		assertEquals(BackChannelTokenDeliveryMode.PUSH, meta.getBackChannelTokenDeliveryMode());
		assertEquals(cibaEndpoint, meta.getBackChannelClientNotificationEndpoint());
		assertEquals(JWSAlgorithm.RS256, meta.getBackChannelAuthRequestJWSAlg());
		assertTrue(meta.supportsBackChannelUserCodeParam());
	
		assertTrue(meta.getCustomFields().isEmpty());
	}


	public void testSerializeAndParse_deprecatedInternetAddressContacts()
		throws Exception {
		
		ClientMetadata meta = new ClientMetadata();
		
		Set<URI> redirectURIs = new HashSet<>();
		redirectURIs.add(new URI("http://example.com/1"));
		redirectURIs.add(new URI("http://example.com/2"));
		meta.setRedirectionURIs(redirectURIs);
		
		Scope scope = Scope.parse("read write");
		assertFalse(meta.hasScopeValue(new Scope.Value("read")));
		meta.setScope(scope);
		assertTrue(meta.hasScopeValue(new Scope.Value("read")));
		assertTrue(meta.hasScopeValue(new Scope.Value("write")));

		Set<ResponseType> rts = new HashSet<>();
		rts.add(ResponseType.parse("code id_token"));
		meta.setResponseTypes(rts);
		
		Set<GrantType> grantTypes = new HashSet<>();
		grantTypes.add(GrantType.AUTHORIZATION_CODE);
		grantTypes.add(GrantType.REFRESH_TOKEN);
		meta.setGrantTypes(grantTypes);
		
		List<String> contacts = new LinkedList<>();
		contacts.add("alice@wonderland.net");
		contacts.add("admin@wonderland.net");
		meta.setEmailContacts(contacts);
		
		String name = "My Example App";
		meta.setName(name);
		
		String nameDE = "Mein Beispiel App";
		meta.setName(nameDE, LangTag.parse("de"));
		
		URI logo = new URI("http://example.com/logo.png");
		meta.setLogoURI(logo);
		
		URI logoDE = new URI("http://example.com/de/logo.png");
		meta.setLogoURI(logoDE, LangTag.parse("de"));
		
		URI uri = new URI("http://example.com");
		meta.setURI(uri);
		
		URI uriDE = new URI("http://example.com/de");
		meta.setURI(uriDE, LangTag.parse("de"));
		
		URI policy = new URI("http://example.com/policy");
		meta.setPolicyURI(policy);
		
		URI policyDE = new URI("http://example.com/de/policy");
		meta.setPolicyURI(policyDE, LangTag.parse("de"));
		
		URI tos = new URI("http://example.com/tos");
		meta.setTermsOfServiceURI(tos);
		
		URI tosDE = new URI("http://example.com/de/tos");
		meta.setTermsOfServiceURI(tosDE, LangTag.parse("de"));
		
		ClientAuthenticationMethod authMethod = ClientAuthenticationMethod.CLIENT_SECRET_JWT;
		meta.setTokenEndpointAuthMethod(authMethod);

		JWSAlgorithm authJWSAlg = JWSAlgorithm.HS256;
		meta.setTokenEndpointAuthJWSAlg(authJWSAlg);
		
		URI jwksURI = new URI("http://example.com/jwks.json");
		meta.setJWKSetURI(jwksURI);

		RSAKey rsaKey = new RSAKey.Builder(new Base64URL("nabc"), new Base64URL("eabc")).build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		meta.setJWKSet(jwkSet);

		SoftwareID softwareID = new SoftwareID();
		meta.setSoftwareID(softwareID);

		SoftwareVersion softwareVersion = new SoftwareVersion("1.0");
		meta.setSoftwareVersion(softwareVersion);
		
		meta.setBackChannelTokenDeliveryMode(BackChannelTokenDeliveryMode.PUSH);
		URI cibaEndpoint = new URI("http://example.com/de/cn");
		meta.setBackChannelClientNotificationEndpoint(cibaEndpoint);
		meta.setBackChannelAuthRequestJWSAlg(JWSAlgorithm.RS256);
		meta.setSupportsBackChannelUserCodeParam(true);
		
		
		// Test getters
		assertEquals(redirectURIs, meta.getRedirectionURIs());
		assertEquals(scope, meta.getScope());
		assertEquals(grantTypes, meta.getGrantTypes());
		assertEquals(contacts, meta.getEmailContacts());
		assertEquals(name, meta.getName());
		assertEquals(nameDE, meta.getName(LangTag.parse("de")));
		assertEquals(2, meta.getNameEntries().size());
		assertEquals(logo, meta.getLogoURI());
		assertEquals(logoDE, meta.getLogoURI(LangTag.parse("de")));
		assertEquals(2, meta.getLogoURIEntries().size());
		assertEquals(uri, meta.getURI());
		assertEquals(uriDE, meta.getURI(LangTag.parse("de")));
		assertEquals(2, meta.getURIEntries().size());
		assertEquals(policy, meta.getPolicyURI());
		assertEquals(policyDE, meta.getPolicyURI(LangTag.parse("de")));
		assertEquals(2, meta.getPolicyURIEntries().size());
		assertEquals(tos, meta.getTermsOfServiceURI());
		assertEquals(tosDE, meta.getTermsOfServiceURI(LangTag.parse("de")));
		assertEquals(2, meta.getTermsOfServiceURIEntries().size());
		assertEquals(authMethod, meta.getTokenEndpointAuthMethod());
		assertEquals(authJWSAlg, meta.getTokenEndpointAuthJWSAlg());
		assertEquals(jwksURI, meta.getJWKSetURI());
		assertEquals("nabc", ((RSAKey)meta.getJWKSet().getKeys().get(0)).getModulus().toString());
		assertEquals("eabc", ((RSAKey)meta.getJWKSet().getKeys().get(0)).getPublicExponent().toString());
		assertEquals(1, meta.getJWKSet().getKeys().size());
		assertEquals(softwareID, meta.getSoftwareID());
		assertEquals(softwareVersion, meta.getSoftwareVersion());
		assertEquals(BackChannelTokenDeliveryMode.PUSH, meta.getBackChannelTokenDeliveryMode());
		assertEquals(cibaEndpoint, meta.getBackChannelClientNotificationEndpoint());
		assertEquals(JWSAlgorithm.RS256, meta.getBackChannelAuthRequestJWSAlg());
		assertTrue(meta.supportsBackChannelUserCodeParam());
		assertTrue(meta.getCustomFields().isEmpty());
		
		String json = meta.toJSONObject().toJSONString();
		
		JSONObject jsonObject = JSONObjectUtils.parse(json);
		
		meta = ClientMetadata.parse(jsonObject);
		
		// Test getters
		assertEquals(redirectURIs, meta.getRedirectionURIs());
		assertEquals(scope, meta.getScope());
		assertTrue(meta.hasScopeValue(new Scope.Value("read")));
		assertTrue(meta.hasScopeValue(new Scope.Value("write")));
		assertEquals(grantTypes, meta.getGrantTypes());
		assertEquals(contacts, meta.getEmailContacts());
		assertEquals(name, meta.getName());
		assertEquals(nameDE, meta.getName(LangTag.parse("de")));
		assertEquals(2, meta.getNameEntries().size());
		assertEquals(logo, meta.getLogoURI());
		assertEquals(logoDE, meta.getLogoURI(LangTag.parse("de")));
		assertEquals(2, meta.getLogoURIEntries().size());
		assertEquals(uri, meta.getURI());
		assertEquals(uriDE, meta.getURI(LangTag.parse("de")));
		assertEquals(2, meta.getURIEntries().size());
		assertEquals(policy, meta.getPolicyURI());
		assertEquals(policyDE, meta.getPolicyURI(LangTag.parse("de")));
		assertEquals(2, meta.getPolicyURIEntries().size());
		assertEquals(tos, meta.getTermsOfServiceURI());
		assertEquals(tosDE, meta.getTermsOfServiceURI(LangTag.parse("de")));
		assertEquals(2, meta.getTermsOfServiceURIEntries().size());
		assertEquals(authMethod, meta.getTokenEndpointAuthMethod());
		assertEquals(authJWSAlg, meta.getTokenEndpointAuthJWSAlg());
		assertEquals(jwksURI, meta.getJWKSetURI());
		assertEquals("nabc", ((RSAKey)meta.getJWKSet().getKeys().get(0)).getModulus().toString());
		assertEquals("eabc", ((RSAKey)meta.getJWKSet().getKeys().get(0)).getPublicExponent().toString());
		assertEquals(1, meta.getJWKSet().getKeys().size());
		assertEquals(softwareID, meta.getSoftwareID());
		assertEquals(softwareVersion, meta.getSoftwareVersion());
		
		assertEquals(cibaEndpoint, meta.getBackChannelClientNotificationEndpoint());
		assertTrue(meta.supportsBackChannelUserCodeParam());
		assertEquals(BackChannelTokenDeliveryMode.PUSH, meta.getBackChannelTokenDeliveryMode());
		assertEquals(JWSAlgorithm.RS256, meta.getBackChannelAuthRequestJWSAlg());
	
		assertTrue(meta.getCustomFields().isEmpty());
	}


	public void testCopyConstructor()
		throws Exception {

		ClientMetadata meta = new ClientMetadata();

		Set<URI> redirectURIs = new HashSet<>();
		redirectURIs.add(new URI("http://example.com/1"));
		redirectURIs.add(new URI("http://example.com/2"));
		meta.setRedirectionURIs(redirectURIs);

		Scope scope = Scope.parse("read write");
		meta.setScope(scope);

		Set<ResponseType> rts = new HashSet<>();
		rts.add(ResponseType.parse("code id_token"));
		meta.setResponseTypes(rts);

		Set<GrantType> grantTypes = new HashSet<>();
		grantTypes.add(GrantType.AUTHORIZATION_CODE);
		grantTypes.add(GrantType.REFRESH_TOKEN);
		meta.setGrantTypes(grantTypes);

		List<String> contacts = new LinkedList<>();
		contacts.add("alice@wonderland.net");
		contacts.add("admin@wonderland.net");
		meta.setEmailContacts(contacts);

		String name = "My Example App";
		meta.setName(name);

		String nameDE = "Mein Beispiel App";
		meta.setName(nameDE, LangTag.parse("de"));

		URI logo = new URI("http://example.com/logo.png");
		meta.setLogoURI(logo);

		URI logoDE = new URI("http://example.com/de/logo.png");
		meta.setLogoURI(logoDE, LangTag.parse("de"));

		URI uri = new URI("http://example.com");
		meta.setURI(uri);

		URI uriDE = new URI("http://example.com/de");
		meta.setURI(uriDE, LangTag.parse("de"));

		URI policy = new URI("http://example.com/policy");
		meta.setPolicyURI(policy);

		URI policyDE = new URI("http://example.com/de/policy");
		meta.setPolicyURI(policyDE, LangTag.parse("de"));

		URI tos = new URI("http://example.com/tos");
		meta.setTermsOfServiceURI(tos);

		URI tosDE = new URI("http://example.com/de/tos");
		meta.setTermsOfServiceURI(tosDE, LangTag.parse("de"));

		ClientAuthenticationMethod authMethod = ClientAuthenticationMethod.CLIENT_SECRET_JWT;
		meta.setTokenEndpointAuthMethod(authMethod);

		JWSAlgorithm authJWSAlg = JWSAlgorithm.HS256;
		meta.setTokenEndpointAuthJWSAlg(authJWSAlg);

		URI jwksURI = new URI("http://example.com/jwks.json");
		meta.setJWKSetURI(jwksURI);

		RSAKey rsaKey = new RSAKey.Builder(new Base64URL("nabc"), new Base64URL("eabc")).build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		meta.setJWKSet(jwkSet);
		
		Set<URI> requestObjURIs = Collections.singleton(new URI("http://client.com/reqobj"));
		meta.setRequestObjectURIs(requestObjURIs);
		meta.setRequestObjectJWSAlg(JWSAlgorithm.HS512);
		meta.setRequestObjectJWEAlg(JWEAlgorithm.A128KW);
		meta.setRequestObjectJWEEnc(EncryptionMethod.A128GCM);

		SoftwareID softwareID = new SoftwareID();
		meta.setSoftwareID(softwareID);

		SoftwareVersion softwareVersion = new SoftwareVersion("1.0");
		meta.setSoftwareVersion(softwareVersion);
		
		meta.setTLSClientCertificateBoundAccessTokens(true);
		
		String subjectDN = "cn=123";
		meta.setTLSClientAuthSubjectDN(subjectDN);
		
		String sanDNS = "example.com";
		meta.setTLSClientAuthSanDNS(sanDNS);
		
		String sanURI = "http://example.com/";
		meta.setTLSClientAuthSanURI(sanURI);
		
		String sanIP = "1.2.3.4";
		meta.setTLSClientAuthSanIP(sanIP);
		
		String sanEmail= "me@example.com";
		meta.setTLSClientAuthSanEmail(sanEmail);
		
		JWSAlgorithm authzJWSAlg = JWSAlgorithm.ES512;
		meta.setAuthorizationJWSAlg(authzJWSAlg);
		
		JWEAlgorithm authzJWEAlg = JWEAlgorithm.ECDH_ES_A256KW;
		meta.setAuthorizationJWEAlg(authzJWEAlg);
		
		EncryptionMethod authzJWEEnc = EncryptionMethod.A256GCM;
		meta.setAuthorizationJWEEnc(authzJWEEnc);
		
		meta.setBackChannelTokenDeliveryMode(BackChannelTokenDeliveryMode.PUSH);
		URI cibaEndpoint = new URI("http://example.com/de/cn");
		meta.setBackChannelClientNotificationEndpoint(cibaEndpoint);
		meta.setBackChannelAuthRequestJWSAlg(JWSAlgorithm.RS256);
		meta.setSupportsBackChannelUserCodeParam(true);

		// Shallow copy
		ClientMetadata copy = new ClientMetadata(meta);

		// Test getters
		assertEquals(redirectURIs, copy.getRedirectionURIs());
		assertEquals(scope, copy.getScope());
		assertEquals(grantTypes, copy.getGrantTypes());
		assertEquals(contacts, copy.getEmailContacts());
		assertEquals(name, copy.getName());
		assertEquals(nameDE, copy.getName(LangTag.parse("de")));
		assertEquals(2, copy.getNameEntries().size());
		assertEquals(logo, copy.getLogoURI());
		assertEquals(logoDE, copy.getLogoURI(LangTag.parse("de")));
		assertEquals(2, copy.getLogoURIEntries().size());
		assertEquals(uri, copy.getURI());
		assertEquals(uriDE, copy.getURI(LangTag.parse("de")));
		assertEquals(2, copy.getURIEntries().size());
		assertEquals(policy, copy.getPolicyURI());
		assertEquals(policyDE, copy.getPolicyURI(LangTag.parse("de")));
		assertEquals(2, copy.getPolicyURIEntries().size());
		assertEquals(tos, copy.getTermsOfServiceURI());
		assertEquals(tosDE, copy.getTermsOfServiceURI(LangTag.parse("de")));
		assertEquals(2, copy.getTermsOfServiceURIEntries().size());
		assertEquals(authMethod, copy.getTokenEndpointAuthMethod());
		assertEquals(authJWSAlg, copy.getTokenEndpointAuthJWSAlg());
		assertEquals(jwksURI, copy.getJWKSetURI());
		assertEquals("nabc", ((RSAKey)copy.getJWKSet().getKeys().get(0)).getModulus().toString());
		assertEquals("eabc", ((RSAKey)copy.getJWKSet().getKeys().get(0)).getPublicExponent().toString());
		assertEquals(1, copy.getJWKSet().getKeys().size());
		assertEquals(requestObjURIs, meta.getRequestObjectURIs());
		assertEquals(JWSAlgorithm.HS512, meta.getRequestObjectJWSAlg());
		assertEquals(JWEAlgorithm.A128KW, meta.getRequestObjectJWEAlg());
		assertEquals(EncryptionMethod.A128GCM, meta.getRequestObjectJWEEnc());
		assertEquals(softwareID, copy.getSoftwareID());
		assertEquals(softwareVersion, copy.getSoftwareVersion());
		assertTrue(copy.getTLSClientCertificateBoundAccessTokens());
		assertTrue(copy.getMutualTLSSenderConstrainedAccessTokens());
		assertEquals(subjectDN, copy.getTLSClientAuthSubjectDN());
		assertEquals(sanDNS, copy.getTLSClientAuthSanDNS());
		assertEquals(sanURI, copy.getTLSClientAuthSanURI());
		assertEquals(sanIP, copy.getTLSClientAuthSanIP());
		assertEquals(sanEmail, copy.getTLSClientAuthSanEmail());
		assertTrue(copy.getCustomFields().isEmpty());
		assertEquals(authzJWSAlg, copy.getAuthorizationJWSAlg());
		assertEquals(authzJWEAlg, copy.getAuthorizationJWEAlg());
		assertEquals(authzJWEEnc, copy.getAuthorizationJWEEnc());
		
		assertEquals(BackChannelTokenDeliveryMode.PUSH, meta.getBackChannelTokenDeliveryMode());
		assertEquals(cibaEndpoint, meta.getBackChannelClientNotificationEndpoint());
		assertEquals(JWSAlgorithm.RS256, meta.getBackChannelAuthRequestJWSAlg());
		assertTrue(meta.supportsBackChannelUserCodeParam());
	
		String json = copy.toJSONObject().toJSONString();

		JSONObject jsonObject = JSONObjectUtils.parse(json);

		copy = ClientMetadata.parse(jsonObject);

		// Test getters
		assertEquals(redirectURIs, copy.getRedirectionURIs());
		assertEquals(scope, copy.getScope());
		assertEquals(grantTypes, copy.getGrantTypes());
		assertEquals(contacts, copy.getEmailContacts());
		assertEquals(name, copy.getName());
		assertEquals(nameDE, copy.getName(LangTag.parse("de")));
		assertEquals(2, copy.getNameEntries().size());
		assertEquals(logo, copy.getLogoURI());
		assertEquals(logoDE, copy.getLogoURI(LangTag.parse("de")));
		assertEquals(2, copy.getLogoURIEntries().size());
		assertEquals(uri, copy.getURI());
		assertEquals(uriDE, copy.getURI(LangTag.parse("de")));
		assertEquals(2, copy.getURIEntries().size());
		assertEquals(policy, copy.getPolicyURI());
		assertEquals(policyDE, copy.getPolicyURI(LangTag.parse("de")));
		assertEquals(2, copy.getPolicyURIEntries().size());
		assertEquals(tos, copy.getTermsOfServiceURI());
		assertEquals(tosDE, copy.getTermsOfServiceURI(LangTag.parse("de")));
		assertEquals(2, copy.getTermsOfServiceURIEntries().size());
		assertEquals(authMethod, copy.getTokenEndpointAuthMethod());
		assertEquals(authJWSAlg, copy.getTokenEndpointAuthJWSAlg());
		assertEquals(jwksURI, copy.getJWKSetURI());
		assertEquals("nabc", ((RSAKey)copy.getJWKSet().getKeys().get(0)).getModulus().toString());
		assertEquals("eabc", ((RSAKey)copy.getJWKSet().getKeys().get(0)).getPublicExponent().toString());
		assertEquals(1, copy.getJWKSet().getKeys().size());
		assertEquals(softwareID, copy.getSoftwareID());
		assertEquals(softwareVersion, copy.getSoftwareVersion());
		assertTrue(copy.getTLSClientCertificateBoundAccessTokens());
		assertTrue(copy.getMutualTLSSenderConstrainedAccessTokens());
		assertEquals(subjectDN, copy.getTLSClientAuthSubjectDN());
		assertEquals(sanDNS, copy.getTLSClientAuthSanDNS());
		assertEquals(sanURI, copy.getTLSClientAuthSanURI());
		assertEquals(sanIP, copy.getTLSClientAuthSanIP());
		assertEquals(sanEmail, copy.getTLSClientAuthSanEmail());
		assertEquals(authzJWSAlg, copy.getAuthorizationJWSAlg());
		assertEquals(authzJWEAlg, copy.getAuthorizationJWEAlg());
		assertEquals(authzJWEEnc, copy.getAuthorizationJWEEnc());
		
		assertEquals(BackChannelTokenDeliveryMode.PUSH, meta.getBackChannelTokenDeliveryMode());
		assertEquals(cibaEndpoint, meta.getBackChannelClientNotificationEndpoint());
		assertEquals(JWSAlgorithm.RS256, meta.getBackChannelAuthRequestJWSAlg());
		assertTrue(meta.supportsBackChannelUserCodeParam());
	
		assertTrue(copy.getCustomFields().isEmpty());
	}


	public void testApplyDefaults()
		throws Exception {
		
		ClientMetadata meta = new ClientMetadata();
		
		assertNull(meta.getResponseTypes());
		assertNull(meta.getGrantTypes());
		assertNull(meta.getTokenEndpointAuthMethod());
		
		meta.applyDefaults();
		
		assertEquals(Collections.singleton(new ResponseType("code")), meta.getResponseTypes());
		assertEquals(Collections.singleton(GrantType.AUTHORIZATION_CODE), meta.getGrantTypes());
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, meta.getTokenEndpointAuthMethod());
		
		// JARM
		assertNull(meta.getAuthorizationJWSAlg());
		assertNull(meta.getAuthorizationJWEAlg());
		assertNull(meta.getAuthorizationJWEEnc());
		
		assertFalse(meta.getTLSClientCertificateBoundAccessTokens());
		
		JSONObject jsonObject = meta.toJSONObject();
		
		assertEquals(Collections.singletonList("authorization_code"), JSONObjectUtils.getStringList(jsonObject, "grant_types"));
		assertEquals(Collections.singletonList("code"), JSONObjectUtils.getStringList(jsonObject, "response_types"));
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue(), jsonObject.get("token_endpoint_auth_method"));
		assertEquals(3, jsonObject.size());
		
		meta = ClientMetadata.parse(jsonObject);
		
		assertEquals(Collections.singleton(new ResponseType("code")), meta.getResponseTypes());
		assertEquals(Collections.singleton(GrantType.AUTHORIZATION_CODE), meta.getGrantTypes());
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, meta.getTokenEndpointAuthMethod());
		
		// JARM
		assertNull(meta.getAuthorizationJWSAlg());
		assertNull(meta.getAuthorizationJWEAlg());
		assertNull(meta.getAuthorizationJWEEnc());
		
		assertFalse(meta.getTLSClientCertificateBoundAccessTokens());
	}


	public void testApplyDefaults_JARM_implicitJWEEnc()
		throws Exception {
		
		ClientMetadata meta = new ClientMetadata();
		meta.setAuthorizationJWEAlg(JWEAlgorithm.ECDH_ES);
		
		meta.applyDefaults();
		
		Set<ResponseType> rts = meta.getResponseTypes();
		assertTrue(rts.contains(ResponseType.parse("code")));
		
		Set<GrantType> grantTypes = meta.getGrantTypes();
		assertTrue(grantTypes.contains(GrantType.AUTHORIZATION_CODE));
		
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, meta.getTokenEndpointAuthMethod());
		
		// JARM
		assertNull(meta.getAuthorizationJWSAlg());
		assertEquals(JWEAlgorithm.ECDH_ES, meta.getAuthorizationJWEAlg());
		assertEquals(EncryptionMethod.A128CBC_HS256, meta.getAuthorizationJWEEnc());
	}


	public void testCustomFields()
		throws Exception {

		ClientMetadata meta = new ClientMetadata();

		meta.setCustomField("x-data", "123");

		assertEquals("123", (String) meta.getCustomField("x-data"));
		assertEquals("123", (String) meta.getCustomFields().get("x-data"));
		assertEquals(1, meta.getCustomFields().size());

		String json = meta.toJSONObject().toJSONString();

		meta = ClientMetadata.parse(JSONObjectUtils.parse(json));

		assertEquals("123", (String)meta.getCustomField("x-data"));
		assertEquals("123", (String) meta.getCustomFields().get("x-data"));
		assertEquals(1, meta.getCustomFields().size());
	}


	public void testSetSingleRedirectURI()
		throws Exception {

		ClientMetadata meta = new ClientMetadata();

		URI uri = new URI("https://client.com/callback");

		meta.setRedirectionURI(uri);

		assertTrue(meta.getRedirectionURIs().contains(uri));
		assertEquals(1, meta.getRedirectionURIs().size());

		meta.setRedirectionURI(null);
		assertNull(meta.getRedirectionURIs());
	}


	public void testSetNullRedirectURI() {

		ClientMetadata meta = new ClientMetadata();
		meta.setRedirectionURI(null);
		assertNull(meta.getRedirectionURIs());
		assertNull(meta.getRedirectionURIStrings());

		meta.setRedirectionURI(URI.create("https://example.com/cb"));
		assertEquals("https://example.com/cb", meta.getRedirectionURIs().iterator().next().toString());

		meta.setRedirectionURI(null);
		assertNull(meta.getRedirectionURIs());
		assertNull(meta.getRedirectionURIStrings());
	}


	public void testSetNullRedirectURIs() {

		ClientMetadata meta = new ClientMetadata();
		meta.setRedirectionURIs(null);
		assertNull(meta.getRedirectionURIs());
		assertNull(meta.getRedirectionURIStrings());

		meta.setRedirectionURIs(Collections.singleton(URI.create("https://example.com/cb")));
		assertEquals("https://example.com/cb", meta.getRedirectionURIs().iterator().next().toString());

		meta.setRedirectionURIs(null);
		assertNull(meta.getRedirectionURIs());
		assertNull(meta.getRedirectionURIStrings());
	}


	public void testGetRedirectionURIStrings()
		throws Exception {

		ClientMetadata meta = new ClientMetadata();

		assertNull(meta.getRedirectionURIStrings());

		Set<URI> redirectURIs = new HashSet<>();
		redirectURIs.add(new URI("https://cliemt.com/cb-1"));
		redirectURIs.add(new URI("https://cliemt.com/cb-2"));
		redirectURIs.add(new URI("https://cliemt.com/cb-3"));

		meta.setRedirectionURIs(redirectURIs);

		assertTrue(meta.getRedirectionURIStrings().contains("https://cliemt.com/cb-1"));
		assertTrue(meta.getRedirectionURIStrings().contains("https://cliemt.com/cb-2"));
		assertTrue(meta.getRedirectionURIStrings().contains("https://cliemt.com/cb-3"));
		assertEquals(3, meta.getRedirectionURIStrings().size());

		meta.setRedirectionURI(new URI("https://cliemt.com/cb"));
		assertTrue(meta.getRedirectionURIStrings().contains("https://cliemt.com/cb"));
		assertEquals(1, meta.getRedirectionURIStrings().size());
	}


	public void testParse()
		throws Exception {

		String json = "{\n" +
			"      \"redirect_uris\":[\n" +
			"        \"https://client.example.org/callback\",\n" +
			"        \"https://client.example.org/callback2\"],\n" +
			"      \"token_endpoint_auth_method\":\"client_secret_basic\",\n" +
			"      \"example_extension_parameter\": \"example_value\"\n" +
			"     }";

		ClientMetadata meta = ClientMetadata.parse(JSONObjectUtils.parse(json));

		assertTrue(meta.getRedirectionURIs().contains(new URI("https://client.example.org/callback")));
		assertTrue(meta.getRedirectionURIs().contains(new URI("https://client.example.org/callback2")));
		assertEquals(2, meta.getRedirectionURIs().size());

		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, meta.getTokenEndpointAuthMethod());

		assertEquals("example_value", meta.getCustomField("example_extension_parameter"));
	}


	public void testParseBadRedirectionURI() {

		String json = "{\n" +
			" \"redirect_uris\":[\n" +
			"   \"https://\",\n" +
			"   \"https://client.example.org/callback2\"],\n" +
			" \"token_endpoint_auth_method\":\"client_secret_basic\",\n" +
			" \"example_extension_parameter\": \"example_value\"\n" +
			"}";

		try {
			ClientMetadata.parse(JSONObjectUtils.parse(json));
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid redirect_uris parameter: Expected authority at index 8: https://", e.getMessage());
			assertEquals(RegistrationError.INVALID_REDIRECT_URI.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid redirection URI(s): Expected authority at index 8: https://", e.getErrorObject().getDescription());
		}
	}
	
	
	public void testHumanFacingURIsMustBeHTTPSorHTTP() throws LangTagException {
		
		ClientMetadata metadata = new ClientMetadata();
		
		String exceptionMessage = "The URI scheme must be https or http";
		
		// client_uri
		try {
			metadata.setURI(URI.create("ftp://example.com"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals(exceptionMessage, e.getMessage());
		}
		try {
			metadata.setURI(URI.create("ftp://example.com"), LangTag.parse("en"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals(exceptionMessage, e.getMessage());
		}
		
		// policy_uri
		try {
			metadata.setPolicyURI(URI.create("ftp://example.com"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals(exceptionMessage, e.getMessage());
		}
		try {
			metadata.setPolicyURI(URI.create("ftp://example.com"), LangTag.parse("en"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals(exceptionMessage, e.getMessage());
		}
		
		// tos_uri
		try {
			metadata.setTermsOfServiceURI(URI.create("ftp://example.com"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals(exceptionMessage, e.getMessage());
		}
		try {
			metadata.setTermsOfServiceURI(URI.create("ftp://example.com"), LangTag.parse("en"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals(exceptionMessage, e.getMessage());
		}
		
		// Test parse
		metadata = new ClientMetadata();
		metadata.applyDefaults();
		JSONObject jsonObject = metadata.toJSONObject();
		
		// client_uri
		JSONObject copy = new JSONObject();
		copy.putAll(jsonObject);
		copy.put("client_uri", "ftp://example.com");
		
		try {
			ClientMetadata.parse(copy);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid client_uri (language tag) parameter: The URI scheme must be https or http", e.getMessage());
		}
		
		// policy_uri
		copy = new JSONObject();
		copy.putAll(jsonObject);
		copy.put("policy_uri", "ftp://example.com");
		
		try {
			ClientMetadata.parse(copy);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid policy_uri (language tag) parameter: The URI scheme must be https or http", e.getMessage());
		}
		
		// tos_uri
		copy = new JSONObject();
		copy.putAll(jsonObject);
		copy.put("tos_uri", "ftp://example.com");
		
		try {
			ClientMetadata.parse(copy);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid tos_uri (language tag) parameter: The URI scheme must be https or http", e.getMessage());
		}
	}


	public void testClientCredentialsGrant()
		throws Exception {

		JSONObject o = new JSONObject();
		o.put("client_name", "Test App");
		o.put("grant_types", Collections.singletonList("client_credentials"));
		o.put("response_types", new ArrayList<String>());
		o.put("scope", "read write");

		String json = o.toJSONString();

		ClientMetadata metadata = ClientMetadata.parse(JSONObjectUtils.parse(json));

		assertEquals("Test App", metadata.getName());
		assertTrue(metadata.getGrantTypes().contains(GrantType.CLIENT_CREDENTIALS));
		assertEquals(1, metadata.getGrantTypes().size());
		assertTrue(metadata.getResponseTypes().isEmpty());
		assertTrue(Scope.parse("read write").containsAll(metadata.getScope()));
		assertEquals(2, metadata.getScope().size());

		assertNull(metadata.getTokenEndpointAuthMethod());

		metadata.applyDefaults();

		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, metadata.getTokenEndpointAuthMethod());
	}


	public void testPasswordGrant()
		throws Exception {

		JSONObject o = new JSONObject();
		o.put("client_name", "Test App");
		o.put("grant_types", Collections.singletonList("password"));
		o.put("response_types", new ArrayList<String>());
		o.put("scope", "read write");

		String json = o.toJSONString();

		ClientMetadata metadata = ClientMetadata.parse(JSONObjectUtils.parse(json));

		assertEquals("Test App", metadata.getName());
		assertTrue(metadata.getGrantTypes().contains(GrantType.PASSWORD));
		assertEquals(1, metadata.getGrantTypes().size());
		assertTrue(metadata.getResponseTypes().isEmpty());
		assertTrue(Scope.parse("read write").containsAll(metadata.getScope()));
		assertEquals(2, metadata.getScope().size());

		assertNull(metadata.getTokenEndpointAuthMethod());

		metadata.applyDefaults();

		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, metadata.getTokenEndpointAuthMethod());
	}


	public void testNoGrant()
		throws Exception {

		JSONObject o = new JSONObject();
		o.put("client_name", "Test App");
		o.put("grant_types", new ArrayList<String>());
		o.put("response_types", new ArrayList<String>());
		o.put("scope", "read write");

		String json = o.toJSONString();

		ClientMetadata metadata = ClientMetadata.parse(JSONObjectUtils.parse(json));

		assertEquals("Test App", metadata.getName());
		assertTrue(metadata.getGrantTypes().isEmpty());
		assertTrue(metadata.getResponseTypes().isEmpty());
		assertTrue(Scope.parse("read write").containsAll(metadata.getScope()));
		assertEquals(2, metadata.getScope().size());

		assertNull(metadata.getTokenEndpointAuthMethod());

		metadata.applyDefaults();

		assertTrue(metadata.getGrantTypes().isEmpty());
		assertTrue(metadata.getResponseTypes().isEmpty());

		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, metadata.getTokenEndpointAuthMethod());
	}


	public void testClientAuthNoneWithImplicitGrant() {

		ClientMetadata clientMetadata = new ClientMetadata();
		clientMetadata.setGrantTypes(Collections.singleton(GrantType.IMPLICIT));
		clientMetadata.setResponseTypes(Collections.singleton(new ResponseType("token")));

		clientMetadata.applyDefaults();

		assertEquals(Collections.singleton(GrantType.IMPLICIT), clientMetadata.getGrantTypes());
		assertEquals(Collections.singleton(new ResponseType("token")), clientMetadata.getResponseTypes());
		assertEquals(ClientAuthenticationMethod.NONE, clientMetadata.getTokenEndpointAuthMethod());
	}


	public void testRejectFragmentInRedirectURI() {

		URI redirectURIWithFragment = URI.create("https://example.com/cb#fragment");

		ClientMetadata metadata = new ClientMetadata();

		// single setter
		try {
			metadata.setRedirectionURI(redirectURIWithFragment);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The redirect_uri must not contain fragment", e.getMessage());
		}

		// collection setter
		try {
			metadata.setRedirectionURIs(Collections.singleton(redirectURIWithFragment));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The redirect_uri must not contain fragment", e.getMessage());
		}

		// static parse method
		JSONObject o = new JSONObject();
		o.put("redirect_uris", Collections.singletonList(redirectURIWithFragment.toString()));

		try {
			ClientMetadata.parse(o);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid redirect_uris parameter: The redirect_uri must not contain fragment", e.getMessage());
			assertEquals(RegistrationError.INVALID_REDIRECT_URI.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid redirection URI(s): The redirect_uri must not contain fragment", e.getErrorObject().getDescription());
		}
	}
	
	
	public void testCustomRedirectURIScheme() throws ParseException {
		
		URI redirectURI = URI.create("myapp://login-callback");
		
		ClientMetadata clientMetadata = new ClientMetadata();
		assertNull(clientMetadata.getRedirectionURI());
		clientMetadata.setRedirectionURI(redirectURI);
		assertEquals(redirectURI, clientMetadata.getRedirectionURI());
		
		JSONObject jsonObject = clientMetadata.toJSONObject();
		
		clientMetadata = ClientMetadata.parse(jsonObject);
		assertEquals(redirectURI, clientMetadata.getRedirectionURI());
	}


	public void testRejectProhibitedSchemeInRedirectURI() {

		for (String scheme: ClientMetadata.PROHIBITED_REDIRECT_URI_SCHEMES) {
			
			URI illegalRedirectURI = URI.create(scheme + "://example.com/cb");
			
			ClientMetadata metadata = new ClientMetadata();
			
			// single setter
			try {
				metadata.setRedirectionURI(illegalRedirectURI);
				fail();
			} catch (IllegalArgumentException e) {
				assertEquals("The URI scheme " + scheme + " is prohibited", e.getMessage());
			}
			
			// collection setter
			try {
				metadata.setRedirectionURIs(Collections.singleton(illegalRedirectURI));
				fail();
			} catch (IllegalArgumentException e) {
				assertEquals("The URI scheme " + scheme + " is prohibited", e.getMessage());
			}
			
			// static parse method
			JSONObject o = new JSONObject();
			o.put("redirect_uris", Collections.singletonList(illegalRedirectURI.toString()));
			
			try {
				ClientMetadata.parse(o);
				fail();
			} catch (ParseException e) {
				assertEquals("Invalid redirect_uris parameter: The URI scheme " + scheme + " is prohibited", e.getMessage());
				assertEquals(RegistrationError.INVALID_REDIRECT_URI.getCode(), e.getErrorObject().getCode());
				assertEquals("Invalid redirection URI(s): The URI scheme " + scheme + " is prohibited", e.getErrorObject().getDescription());
			}
		}
	}


	public void testInvalidMetadataError() {

		JSONObject o = new JSONObject();
		o.put("response_types", 123);

		try {
			ClientMetadata.parse(o);
			fail();
		} catch (ParseException e) {
			assertEquals("Unexpected type of JSON object member with key response_types", e.getMessage());
			assertEquals(RegistrationError.INVALID_CLIENT_METADATA.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid client metadata field: Unexpected type of JSON object member with key response_types", e.getErrorObject().getDescription());
		}
	}
	
	
	public void testPermitParseNullValues()
		throws Exception {
		
		JSONObject jsonObject = new JSONObject();
		
		for (String paramName: ClientMetadata.getRegisteredParameterNames()) {
			
			jsonObject.put(paramName, null);
		}
		
		ClientMetadata.parse(jsonObject);
	}
	
	
	public void testGetOneRedirectionURI() {
		
		ClientMetadata clientMetadata = new ClientMetadata();
		
		assertNull(clientMetadata.getRedirectionURI());
		
		URI uri1 = URI.create("https://example.com/cb-1");
		clientMetadata.setRedirectionURI(uri1);
		assertEquals(uri1, clientMetadata.getRedirectionURI());
		
		URI uri2 = URI.create("https://example.com/cb-2");
		Set<URI> uriSet = new HashSet<>(Arrays.asList(uri1, uri2));
		clientMetadata.setRedirectionURIs(uriSet);
		assertTrue(uriSet.contains(clientMetadata.getRedirectionURI()));
	}
	
	
	public void testCustomParameters()
		throws ParseException {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("grant_types", Collections.singletonList("code"));
		jsonObject.put("preferred_client_id", "123");
		jsonObject.put("preferred_client_secret", "ahp7Thaeh4iedagohhaeThuhu9ahreiw");
		
		ClientMetadata clientMetadata = ClientMetadata.parse(jsonObject);
		
		assertEquals("123", clientMetadata.getCustomField("preferred_client_id"));
		assertEquals("ahp7Thaeh4iedagohhaeThuhu9ahreiw", clientMetadata.getCustomField("preferred_client_secret"));
	}
	
	
	public void testSoftwareVersion_string()
		throws ParseException {
		
		ClientMetadata clientMetadata = new ClientMetadata();
		clientMetadata.setSoftwareVersion(new SoftwareVersion("1.0"));
		clientMetadata.applyDefaults();
		
		String json = clientMetadata.toJSONObject().toJSONString();
		
		clientMetadata = ClientMetadata.parse(JSONObjectUtils.parse(json));
		
		assertEquals("1.0", clientMetadata.getSoftwareVersion().getValue());
	}
	
	
	// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/348/clientmetadataparse-normalize
	public void testSoftwareVersion_integer()
		throws ParseException {
		
		ClientMetadata clientMetadata = new ClientMetadata();
		clientMetadata.applyDefaults();
		
		JSONObject jsonObject = clientMetadata.toJSONObject();
		jsonObject.put("software_version", 1);
		String json = jsonObject.toJSONString();
		
		clientMetadata = ClientMetadata.parse(JSONObjectUtils.parse(json));
		
		assertEquals("1", clientMetadata.getSoftwareVersion().getValue());
	}
	
	
	// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/348/clientmetadataparse-normalize
	public void testSoftwareVersion_float()
		throws ParseException {
		
		ClientMetadata clientMetadata = new ClientMetadata();
		clientMetadata.applyDefaults();
		
		JSONObject jsonObject = clientMetadata.toJSONObject();
		jsonObject.put("software_version", 1.0);
		String json = jsonObject.toJSONString();
		
		clientMetadata = ClientMetadata.parse(JSONObjectUtils.parse(json));
		
		assertEquals("1.0", clientMetadata.getSoftwareVersion().getValue());
	}
	
	
	public void testSoftwareStatement()
		throws JOSEException, java.text.ParseException, ParseException {
		
		ClientMetadata clientMetadata = new ClientMetadata();
		assertNull(clientMetadata.getSoftwareStatement());
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.keyIDFromThumbprint(true)
			.generate();
		
		ClientMetadata signedClientMetadata = new ClientMetadata();
		SoftwareID softwareID = new SoftwareID("4NRB1-0XZABZI9E6-5SM3R");
		signedClientMetadata.setSoftwareID(softwareID);
		String name = "Example Statement-based Client";
		signedClientMetadata.setName(name);
		URI uri = URI.create("https://client.example.net/");
		signedClientMetadata.setURI(uri);
		
		SignedJWT softwareStatement = new SignedJWT(
			new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
			JWTClaimsSet.parse(signedClientMetadata.toJSONObject()));
		
		try {
			clientMetadata.setSoftwareStatement(softwareStatement);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The software statement must be signed", e.getMessage());
		}
		
		softwareStatement.sign(new RSASSASigner(rsaJWK));
		
		clientMetadata.setSoftwareStatement(softwareStatement);
		
		assertEquals(softwareStatement, clientMetadata.getSoftwareStatement());
		
		JSONObject jsonObject = clientMetadata.toJSONObject();
		
		assertEquals(softwareStatement.serialize(), jsonObject.get("software_statement"));
		
		clientMetadata = ClientMetadata.parse(jsonObject);
		assertEquals(softwareStatement.serialize(), clientMetadata.getSoftwareStatement().serialize());
		
		assertTrue(clientMetadata.getSoftwareStatement().verify(new RSASSAVerifier(rsaJWK.toRSAPublicKey())));
	}
	
	
	public void testJARM()
		throws ParseException {
		
		ClientMetadata clientMetadata = new ClientMetadata();
		
		assertNull(clientMetadata.getAuthorizationJWSAlg());
		assertNull(clientMetadata.getAuthorizationJWEAlg());
		assertNull(clientMetadata.getAuthorizationJWEEnc());
		
		clientMetadata.setAuthorizationJWSAlg(JWSAlgorithm.ES256);
		assertEquals(JWSAlgorithm.ES256, clientMetadata.getAuthorizationJWSAlg());
		
		clientMetadata.setAuthorizationJWEAlg(JWEAlgorithm.ECDH_ES);
		assertEquals(JWEAlgorithm.ECDH_ES, clientMetadata.getAuthorizationJWEAlg());
		
		clientMetadata.setAuthorizationJWEEnc(EncryptionMethod.A256GCM);
		assertEquals(EncryptionMethod.A256GCM, clientMetadata.getAuthorizationJWEEnc());
		
		JSONObject jsonObject = clientMetadata.toJSONObject();
		
		assertEquals(JWSAlgorithm.ES256.getName(), jsonObject.get("authorization_signed_response_alg"));
		assertEquals(JWEAlgorithm.ECDH_ES.getName(), jsonObject.get("authorization_encrypted_response_alg"));
		assertEquals(EncryptionMethod.A256GCM.getName(), jsonObject.get("authorization_encrypted_response_enc"));
		
		clientMetadata = ClientMetadata.parse(jsonObject);
		
		assertEquals(JWSAlgorithm.ES256, clientMetadata.getAuthorizationJWSAlg());
		assertEquals(JWEAlgorithm.ECDH_ES, clientMetadata.getAuthorizationJWEAlg());
		assertEquals(EncryptionMethod.A256GCM, clientMetadata.getAuthorizationJWEEnc());
	}
	
	
	public void testJARM_rejectNoneJWSAlg() {
		
		ClientMetadata clientMetadata = new ClientMetadata();
		
		try {
			clientMetadata.setAuthorizationJWSAlg(new JWSAlgorithm("none"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The JWS algorithm must not be \"none\"", e.getMessage());
		}
	}
	
	
	public void testRequireOneTLSSubjectParam_toJSONObject() {
	
		ClientMetadata clientMetadata = new ClientMetadata();
		clientMetadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH);
		clientMetadata.applyDefaults();
		
		try {
			clientMetadata.toJSONObject();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("A certificate field must be specified to indicate the subject in tls_client_auth: " +
				"tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip or tls_client_auth_san_email",
				e.getMessage());
		}
	}
	
	
	public void testRequireOneTLSSubjectParam_parse() {
	
		ClientMetadata clientMetadata = new ClientMetadata();
		clientMetadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH);
		clientMetadata.applyDefaults();
		
		clientMetadata.setTLSClientAuthSubjectDN("cn=example.com"); // to pass toJSON checks
		
		JSONObject jsonObject = clientMetadata.toJSONObject();
		jsonObject.remove("tls_client_auth_subject_dn");
		
		try {
			ClientMetadata.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("A certificate field must be specified to indicate the subject in tls_client_auth: " +
				"tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip or tls_client_auth_san_email",
				e.getMessage());
		}
	}
	
	
	public void testRejectMoreThanOneTLSSubjectParam_toJSONObject() {
	
		ClientMetadata clientMetadata = new ClientMetadata();
		clientMetadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.TLS_CLIENT_AUTH);
		clientMetadata.applyDefaults();
		
		List<ClientMetadata> forTest = new LinkedList<>();
		
		// test combinations of two only
		
		// tls_client_auth_subject_dn
		ClientMetadata a_1 = new ClientMetadata(clientMetadata);
		a_1.setTLSClientAuthSubjectDN("cn=example.com");
		a_1.setTLSClientAuthSanDNS("example.com");
		forTest.add(a_1);
		
		ClientMetadata a_2 = new ClientMetadata(clientMetadata);
		a_2.setTLSClientAuthSubjectDN("cn=example.com");
		a_2.setTLSClientAuthSanURI("https://example.com");
		forTest.add(a_2);
		
		ClientMetadata a_3 = new ClientMetadata(clientMetadata);
		a_3.setTLSClientAuthSubjectDN("cn=example.com");
		a_3.setTLSClientAuthSanIP("192.168.0.1");
		forTest.add(a_3);
		
		ClientMetadata a_4 = new ClientMetadata(clientMetadata);
		a_4.setTLSClientAuthSubjectDN("cn=example.com");
		a_4.setTLSClientAuthSanEmail("user@example.com");
		forTest.add(a_4);
		
		// tls_client_auth_san_dns
		ClientMetadata b_1 = new ClientMetadata(clientMetadata);
		b_1.setTLSClientAuthSanDNS("example.com");
		b_1.setTLSClientAuthSanURI("https://example.com");
		forTest.add(b_1);
		
		ClientMetadata b_2 = new ClientMetadata(clientMetadata);
		b_2.setTLSClientAuthSanDNS("example.com");
		b_2.setTLSClientAuthSanIP("192.168.0.1");
		forTest.add(b_2);
		
		ClientMetadata b_3 = new ClientMetadata(clientMetadata);
		b_3.setTLSClientAuthSanDNS("example.com");
		b_3.setTLSClientAuthSanEmail("user@example.com");
		forTest.add(b_3);
		
		// tls_client_auth_san_uri
		ClientMetadata c_1 = new ClientMetadata(clientMetadata);
		c_1.setTLSClientAuthSanURI("https://example.com");
		c_1.setTLSClientAuthSanIP("192.168.0.1");
		forTest.add(c_1);
		
		ClientMetadata c_2 = new ClientMetadata(clientMetadata);
		c_2.setTLSClientAuthSanURI("https://example.com");
		c_2.setTLSClientAuthSanEmail("user@example.com");
		forTest.add(c_2);
		
		// tls_client_auth_san_ip
		ClientMetadata d_1 = new ClientMetadata(clientMetadata);
		d_1.setTLSClientAuthSanIP("192.168.0.1");
		d_1.setTLSClientAuthSanEmail("user@example.com");
		forTest.add(d_1);
		
		for (ClientMetadata cm: forTest) {
			try {
				cm.toJSONObject();
				fail();
			} catch (IllegalStateException e) {
				assertEquals("Exactly one certificate field must be specified to indicate the subject in tls_client_auth: " +
						"tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip or tls_client_auth_san_email",
					e.getMessage());
			}
		}
	}
	
	
	public void testRejectMoreThanOneTLSSubjectParam_parse() {
		
		ClientMetadata clientMetadata = new ClientMetadata();
		clientMetadata.applyDefaults();
		
		List<String> certParams = new LinkedList<>();
		certParams.add("tls_client_auth_subject_dn");
		certParams.add("tls_client_auth_san_dns");
		certParams.add("tls_client_auth_san_uri");
		certParams.add("tls_client_auth_san_ip");
		certParams.add("tls_client_auth_san_email");
		
		String expectedMessage = "Exactly one certificate field must be specified to indicate the subject in tls_client_auth: " +
			"tls_client_auth_subject_dn, tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip or tls_client_auth_san_email";
		
		for (int subsetSize: new int[]{2,3,4,5}) {
			
			for (int[] combi : new Combinations(certParams.size(), subsetSize)) {
				
				JSONObject jsonObject = clientMetadata.toJSONObject();
				jsonObject.put("token_endpoint_auth_method", "tls_client_auth");
				for (int i: combi) {
					jsonObject.put(certParams.get(i), "value");
				}
				try {
					ClientMetadata.parse(jsonObject);
					fail(jsonObject.toJSONString());
				} catch (ParseException e) {
					assertEquals(expectedMessage, e.getMessage());
					assertEquals("invalid_client_metadata", e.getErrorObject().getCode());
					assertEquals("Invalid client metadata field: " + expectedMessage, e.getErrorObject().getDescription());
				}
			}
		}
	}
	
	
	public void testPAR()
		throws ParseException {
		
		ClientMetadata clientMetadata = new ClientMetadata();
		assertFalse(clientMetadata.requiresPushedAuthorizationRequests());
		
		clientMetadata.applyDefaults();
		assertFalse(clientMetadata.requiresPushedAuthorizationRequests());
		
		JSONObject jsonObject = clientMetadata.toJSONObject();
		assertFalse(jsonObject.containsKey("require_pushed_authorization_requests"));
		
		clientMetadata = ClientMetadata.parse(jsonObject);
		assertFalse(clientMetadata.requiresPushedAuthorizationRequests());
		
		assertTrue(clientMetadata.getCustomFields().isEmpty());
	}
	
	
	public void testPAR_required()
		throws ParseException {
		
		ClientMetadata clientMetadata = new ClientMetadata();
		clientMetadata.requiresPushedAuthorizationRequests(true);
		assertTrue(clientMetadata.requiresPushedAuthorizationRequests());
		
		clientMetadata.applyDefaults();
		assertTrue(clientMetadata.requiresPushedAuthorizationRequests());
		
		JSONObject jsonObject = clientMetadata.toJSONObject();
		assertTrue((Boolean) jsonObject.get("require_pushed_authorization_requests"));
		
		clientMetadata = ClientMetadata.parse(jsonObject);
		assertTrue(clientMetadata.requiresPushedAuthorizationRequests());
		
		assertTrue(clientMetadata.getCustomFields().isEmpty());
	}
	
	
	public void testFederationFields()
		throws Exception {
		
		ClientMetadata clientMetadata = new ClientMetadata();
		
		URI redirectionURI = URI.create("https://example.com/cb");
		clientMetadata.setRedirectionURI(redirectionURI);
		
		assertNull(clientMetadata.getClientRegistrationTypes());
		List<ClientRegistrationType> federationTypes = Arrays.asList(ClientRegistrationType.EXPLICIT, ClientRegistrationType.AUTOMATIC);
		clientMetadata.setClientRegistrationTypes(federationTypes);
		assertEquals(federationTypes, clientMetadata.getClientRegistrationTypes());
		
		URI signedJWKSetURI = URI.create("https://example.com/jwks.jwt");
		clientMetadata.setSignedJWKSetURI(signedJWKSetURI);
		assertEquals(signedJWKSetURI, clientMetadata.getSignedJWKSetURI());
		
		assertNull(clientMetadata.getOrganizationName());
		String orgName = "Example Org";
		clientMetadata.setOrganizationName(orgName);
		assertEquals(orgName, clientMetadata.getOrganizationName());
		
		JSONObject jsonObject = clientMetadata.toJSONObject();
		
		assertEquals(Arrays.asList("explicit", "automatic"), JSONObjectUtils.getStringList(jsonObject, "client_registration_types"));
		assertEquals(signedJWKSetURI, JSONObjectUtils.getURI(jsonObject, "signed_jwks_uri"));
		assertEquals(orgName, JSONObjectUtils.getString(jsonObject, "organization_name"));
		
		clientMetadata = ClientMetadata.parse(jsonObject);
		
		assertEquals(redirectionURI, clientMetadata.getRedirectionURI());
		assertEquals(federationTypes, clientMetadata.getClientRegistrationTypes());
		assertEquals(signedJWKSetURI, clientMetadata.getSignedJWKSetURI());
		assertEquals(orgName, clientMetadata.getOrganizationName());
		
		ClientMetadata copy = new ClientMetadata(clientMetadata);
		assertEquals(redirectionURI, copy.getRedirectionURI());
		assertEquals(federationTypes, copy.getClientRegistrationTypes());
		assertEquals(signedJWKSetURI, copy.getSignedJWKSetURI());
		assertEquals(orgName, copy.getOrganizationName());
	}
	
	
	public void testSerializeAndParseWithJWKs()
		throws JOSEException, ParseException {
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.keyIDFromThumbprint(true)
			.generate();
		
		JWKSet jwkSet = new JWKSet(rsaJWK.toPublicJWK());
		
		ClientMetadata metadata = new ClientMetadata();
		metadata.setJWKSet(jwkSet);
		metadata.applyDefaults();
		
		metadata = ClientMetadata.parse(metadata.toJSONObject());
		
		assertEquals(jwkSet.toJSONObject(), metadata.getJWKSet().toJSONObject());
	}
	
	
	public void testClientInformationFieldsMustNotBeParsedAsCustom() throws URISyntaxException, ParseException {
		
		ClientMetadata metadata = new ClientMetadata();
		metadata.setRedirectionURI(new URI("https://example.com/1"));
		metadata.applyDefaults();
		
		metadata.setCustomField("x-custom", "123");
		metadata.setCustomField("y-custom", "456");
		metadata.setCustomField("z-custom", "789");
		
		ClientInformation clientInfo = new ClientInformation(
			new ClientID("123"),
			DateUtils.nowWithSecondsPrecision(),
			metadata,
			new Secret(),
			new URI("https://op.example.com/clints/123"),
			new BearerAccessToken());
		
		ClientMetadata parsed = ClientMetadata.parse(clientInfo.toJSONObject());
		assertEquals("123", parsed.getCustomField("x-custom"));
		assertEquals("456", parsed.getCustomField("y-custom"));
		assertEquals("789", parsed.getCustomField("z-custom"));
		assertEquals(3, parsed.getCustomFields().size());
		
		assertEquals(metadata.toJSONObject(true), parsed.toJSONObject(true));
	}
}