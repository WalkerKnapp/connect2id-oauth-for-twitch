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
import java.util.*;
import javax.mail.internet.InternetAddress;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.SoftwareID;
import com.nimbusds.oauth2.sdk.id.SoftwareVersion;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


/**
 * Tests the OAuth 2.0 client metadata class.
 */
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
		assertTrue(paramNames.contains("software_id"));
		assertTrue(paramNames.contains("software_version"));

		assertEquals(16, ClientMetadata.getRegisteredParameterNames().size());
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

		SoftwareID softwareID = new SoftwareID();
		meta.setSoftwareID(softwareID);

		SoftwareVersion softwareVersion = new SoftwareVersion("1.0");
		meta.setSoftwareVersion(softwareVersion);
		
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
		
		List<InternetAddress> contacts = new LinkedList<>();
		contacts.add(new InternetAddress("alice@wonderland.net"));
		contacts.add(new InternetAddress("admin@wonderland.net"));
		meta.setContacts(contacts);
		
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
		
		// Test getters
		assertEquals(redirectURIs, meta.getRedirectionURIs());
		assertEquals(scope, meta.getScope());
		assertEquals(grantTypes, meta.getGrantTypes());
		assertEquals(contacts, meta.getContacts());
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
		assertEquals(contacts, meta.getContacts());
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

		SoftwareID softwareID = new SoftwareID();
		meta.setSoftwareID(softwareID);

		SoftwareVersion softwareVersion = new SoftwareVersion("1.0");
		meta.setSoftwareVersion(softwareVersion);

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
		assertEquals(softwareID, copy.getSoftwareID());
		assertEquals(softwareVersion, copy.getSoftwareVersion());
		assertTrue(copy.getCustomFields().isEmpty());

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

		assertTrue(copy.getCustomFields().isEmpty());
	}


	public void testApplyDefaults()
		throws Exception {
		
		ClientMetadata meta = new ClientMetadata();
		
		assertNull(meta.getResponseTypes());
		assertNull(meta.getGrantTypes());
		assertNull(meta.getTokenEndpointAuthMethod());
		
		meta.applyDefaults();
		
		Set<ResponseType> rts = meta.getResponseTypes();
		assertTrue(rts.contains(ResponseType.parse("code")));
		
		Set<GrantType> grantTypes = meta.getGrantTypes();
		assertTrue(grantTypes.contains(GrantType.AUTHORIZATION_CODE));
		
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, meta.getTokenEndpointAuthMethod());
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


	public void testParseBadRedirectionURI()
		throws Exception {

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
			assertEquals("Invalid \"redirect_uris\" parameter: Expected authority at index 8: https://", e.getMessage());
			assertEquals(RegistrationError.INVALID_REDIRECT_URI.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid redirection URI(s): Expected authority at index 8: https://", e.getErrorObject().getDescription());
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
			assertEquals("Invalid \"redirect_uris\" parameter: URI must not contain fragment", e.getMessage());
			assertEquals(RegistrationError.INVALID_REDIRECT_URI.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid redirection URI(s): URI must not contain fragment", e.getErrorObject().getDescription());
		}
	}


	public void testInvalidMetadataError() {

		JSONObject o = new JSONObject();
		o.put("response_types", 123);

		try {
			ClientMetadata.parse(o);
			fail();
		} catch (ParseException e) {
			assertEquals("Unexpected type of JSON object member with key \"response_types\"", e.getMessage());
			assertEquals(RegistrationError.INVALID_CLIENT_METADATA.getCode(), e.getErrorObject().getCode());
			assertEquals("Invalid client metadata field: Unexpected type of JSON object member with key \"response_types\"", e.getErrorObject().getDescription());
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
	
	
	public void testIgnoreInvalidEmailOnGetContacts()
		throws Exception {
		
		ClientMetadata clientMetadata = new ClientMetadata();
		List<String> invalidEmail = Collections.singletonList("invalid-email-address");
		clientMetadata.setEmailContacts(invalidEmail);
		assertEquals(invalidEmail.get(0), clientMetadata.getContacts().get(0).toString());
		assertEquals(invalidEmail.size(), clientMetadata.getContacts().size());
	}
}