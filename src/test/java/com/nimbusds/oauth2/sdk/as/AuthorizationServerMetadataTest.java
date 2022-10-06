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

package com.nimbusds.oauth2.sdk.as;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;
import org.checkerframework.checker.units.qual.A;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.client.ClientType;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.federation.registration.ClientRegistrationType;
import com.nimbusds.openid.connect.sdk.op.EndpointName;


public class AuthorizationServerMetadataTest extends TestCase {
	
	
	public void testRegisteredParameters() {
		
		Set<String> paramNames = AuthorizationServerMetadata.getRegisteredParameterNames();
		
		assertTrue(paramNames.contains("issuer"));
		assertTrue(paramNames.contains("authorization_endpoint"));
		assertTrue(paramNames.contains("token_endpoint"));
		assertTrue(paramNames.contains("jwks_uri"));
		assertTrue(paramNames.contains("registration_endpoint"));
		assertTrue(paramNames.contains("scopes_supported"));
		assertTrue(paramNames.contains("response_types_supported"));
		assertTrue(paramNames.contains("response_modes_supported"));
		assertTrue(paramNames.contains("grant_types_supported"));
		assertTrue(paramNames.contains("code_challenge_methods_supported"));
		assertTrue(paramNames.contains("request_object_endpoint"));
		assertTrue(paramNames.contains("request_parameter_supported"));
		assertTrue(paramNames.contains("require_request_uri_registration"));
		assertTrue(paramNames.contains("authorization_response_iss_parameter_supported"));
		assertTrue(paramNames.contains("pushed_authorization_request_endpoint"));
		assertTrue(paramNames.contains("require_pushed_authorization_requests"));
		assertTrue(paramNames.contains("request_object_endpoint"));
		assertTrue(paramNames.contains("request_object_signing_alg_values_supported"));
		assertTrue(paramNames.contains("request_object_encryption_alg_values_supported"));
		assertTrue(paramNames.contains("request_object_encryption_enc_values_supported"));
		assertTrue(paramNames.contains("token_endpoint_auth_methods_supported"));
		assertTrue(paramNames.contains("token_endpoint_auth_signing_alg_values_supported"));
		assertTrue(paramNames.contains("service_documentation"));
		assertTrue(paramNames.contains("ui_locales_supported"));
		assertTrue(paramNames.contains("op_policy_uri"));
		assertTrue(paramNames.contains("op_tos_uri"));
		assertTrue(paramNames.contains("introspection_endpoint"));
		assertTrue(paramNames.contains("introspection_endpoint_auth_methods_supported"));
		assertTrue(paramNames.contains("introspection_endpoint_auth_signing_alg_values_supported"));
		assertTrue(paramNames.contains("revocation_endpoint"));
		assertTrue(paramNames.contains("revocation_endpoint_auth_methods_supported"));
		assertTrue(paramNames.contains("revocation_endpoint_auth_signing_alg_values_supported"));
		assertTrue(paramNames.contains("mtls_endpoint_aliases"));
		assertTrue(paramNames.contains("tls_client_certificate_bound_access_tokens"));
		assertTrue(paramNames.contains("dpop_signing_alg_values_supported"));
		assertTrue(paramNames.contains("authorization_signing_alg_values_supported"));
		assertTrue(paramNames.contains("authorization_encryption_alg_values_supported"));
		assertTrue(paramNames.contains("authorization_encryption_enc_values_supported"));
		assertTrue(paramNames.contains("device_authorization_endpoint"));
		assertTrue(paramNames.contains("incremental_authz_types_supported"));
		assertTrue(paramNames.contains("pushed_authorization_request_endpoint"));
		assertTrue(paramNames.contains("backchannel_token_delivery_modes_supported"));
		assertTrue(paramNames.contains("backchannel_authentication_endpoint"));
		assertTrue(paramNames.contains("backchannel_authentication_request_signing_alg_values_supported"));
		assertTrue(paramNames.contains("backchannel_user_code_parameter_supported"));
		assertTrue(paramNames.contains("prompt_values_supported"));
		assertTrue(paramNames.contains("organization_name"));
		assertTrue(paramNames.contains("signed_jwks_uri"));
		assertTrue(paramNames.contains("jwks"));
		assertTrue(paramNames.contains("client_registration_types_supported"));
		assertTrue(paramNames.contains("request_authentication_methods_supported"));
		assertTrue(paramNames.contains("request_authentication_signing_alg_values_supported"));
		assertTrue(paramNames.contains("federation_registration_endpoint"));
		assertEquals(52, paramNames.size());
	}
	
	
	public void testParseExample()
		throws Exception {
		
		String json = "{" +
			" \"issuer\":" +
			"   \"https://server.example.com\"," +
			" \"authorization_endpoint\":" +
			"   \"https://server.example.com/authorize\"," +
			" \"token_endpoint\":" +
			"   \"https://server.example.com/token\"," +
			" \"token_endpoint_auth_methods_supported\":" +
			"   [\"client_secret_basic\", \"private_key_jwt\"]," +
			" \"token_endpoint_auth_signing_alg_values_supported\":" +
			"   [\"RS256\", \"ES256\"]," +
			" \"userinfo_endpoint\":" +
			"   \"https://server.example.com/userinfo\"," +
			" \"jwks_uri\":" +
			"   \"https://server.example.com/jwks.json\"," +
			" \"registration_endpoint\":" +
			"   \"https://server.example.com/register\"," +
			" \"scopes_supported\":" +
			"   [\"openid\", \"profile\", \"email\", \"address\"," +
			"    \"phone\", \"offline_access\"]," +
			" \"response_types_supported\":" +
			"   [\"code\", \"code token\"]," +
			" \"service_documentation\":" +
			"   \"http://server.example.com/service_documentation.html\"," +
			" \"ui_locales_supported\":" +
			"   [\"en-US\", \"en-GB\", \"en-CA\", \"fr-FR\", \"fr-CA\"]" +
			"}";
		
		AuthorizationServerMetadata as = AuthorizationServerMetadata.parse(json);
		
		assertEquals(new Issuer("https://server.example.com"), as.getIssuer());
		assertEquals(new URI("https://server.example.com/authorize"), as.getAuthorizationEndpointURI());
		assertEquals(new URI("https://server.example.com/token"), as.getTokenEndpointURI());
		assertEquals(Arrays.asList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.PRIVATE_KEY_JWT), as.getTokenEndpointAuthMethods());
		assertEquals(new URI("https://server.example.com/userinfo"), as.getCustomURIParameter("userinfo_endpoint"));
		assertEquals(new URI("https://server.example.com/jwks.json"), as.getJWKSetURI());
		assertEquals(new URI("https://server.example.com/register"), as.getRegistrationEndpointURI());
		assertEquals(new Scope("openid", "profile", "email", "address", "phone", "offline_access"), as.getScopes());
		assertEquals(Arrays.asList(new ResponseType("code"), new ResponseType("code", "token")), as.getResponseTypes());
		assertEquals(new URI("http://server.example.com/service_documentation.html"), as.getServiceDocsURI());
		assertEquals(Arrays.asList(LangTag.parse("en-US"), LangTag.parse("en-GB"), LangTag.parse("en-CA"), LangTag.parse("fr-FR"), LangTag.parse("fr-CA")), as.getUILocales());
	}
	
	
	public void testApplyDefaults() throws ParseException {
		
		Issuer issuer = new Issuer("https://c2id.com");
		
		AuthorizationServerMetadata meta = new AuthorizationServerMetadata(issuer);
		
		meta.applyDefaults();
		
		List<ResponseMode> responseModes = meta.getResponseModes();
		assertTrue(responseModes.contains(ResponseMode.QUERY));
		assertTrue(responseModes.contains(ResponseMode.FRAGMENT));
		assertEquals(2, responseModes.size());
		
		List<GrantType> grantTypes = meta.getGrantTypes();
		assertTrue(grantTypes.contains(GrantType.AUTHORIZATION_CODE));
		assertTrue(grantTypes.contains(GrantType.IMPLICIT));
		assertEquals(2, grantTypes.size());
		
		assertEquals(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC), meta.getTokenEndpointAuthMethods());
		
		JSONObject jsonObject = meta.toJSONObject();
		assertEquals(issuer.getValue(), jsonObject.get("issuer"));
		assertEquals(Arrays.asList("query", "fragment"), JSONObjectUtils.getStringList(jsonObject, "response_modes_supported"));
		assertEquals(Arrays.asList("authorization_code","implicit"), JSONObjectUtils.getStringList(jsonObject, "grant_types_supported"));
		assertEquals(Collections.singletonList("client_secret_basic"), JSONObjectUtils.getStringList(jsonObject, "token_endpoint_auth_methods_supported"));
		assertEquals(4, jsonObject.size());
		
		meta = AuthorizationServerMetadata.parse(jsonObject);
		
		assertEquals(issuer, meta.getIssuer());
		
		responseModes = meta.getResponseModes();
		assertTrue(responseModes.contains(ResponseMode.QUERY));
		assertTrue(responseModes.contains(ResponseMode.FRAGMENT));
		assertEquals(2, responseModes.size());
		
		grantTypes = meta.getGrantTypes();
		assertTrue(grantTypes.contains(GrantType.AUTHORIZATION_CODE));
		assertTrue(grantTypes.contains(GrantType.IMPLICIT));
		assertEquals(2, grantTypes.size());
		
		assertEquals(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC), meta.getTokenEndpointAuthMethods());
		
		assertFalse(meta.supportsRequestParam());
		assertFalse(meta.supportsRequestURIParam());
		assertFalse(meta.requiresRequestURIRegistration());
		assertFalse(meta.supportsTLSClientCertificateBoundAccessTokens());
	}
	
	
	public void testParseMinimal()
		throws Exception {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("issuer", "https://c2id.com");
		
		AuthorizationServerMetadata as = AuthorizationServerMetadata.parse(jsonObject.toJSONString());
		assertEquals(new Issuer("https://c2id.com"), as.getIssuer());
	}
	
	
	public void testParse_issuerNotURI() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("issuer", "a b c");
		
		try {
			AuthorizationServerMetadata.parse(jsonObject.toJSONString());
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal character in path at index 1: a b c", e.getMessage());
		}
	}
	
	
	public void testParse_issuerWithQuery() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("issuer", "https://c2id.com?a=b");
		
		try {
			AuthorizationServerMetadata.parse(jsonObject.toJSONString());
			fail();
		} catch (ParseException e) {
			assertEquals("The issuer URI must be without a query component", e.getMessage());
		}
	}
	
	
	public void testParse_issuerWithFragment() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("issuer", "https://c2id.com#abc");
		
		try {
			AuthorizationServerMetadata.parse(jsonObject.toJSONString());
			fail();
		} catch (ParseException e) {
			assertEquals("The issuer URI must be without a fragment component", e.getMessage());
		}
	}
	
	
	public void testRejectAlgNoneInEndpointJWSAlgs() {
		
		AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		
		try {
			as.setTokenEndpointJWSAlgs(Collections.singletonList(new JWSAlgorithm("none")));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The \"none\" algorithm is not accepted", e.getMessage());
		}
		
		try {
			as.setIntrospectionEndpointJWSAlgs(Collections.singletonList(new JWSAlgorithm("none")));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The \"none\" algorithm is not accepted", e.getMessage());
		}
		
		try {
			as.setRevocationEndpointJWSAlgs(Collections.singletonList(new JWSAlgorithm("none")));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The \"none\" algorithm is not accepted", e.getMessage());
		}
	}
	
	
	public void testDPoP() throws ParseException {
		
		// init
		AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		
		assertNull(as.getDPoPJWSAlgs());
		
		as.applyDefaults();
		assertNull(as.getDPoPJWSAlgs());
		
		// null
		as.setDPoPJWSAlgs(null);
		assertNull(as.getDPoPJWSAlgs());
		
		as = AuthorizationServerMetadata.parse(as.toJSONObject());
		assertNull(as.getDPoPJWSAlgs());
		
		// empty
		as.setDPoPJWSAlgs(Collections.<JWSAlgorithm>emptyList());
		assertEquals(Collections.emptyList(), as.getDPoPJWSAlgs());
		
		as = AuthorizationServerMetadata.parse(as.toJSONObject());
		assertEquals(Collections.emptyList(), as.getDPoPJWSAlgs());
		
		// one JWS alg
		as.setDPoPJWSAlgs(Collections.singletonList(JWSAlgorithm.RS256));
		assertEquals(Collections.singletonList(JWSAlgorithm.RS256), as.getDPoPJWSAlgs());
		
		JSONObject jsonObject = as.toJSONObject();
		assertEquals(Collections.singletonList("RS256"), JSONObjectUtils.getStringList(jsonObject, "dpop_signing_alg_values_supported"));
		
		as = AuthorizationServerMetadata.parse(jsonObject);
		assertEquals(Collections.singletonList(JWSAlgorithm.RS256), as.getDPoPJWSAlgs());
		
		// three JWS algs
		as.setDPoPJWSAlgs(Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512));
		
		jsonObject = as.toJSONObject();
		assertEquals(Arrays.asList("ES256", "ES384", "ES512"), JSONObjectUtils.getStringList(jsonObject, "dpop_signing_alg_values_supported"));
		
		as = AuthorizationServerMetadata.parse(jsonObject);
		assertEquals(Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512), as.getDPoPJWSAlgs());
	}
	
	
	public void testJARM() throws ParseException {
		
		AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		as.applyDefaults();
		
		assertNull(as.getAuthorizationJWSAlgs());
		assertNull(as.getAuthorizationJWEAlgs());
		assertNull(as.getAuthorizationJWEEncs());
		
		List<JWSAlgorithm> jwsAlgs = Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512);
		as.setAuthorizationJWSAlgs(jwsAlgs);
		assertEquals(jwsAlgs, as.getAuthorizationJWSAlgs());
		
		List<JWEAlgorithm> jweAlgs = Arrays.asList(JWEAlgorithm.ECDH_ES, JWEAlgorithm.ECDH_ES_A128KW);
		as.setAuthorizationJWEAlgs(jweAlgs);
		assertEquals(jweAlgs, as.getAuthorizationJWEAlgs());
		
		List<EncryptionMethod> jweEncs = Arrays.asList(EncryptionMethod.A128GCM, EncryptionMethod.A256GCM);
		as.setAuthorizationJWEEncs(jweEncs);
		assertEquals(jweEncs, as.getAuthorizationJWEEncs());
		
		JSONObject jsonObject = as.toJSONObject();
		
		assertEquals(
			Arrays.asList(JWSAlgorithm.ES256.getName(), JWSAlgorithm.ES384.getName(), JWSAlgorithm.ES512.getName()),
			JSONObjectUtils.getStringList(jsonObject, "authorization_signing_alg_values_supported")
		);
		
		assertEquals(
			Arrays.asList(JWEAlgorithm.ECDH_ES.getName(), JWEAlgorithm.ECDH_ES_A128KW.getName()),
			JSONObjectUtils.getStringList(jsonObject, "authorization_encryption_alg_values_supported")
		);
		
		assertEquals(
			Arrays.asList(EncryptionMethod.A128GCM.getName(), EncryptionMethod.A256GCM.getName()),
			JSONObjectUtils.getStringList(jsonObject, "authorization_encryption_enc_values_supported")
		);
		
		as = AuthorizationServerMetadata.parse(jsonObject.toJSONString());
		
		assertEquals(jwsAlgs, as.getAuthorizationJWSAlgs());
		assertEquals(jweAlgs, as.getAuthorizationJWEAlgs());
		assertEquals(jweEncs, as.getAuthorizationJWEEncs());
	}
	
	
	public void testRequestObjectEndpoint() throws ParseException {
		
		AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		as.applyDefaults();
		assertNull(as.getRequestObjectEndpoint());
		
		JSONObject jsonObject = as.toJSONObject();
		assertFalse(jsonObject.containsKey("request_object_endpoint"));
		
		URI endpoint = URI.create("https://c2id.com/requests");
		
		as.setRequestObjectEndpoint(endpoint);
		
		assertEquals(endpoint, as.getRequestObjectEndpoint());
		
		jsonObject = as.toJSONObject();
		assertEquals(endpoint.toString(), jsonObject.get("request_object_endpoint"));
		
		as = AuthorizationServerMetadata.parse(jsonObject);
		
		assertEquals(endpoint, as.getRequestObjectEndpoint());
	}
	
	
	public void testRequestURIParamSupported_defaultFalse() throws ParseException {
		
		AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		assertFalse(as.supportsRequestURIParam());
		
		as.applyDefaults();
		assertFalse(as.supportsRequestURIParam());
		
		JSONObject jsonObject = as.toJSONObject();
		assertNull(jsonObject.get("request_uri_parameter_supported"));
		
		as = AuthorizationServerMetadata.parse(jsonObject);
		assertFalse(as.supportsRequestURIParam());
	}
	
	
	public void testAuthorizationResponseIssuerParameterSupported_default() throws ParseException {
		
		AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		assertFalse(as.supportsAuthorizationResponseIssuerParam());
		
		as.applyDefaults();
		assertFalse(as.supportsAuthorizationResponseIssuerParam());
		
		JSONObject jsonObject = as.toJSONObject();
		assertNull(jsonObject.get("authorization_response_iss_parameter_supported"));
		
		as = AuthorizationServerMetadata.parse(jsonObject);
		assertFalse(as.supportsAuthorizationResponseIssuerParam());
	}
	
	
	public void testAuthorizationResponseIssuerParameterSupported_set() throws ParseException {
		
		AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		assertFalse(as.supportsAuthorizationResponseIssuerParam());
		
		as.setSupportsAuthorizationResponseIssuerParam(true);
		assertTrue(as.supportsAuthorizationResponseIssuerParam());
		
		as.applyDefaults();
		assertTrue(as.supportsAuthorizationResponseIssuerParam());
		
		JSONObject jsonObject = as.toJSONObject();
		assertTrue(JSONObjectUtils.getBoolean(jsonObject, "authorization_response_iss_parameter_supported"));
		
		as = AuthorizationServerMetadata.parse(jsonObject);
		assertTrue(as.supportsAuthorizationResponseIssuerParam());
	}
	
	
	public void testPAR() throws ParseException {
		
		AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		
		assertNull(as.getPushedAuthorizationRequestEndpointURI());
		assertFalse(as.requiresPushedAuthorizationRequests());
		
		as.applyDefaults();
		assertNull(as.getPushedAuthorizationRequestEndpointURI());
		assertFalse(as.requiresPushedAuthorizationRequests());
		
		URI parEndpoint = URI.create("https://c2id.com/par");
		as.setPushedAuthorizationRequestEndpointURI(parEndpoint);
		assertEquals(parEndpoint, as.getPushedAuthorizationRequestEndpointURI());
		
		JSONObject jsonObject = as.toJSONObject();
		assertEquals(parEndpoint.toString(), jsonObject.get("pushed_authorization_request_endpoint"));
		assertFalse(jsonObject.containsKey("require_pushed_authorization_requests"));
		
		as = AuthorizationServerMetadata.parse(jsonObject.toJSONString());
		assertEquals(parEndpoint, as.getPushedAuthorizationRequestEndpointURI());
		assertFalse(as.requiresPushedAuthorizationRequests());
	}
	
	
	public void testPAR_requiredByAS() throws ParseException {
		
		AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		
		assertNull(as.getPushedAuthorizationRequestEndpointURI());
		assertFalse(as.requiresPushedAuthorizationRequests());
		
		as.applyDefaults();
		assertNull(as.getPushedAuthorizationRequestEndpointURI());
		assertFalse(as.requiresPushedAuthorizationRequests());
		
		URI parEndpoint = URI.create("https://c2id.com/par");
		as.setPushedAuthorizationRequestEndpointURI(parEndpoint);
		assertEquals(parEndpoint, as.getPushedAuthorizationRequestEndpointURI());
		
		as.requiresPushedAuthorizationRequests(true);
		assertTrue(as.requiresPushedAuthorizationRequests());
		
		JSONObject jsonObject = as.toJSONObject();
		assertEquals(parEndpoint.toString(), jsonObject.get("pushed_authorization_request_endpoint"));
		assertTrue((Boolean) jsonObject.get("require_pushed_authorization_requests"));
		
		as = AuthorizationServerMetadata.parse(jsonObject.toJSONString());
		assertEquals(parEndpoint, as.getPushedAuthorizationRequestEndpointURI());
		assertTrue(as.requiresPushedAuthorizationRequests());
	}
	
	
	public void testIncrementalAuthz_none() throws ParseException {
		
		AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		
		assertNull(as.getIncrementalAuthorizationTypes());
		
		JSONObject jsonObject = as.toJSONObject();
		assertFalse(jsonObject.containsKey("incremental_authz_types_supported"));
		
		as = AuthorizationServerMetadata.parse(jsonObject.toJSONString());
		
		assertNull(as.getIncrementalAuthorizationTypes());
		
		assertTrue(as.getCustomParameters().isEmpty());
	}
	
	
	public void testIncrementalAuthz_confidential() throws ParseException {
		
		AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		
		assertNull(as.getIncrementalAuthorizationTypes());
		
		as.setIncrementalAuthorizationTypes(Collections.singletonList(ClientType.CONFIDENTIAL));
		
		assertEquals(Collections.singletonList(ClientType.CONFIDENTIAL), as.getIncrementalAuthorizationTypes());
		
		JSONObject jsonObject = as.toJSONObject();
		assertEquals(Collections.singletonList("confidential"), jsonObject.get("incremental_authz_types_supported"));
		
		as = AuthorizationServerMetadata.parse(jsonObject.toJSONString());
		
		assertEquals(Collections.singletonList(ClientType.CONFIDENTIAL), as.getIncrementalAuthorizationTypes());
		
		assertTrue(as.getCustomParameters().isEmpty());
	}
	
	
	public void testIncrementalAuthz_public() throws ParseException {
		
		AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		
		assertNull(as.getIncrementalAuthorizationTypes());
		
		as.setIncrementalAuthorizationTypes(Collections.singletonList(ClientType.PUBLIC));
		
		assertEquals(Collections.singletonList(ClientType.PUBLIC), as.getIncrementalAuthorizationTypes());
		
		JSONObject jsonObject = as.toJSONObject();
		assertEquals(Collections.singletonList("public"), jsonObject.get("incremental_authz_types_supported"));
		
		as = AuthorizationServerMetadata.parse(jsonObject.toJSONString());
		
		assertEquals(Collections.singletonList(ClientType.PUBLIC), as.getIncrementalAuthorizationTypes());
		
		assertTrue(as.getCustomParameters().isEmpty());
	}
	
	
	public void testIncrementalAuthz_public_confidential() throws ParseException {
		
		AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		
		assertNull(as.getIncrementalAuthorizationTypes());
		
		as.setIncrementalAuthorizationTypes(Arrays.asList(ClientType.PUBLIC, ClientType.CONFIDENTIAL));
		
		assertEquals(Arrays.asList(ClientType.PUBLIC, ClientType.CONFIDENTIAL), as.getIncrementalAuthorizationTypes());
		
		JSONObject jsonObject = as.toJSONObject();
		assertEquals(Arrays.asList("public", "confidential"), jsonObject.get("incremental_authz_types_supported"));
		
		as = AuthorizationServerMetadata.parse(jsonObject.toJSONString());
		
		assertEquals(Arrays.asList(ClientType.PUBLIC, ClientType.CONFIDENTIAL), as.getIncrementalAuthorizationTypes());
		
		assertTrue(as.getCustomParameters().isEmpty());
	}
	
	
	public void testIncrementalAuthz_illegalClientType() {
		
		AuthorizationServerMetadata as = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		
		JSONObject jsonObject = as.toJSONObject();
		jsonObject.put("incremental_authz_types_supported", Collections.singletonList("illegal_client_tupe"));
		
		try {
			AuthorizationServerMetadata.parse(jsonObject.toJSONString());
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal client type in incremental_authz_types_supported field: illegal_client_tupe", e.getMessage());
		}
	}
	
	
	public void testHumanFacingURIsMustBeHTTPSorHTTP() throws LangTagException {
		
		AuthorizationServerMetadata metadata = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		
		String exceptionMessage = "The URI scheme must be https or http";
		
		// service_documentation
		metadata.setServiceDocsURI(URI.create("https://example.com"));
		metadata.setServiceDocsURI(URI.create("http://example.com"));
		
		try {
			metadata.setServiceDocsURI(URI.create("ftp://example.com"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals(exceptionMessage, e.getMessage());
		}
		
		// op_policy_uri
		metadata.setPolicyURI(URI.create("https://example.com"));
		metadata.setPolicyURI(URI.create("http://example.com"));
		
		try {
			metadata.setPolicyURI(URI.create("ftp://example.com"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals(exceptionMessage, e.getMessage());
		}
		
		// op_tos_uri
		metadata.setTermsOfServiceURI(URI.create("https://example.com"));
		metadata.setTermsOfServiceURI(URI.create("http://example.com"));
		
		try {
			metadata.setTermsOfServiceURI(URI.create("ftp://example.com"));
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals(exceptionMessage, e.getMessage());
		}
		
		// Test parse
		metadata = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		metadata.applyDefaults();
		JSONObject jsonObject = metadata.toJSONObject();
		
		// client_uri
		JSONObject copy = new JSONObject();
		copy.putAll(jsonObject);
		copy.put("service_documentation", "ftp://example.com");
		
		try {
			AuthorizationServerMetadata.parse(copy);
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal service_documentation parameter: The URI scheme must be https or http", e.getMessage());
		}
		
		// policy_uri
		copy = new JSONObject();
		copy.putAll(jsonObject);
		copy.put("op_policy_uri", "ftp://example.com");
		
		try {
			AuthorizationServerMetadata.parse(copy);
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal op_policy_uri parameter: The URI scheme must be https or http", e.getMessage());
		}
		
		// tos_uri
		copy = new JSONObject();
		copy.putAll(jsonObject);
		copy.put("op_tos_uri", "ftp://example.com");
		
		try {
			AuthorizationServerMetadata.parse(copy);
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal op_tos_uri parameter: The URI scheme must be https or http", e.getMessage());
		}
	}
	
	
	public void testParseWithMTLSEndpointAliases()
		throws URISyntaxException, ParseException {
	
		AuthorizationServerMetadata metadata = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		
		AuthorizationServerEndpointMetadata endpointMetadata = new AuthorizationServerEndpointMetadata();
		URI tokenEndpoint = new URI("https://c2id.com/token");
		endpointMetadata.setTokenEndpointURI(tokenEndpoint);
		JSONObject endpointsJSONObject = endpointMetadata.toJSONObject();
		assertEquals(tokenEndpoint.toString(), endpointsJSONObject.get("token_endpoint"));
		assertEquals(1, endpointsJSONObject.size());
		
		metadata.setMtlsEndpointAliases(endpointMetadata);
		
		metadata.applyDefaults();
		
		AuthorizationServerMetadata parsed = AuthorizationServerMetadata.parse(metadata.toJSONObject().toJSONString());
		
		assertEquals(endpointMetadata.toJSONObject(), parsed.getMtlsEndpointAliases().toJSONObject());
		assertEquals(metadata.toJSONObject(), parsed.toJSONObject());
	}
	
	
	// https://datatracker.ietf.org/doc/html/rfc8705#section-5
	public void testParseWithMTLSEndpointAliasesExample()
		throws ParseException, URISyntaxException {
		
		String json = 
			"{" +
			"  \"issuer\": \"https://server.example.com\"," +
			"  \"authorization_endpoint\": \"https://server.example.com/authz\"," +
			"  \"token_endpoint\": \"https://server.example.com/token\"," +
			"  \"introspection_endpoint\": \"https://server.example.com/introspect\"," +
			"  \"revocation_endpoint\": \"https://server.example.com/revo\"," +
			"  \"jwks_uri\": \"https://server.example.com/jwks\"," +
			"  \"response_types_supported\": [\"code\"]," +
			"  \"response_modes_supported\": [\"fragment\",\"query\",\"form_post\"]," +
			"  \"grant_types_supported\": [\"authorization_code\", \"refresh_token\"]," +
			"  \"token_endpoint_auth_methods_supported\":" +
			"                  [\"tls_client_auth\",\"client_secret_basic\",\"none\"]," +
			"  \"tls_client_certificate_bound_access_tokens\": true," +
			"  \"mtls_endpoint_aliases\": {" +
			"    \"token_endpoint\": \"https://mtls.example.com/token\"," +
			"    \"revocation_endpoint\": \"https://mtls.example.com/revo\"," +
			"    \"introspection_endpoint\": \"https://mtls.example.com/introspect\"" +
			"  }" +
			"}";
	
		AuthorizationServerMetadata metadata = AuthorizationServerMetadata.parse(json);
		
		assertEquals(new Issuer("https://server.example.com"), metadata.getIssuer());
		assertEquals(new URI("https://server.example.com/authz"), metadata.getAuthorizationEndpointURI());
		assertEquals(new URI("https://server.example.com/token"), metadata.getTokenEndpointURI());
		assertEquals(new URI("https://server.example.com/introspect"), metadata.getIntrospectionEndpointURI());
		assertEquals(new URI("https://server.example.com/revo"), metadata.getRevocationEndpointURI());
		assertEquals(new URI("https://server.example.com/jwks"), metadata.getJWKSetURI());
		assertEquals(Collections.singletonList(ResponseType.CODE), metadata.getResponseTypes());
		assertEquals(Arrays.asList(ResponseMode.FRAGMENT, ResponseMode.QUERY, ResponseMode.FORM_POST), metadata.getResponseModes());
		assertEquals(Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN), metadata.getGrantTypes());
		assertEquals(Arrays.asList(ClientAuthenticationMethod.TLS_CLIENT_AUTH, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, ClientAuthenticationMethod.NONE), metadata.getTokenEndpointAuthMethods());
		assertTrue(metadata.supportsTLSClientCertificateBoundAccessTokens());
		
		// Aliases
		assertEquals(new URI("https://mtls.example.com/token"), metadata.getMtlsEndpointAliases().getTokenEndpointURI());
		assertEquals(new URI("https://mtls.example.com/revo"), metadata.getMtlsEndpointAliases().getRevocationEndpointURI());
		assertEquals(new URI("https://mtls.example.com/introspect"), metadata.getMtlsEndpointAliases().getIntrospectionEndpointURI());
		assertEquals(3, metadata.getMtlsEndpointAliases().toJSONObject().size());
		
		assertEquals(12, metadata.toJSONObject().size());
	}
	
	
	public void testPromptValuesSupported() throws ParseException {
		
		AuthorizationServerMetadata metadata = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		metadata.applyDefaults();
		
		assertNull(metadata.getPromptTypes());
		
		List<Prompt.Type> promptTypes = Arrays.asList(Prompt.Type.LOGIN, Prompt.Type.CREATE);
		
		metadata.setPromptTypes(promptTypes);
		
		assertEquals(promptTypes, metadata.getPromptTypes());
		
		JSONObject jsonObject = metadata.toJSONObject();
		
		assertEquals(Arrays.asList("login", "create"), jsonObject.get("prompt_values_supported"));
		
		metadata = AuthorizationServerMetadata.parse(jsonObject.toJSONString());
		
		assertEquals(promptTypes, metadata.getPromptTypes());
	}
	
	
	public void testPromptValuesSupport_parseIllegal() {
		
		AuthorizationServerMetadata metadata = new AuthorizationServerMetadata(new Issuer("https://c2id.com"));
		metadata.applyDefaults();
		JSONObject jsonObject = metadata.toJSONObject();
		
		jsonObject.put("prompt_values_supported", Arrays.asList("login", "create", "xxx"));
		
		try {
			AuthorizationServerMetadata.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Unknown prompt type: xxx", e.getMessage());
		}
	}
	
	
	public void testFederation() throws ParseException {
		
		Issuer issuer = new Issuer("https://c2id.com");
		
		AuthorizationServerMetadata metadata = new AuthorizationServerMetadata(issuer);
		
		String orgName = "Connect2id";
		metadata.setOrganizationName(orgName);
		assertEquals(orgName, metadata.getOrganizationName());
		
		URI signedJWKSetURI = URI.create("https://c2id.com/jwks.jwt");
		metadata.setSignedJWKSetURI(signedJWKSetURI);
		assertEquals(signedJWKSetURI, metadata.getSignedJWKSetURI());
		
		List<ClientRegistrationType> registrationTypes = Arrays.asList(ClientRegistrationType.AUTOMATIC, ClientRegistrationType.EXPLICIT);
		metadata.setClientRegistrationTypes(registrationTypes);
		assertEquals(registrationTypes, metadata.getClientRegistrationTypes());
		
		Map<EndpointName, List<ClientAuthenticationMethod>> autoRegMethods = new HashMap<>();
		autoRegMethods.put(EndpointName.AUTHORIZATION, Collections.singletonList(ClientAuthenticationMethod.REQUEST_OBJECT));
		autoRegMethods.put(EndpointName.PAR, Arrays.asList(ClientAuthenticationMethod.REQUEST_OBJECT, ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH));
		metadata.setClientRegistrationAuthnMethods(autoRegMethods);
		assertEquals(autoRegMethods, metadata.getClientRegistrationAuthnMethods());
		
		metadata.setClientRegistrationAuthnJWSAlgs(Collections.singletonList(JWSAlgorithm.RS256));
		assertEquals(Collections.singletonList(JWSAlgorithm.RS256), metadata.getClientRegistrationAuthnJWSAlgs());
		
		URI fedRegEndpoint = URI.create("https://c2id.com/clients/federation");
		metadata.setFederationRegistrationEndpointURI(fedRegEndpoint);
		assertEquals(fedRegEndpoint, metadata.getFederationRegistrationEndpointURI());
		
		JSONObject o = metadata.toJSONObject();
		
		assertEquals(issuer.getValue(), JSONObjectUtils.getURI(o, "issuer").toString());
		assertEquals(orgName, JSONObjectUtils.getString(o, "organization_name"));
		assertEquals(signedJWKSetURI, JSONObjectUtils.getURI(o, "signed_jwks_uri"));
		assertEquals(Collections.singletonList(ClientAuthenticationMethod.REQUEST_OBJECT.getValue()), JSONObjectUtils.getJSONObject(o, "request_authentication_methods_supported").get(EndpointName.AUTHORIZATION.getValue()));
		assertEquals(Arrays.asList(ClientAuthenticationMethod.REQUEST_OBJECT.getValue(), ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH.getValue()), JSONObjectUtils.getJSONObject(o, "request_authentication_methods_supported").get(EndpointName.PAR.getValue()));
		assertEquals(2, JSONObjectUtils.getJSONObject(o, "request_authentication_methods_supported").size());
		assertEquals(Collections.singletonList(JWSAlgorithm.RS256.getName()), JSONObjectUtils.getStringList(o, "request_authentication_signing_alg_values_supported"));
		assertEquals(fedRegEndpoint, JSONObjectUtils.getURI(o, "federation_registration_endpoint"));
		assertEquals(7, o.size());
		
		metadata = AuthorizationServerMetadata.parse(o.toJSONString());
		
		assertEquals(orgName, metadata.getOrganizationName());
		assertEquals(signedJWKSetURI, metadata.getSignedJWKSetURI());
		assertEquals(registrationTypes, metadata.getClientRegistrationTypes());
		assertEquals(autoRegMethods, metadata.getClientRegistrationAuthnMethods());
		assertEquals(Collections.singletonList(JWSAlgorithm.RS256), metadata.getClientRegistrationAuthnJWSAlgs());
		assertEquals(fedRegEndpoint, metadata.getFederationRegistrationEndpointURI());
	}
	
	
	public void testFederation_multipleJWKSets() throws JOSEException {
		
		Issuer issuer = new Issuer("https://c2id.com");
		
		URI jwkSetURI = URI.create("https://c2id.com/jwks.json");
		
		URI signedJWKSetURI = URI.create("https://c2id.com/jwks.jwt");
		
		JWKSet jwkSet = new JWKSet(
			new RSAKeyGenerator(2048)
				.keyID("1")
				.generate());
		
		AuthorizationServerMetadata metadata = new AuthorizationServerMetadata(issuer);
	}
}
