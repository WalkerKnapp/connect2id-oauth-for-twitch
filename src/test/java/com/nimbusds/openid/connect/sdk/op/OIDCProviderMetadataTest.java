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

package com.nimbusds.openid.connect.sdk.op;


import java.net.URI;
import java.util.*;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerEndpointMetadata;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.ciba.BackChannelTokenDeliveryMode;
import com.nimbusds.oauth2.sdk.client.ClientType;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.assurance.IdentityTrustFramework;
import com.nimbusds.openid.connect.sdk.assurance.evidences.*;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.AttachmentType;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.HashAlgorithm;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimType;
import com.nimbusds.openid.connect.sdk.federation.registration.ClientRegistrationType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;


public class OIDCProviderMetadataTest extends TestCase {


	public void testRegisteredParameters() {

		Set<String> paramNames = OIDCProviderMetadata.getRegisteredParameterNames();

		assertTrue(paramNames.contains("issuer"));
		assertTrue(paramNames.contains("authorization_endpoint"));
		assertTrue(paramNames.contains("token_endpoint"));
		assertTrue(paramNames.contains("userinfo_endpoint"));
		assertTrue(paramNames.contains("jwks_uri"));
		assertTrue(paramNames.contains("registration_endpoint"));
		assertTrue(paramNames.contains("scopes_supported"));
		assertTrue(paramNames.contains("response_types_supported"));
		assertTrue(paramNames.contains("response_modes_supported"));
		assertTrue(paramNames.contains("grant_types_supported"));
		assertTrue(paramNames.contains("code_challenge_methods_supported"));
		assertTrue(paramNames.contains("acr_values_supported"));
		assertTrue(paramNames.contains("subject_types_supported"));
		assertTrue(paramNames.contains("id_token_signing_alg_values_supported"));
		assertTrue(paramNames.contains("id_token_encryption_alg_values_supported"));
		assertTrue(paramNames.contains("id_token_encryption_enc_values_supported"));
		assertTrue(paramNames.contains("userinfo_signing_alg_values_supported"));
		assertTrue(paramNames.contains("userinfo_encryption_alg_values_supported"));
		assertTrue(paramNames.contains("userinfo_encryption_enc_values_supported"));
		assertTrue(paramNames.contains("pushed_authorization_request_endpoint"));
		assertTrue(paramNames.contains("require_pushed_authorization_requests"));
		assertTrue(paramNames.contains("request_object_endpoint"));
		assertTrue(paramNames.contains("request_object_signing_alg_values_supported"));
		assertTrue(paramNames.contains("request_object_encryption_alg_values_supported"));
		assertTrue(paramNames.contains("request_object_encryption_enc_values_supported"));
		assertTrue(paramNames.contains("token_endpoint_auth_methods_supported"));
		assertTrue(paramNames.contains("token_endpoint_auth_signing_alg_values_supported"));
		assertTrue(paramNames.contains("display_values_supported"));
		assertTrue(paramNames.contains("claim_types_supported"));
		assertTrue(paramNames.contains("claims_supported"));
		assertTrue(paramNames.contains("service_documentation"));
		assertTrue(paramNames.contains("claims_locales_supported"));
		assertTrue(paramNames.contains("ui_locales_supported"));
		assertTrue(paramNames.contains("claims_parameter_supported"));
		assertTrue(paramNames.contains("request_parameter_supported"));
		assertTrue(paramNames.contains("request_uri_parameter_supported"));
		assertTrue(paramNames.contains("require_request_uri_registration"));
		assertTrue(paramNames.contains("authorization_response_iss_parameter_supported"));
		assertTrue(paramNames.contains("op_policy_uri"));
		assertTrue(paramNames.contains("op_tos_uri"));
		assertTrue(paramNames.contains("check_session_iframe"));
		assertTrue(paramNames.contains("end_session_endpoint"));
		assertTrue(paramNames.contains("introspection_endpoint"));
		assertTrue(paramNames.contains("introspection_endpoint_auth_methods_supported"));
		assertTrue(paramNames.contains("introspection_endpoint_auth_signing_alg_values_supported"));
		assertTrue(paramNames.contains("revocation_endpoint"));
		assertTrue(paramNames.contains("revocation_endpoint_auth_methods_supported"));
		assertTrue(paramNames.contains("revocation_endpoint_auth_signing_alg_values_supported"));
		assertTrue(paramNames.contains("frontchannel_logout_supported"));
		assertTrue(paramNames.contains("frontchannel_logout_session_supported"));
		assertTrue(paramNames.contains("backchannel_logout_supported"));
		assertTrue(paramNames.contains("backchannel_logout_session_supported"));
		assertTrue(paramNames.contains("mtls_endpoint_aliases"));
		assertTrue(paramNames.contains("tls_client_certificate_bound_access_tokens"));
		assertTrue(paramNames.contains("dpop_signing_alg_values_supported"));
		assertTrue(paramNames.contains("authorization_signing_alg_values_supported"));
		assertTrue(paramNames.contains("authorization_encryption_alg_values_supported"));
		assertTrue(paramNames.contains("authorization_encryption_enc_values_supported"));
		assertTrue(paramNames.contains("device_authorization_endpoint"));
		assertTrue(paramNames.contains("incremental_authz_types_supported"));
		assertTrue(paramNames.contains("verified_claims_supported"));
		assertTrue(paramNames.contains("trust_frameworks_supported"));
		assertTrue(paramNames.contains("evidence_supported"));
		assertTrue(paramNames.contains("documents_supported"));
		assertTrue(paramNames.contains("documents_methods_supported"));
		assertTrue(paramNames.contains("documents_validation_methods_supported"));
		assertTrue(paramNames.contains("documents_verification_methods_supported"));
		assertTrue(paramNames.contains("id_documents_supported"));
		assertTrue(paramNames.contains("id_documents_verification_methods_supported"));
		assertTrue(paramNames.contains("electronic_records_supported"));
		assertTrue(paramNames.contains("claims_in_verified_claims_supported"));
		assertTrue(paramNames.contains("attachments_supported"));
		assertTrue(paramNames.contains("digest_algorithms_supported"));
		assertTrue(paramNames.contains("organization_name"));
		assertTrue(paramNames.contains("signed_jwks_uri"));
		assertTrue(paramNames.contains("jwks"));
		assertTrue(paramNames.contains("client_registration_types_supported"));
		assertTrue(paramNames.contains("request_authentication_methods_supported"));
		assertTrue(paramNames.contains("request_authentication_signing_alg_values_supported"));
		assertTrue(paramNames.contains("federation_registration_endpoint"));
		assertTrue(paramNames.contains("prompt_values_supported"));
		assertEquals(85, paramNames.size());
	}


	public void testParseExample() throws Exception {

		String s = "{\n" +
			"   \"issuer\":\n" +
			"     \"https://server.example.com\",\n" +
			"   \"authorization_endpoint\":\n" +
			"     \"https://server.example.com/connect/authorize\",\n" +
			"   \"token_endpoint\":\n" +
			"     \"https://server.example.com/connect/token\",\n" +
			"   \"token_endpoint_auth_methods_supported\":\n" +
			"     [\"client_secret_basic\", \"private_key_jwt\"],\n" +
			"   \"token_endpoint_auth_signing_alg_values_supported\":\n" +
			"     [\"RS256\", \"ES256\"],\n" +
			"   \"userinfo_endpoint\":\n" +
			"     \"https://server.example.com/connect/userinfo\",\n" +
			"   \"check_session_iframe\":\n" +
			"     \"https://server.example.com/connect/check_session\",\n" +
			"   \"end_session_endpoint\":\n" +
			"     \"https://server.example.com/connect/end_session\",\n" +
			"   \"jwks_uri\":\n" +
			"     \"https://server.example.com/jwks.json\",\n" +
			"   \"registration_endpoint\":\n" +
			"     \"https://server.example.com/connect/register\",\n" +
			"   \"scopes_supported\":\n" +
			"     [\"openid\", \"profile\", \"email\", \"address\",\n" +
			"      \"phone\", \"offline_access\"],\n" +
			"   \"response_types_supported\":\n" +
			"     [\"code\", \"code id_token\", \"id_token\", \"token id_token\"],\n" +
			"   \"acr_values_supported\":\n" +
			"     [\"urn:mace:incommon:iap:silver\",\n" +
			"      \"urn:mace:incommon:iap:bronze\"],\n" +
			"   \"subject_types_supported\":\n" +
			"     [\"public\", \"pairwise\"],\n" +
			"   \"userinfo_signing_alg_values_supported\":\n" +
			"     [\"RS256\", \"ES256\", \"HS256\"],\n" +
			"   \"userinfo_encryption_alg_values_supported\":\n" +
			"     [\"RSA1_5\", \"A128KW\"],\n" +
			"   \"userinfo_encryption_enc_values_supported\":\n" +
			"     [\"A128CBC-HS256\", \"A128GCM\"],\n" +
			"   \"id_token_signing_alg_values_supported\":\n" +
			"     [\"RS256\", \"ES256\", \"HS256\"],\n" +
			"   \"id_token_encryption_alg_values_supported\":\n" +
			"     [\"RSA1_5\", \"A128KW\"],\n" +
			"   \"id_token_encryption_enc_values_supported\":\n" +
			"     [\"A128CBC-HS256\", \"A128GCM\"],\n" +
			"   \"request_object_signing_alg_values_supported\":\n" +
			"     [\"none\", \"RS256\", \"ES256\"],\n" +
			"   \"display_values_supported\":\n" +
			"     [\"page\", \"popup\"],\n" +
			"   \"claim_types_supported\":\n" +
			"     [\"normal\", \"distributed\"],\n" +
			"   \"claims_supported\":\n" +
			"     [\"sub\", \"iss\", \"auth_time\", \"acr\",\n" +
			"      \"name\", \"given_name\", \"family_name\", \"nickname\",\n" +
			"      \"profile\", \"picture\", \"website\",\n" +
			"      \"email\", \"email_verified\", \"locale\", \"zoneinfo\",\n" +
			"      \"http://example.info/claims/groups\"],\n" +
			"   \"claims_parameter_supported\":\n" +
			"     true,\n" +
			"   \"service_documentation\":\n" +
			"     \"http://server.example.com/connect/service_documentation.html\",\n" +
			"   \"ui_locales_supported\":\n" +
			"     [\"en-US\", \"en-GB\", \"en-CA\", \"fr-FR\", \"fr-CA\"]\n" +
			"  }";
		
		OIDCProviderMetadata op = OIDCProviderMetadata.parse(s);
		
		assertEquals("https://server.example.com", op.getIssuer().getValue());
		assertEquals("https://server.example.com/connect/authorize", op.getAuthorizationEndpointURI().toString());
		assertEquals("https://server.example.com/connect/token", op.getTokenEndpointURI().toString());
		
		List<ClientAuthenticationMethod> authMethods = op.getTokenEndpointAuthMethods();
		assertTrue(authMethods.contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
		assertTrue(authMethods.contains(ClientAuthenticationMethod.PRIVATE_KEY_JWT));
		assertEquals(2, authMethods.size());
		
		List<JWSAlgorithm> tokenEndpointJWSAlgs = op.getTokenEndpointJWSAlgs();
		assertTrue(tokenEndpointJWSAlgs.contains(JWSAlgorithm.RS256));
		assertTrue(tokenEndpointJWSAlgs.contains(JWSAlgorithm.ES256));
		assertEquals(2, tokenEndpointJWSAlgs.size());

		assertNull(op.getCodeChallengeMethods());
		
		assertEquals("https://server.example.com/connect/userinfo", op.getUserInfoEndpointURI().toString());
		
		assertEquals("https://server.example.com/connect/check_session", op.getCheckSessionIframeURI().toString());
		assertEquals("https://server.example.com/connect/end_session", op.getEndSessionEndpointURI().toString());
		
		assertEquals("https://server.example.com/jwks.json", op.getJWKSetURI().toString());
		
		assertEquals("https://server.example.com/connect/register", op.getRegistrationEndpointURI().toString());
		Scope scopes = op.getScopes();
		assertTrue(scopes.contains(OIDCScopeValue.OPENID));
		assertTrue(scopes.contains(OIDCScopeValue.PROFILE));
		assertTrue(scopes.contains(OIDCScopeValue.EMAIL));
		assertTrue(scopes.contains(OIDCScopeValue.ADDRESS));
		assertTrue(scopes.contains(OIDCScopeValue.PHONE));
		assertTrue(scopes.contains(OIDCScopeValue.OFFLINE_ACCESS));
		assertEquals(6, scopes.size());
		
		List<ResponseType> rts = op.getResponseTypes();
		// [\"code\", \"code id_token\", \"id_token\", \"token id_token\"]
		ResponseType rt1 = new ResponseType();
		rt1.add(ResponseType.Value.CODE);
		assertTrue(rts.contains(rt1));
		
		ResponseType rt2 = new ResponseType();
		rt2.add(ResponseType.Value.CODE);
		rt2.add(OIDCResponseTypeValue.ID_TOKEN);
		assertTrue(rts.contains(rt2));
		
		ResponseType rt3 = new ResponseType();
		rt3.add(OIDCResponseTypeValue.ID_TOKEN);
		assertTrue(rts.contains(rt3));
		
		ResponseType rt4 = new ResponseType();
		rt4.add(ResponseType.Value.TOKEN);
		rt4.add(OIDCResponseTypeValue.ID_TOKEN);
		assertTrue(rts.contains(rt4));
		
		assertEquals(4, rts.size());
		
		List<ACR> acrValues = op.getACRs();
		assertTrue(acrValues.contains(new ACR("urn:mace:incommon:iap:silver")));
		assertTrue(acrValues.contains(new ACR("urn:mace:incommon:iap:bronze")));
		assertEquals(2, acrValues.size());
		
		List<SubjectType> subjectTypes = op.getSubjectTypes();
		assertTrue(subjectTypes.contains(SubjectType.PUBLIC));
		assertTrue(subjectTypes.contains(SubjectType.PAIRWISE));
		assertEquals(2, subjectTypes.size());
		
		// UserInfo
		List<JWSAlgorithm> userInfoJWSAlgs = op.getUserInfoJWSAlgs();
		assertTrue(userInfoJWSAlgs.contains(JWSAlgorithm.RS256));
		assertTrue(userInfoJWSAlgs.contains(JWSAlgorithm.ES256));
		assertTrue(userInfoJWSAlgs.contains(JWSAlgorithm.HS256));
		assertEquals(3, userInfoJWSAlgs.size());
		
		List<JWEAlgorithm> userInfoJWEalgs = op.getUserInfoJWEAlgs();
		assertTrue(userInfoJWEalgs.contains(JWEAlgorithm.RSA1_5));
		assertTrue(userInfoJWEalgs.contains(JWEAlgorithm.A128KW));
		assertEquals(2, userInfoJWEalgs.size());
		
		List<EncryptionMethod> userInfoEncs = op.getUserInfoJWEEncs();
		assertTrue(userInfoEncs.contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(userInfoEncs.contains(EncryptionMethod.A128GCM));
		assertEquals(2, userInfoEncs.size());
	
		// ID token
		List<JWSAlgorithm> idTokenJWSAlgs = op.getIDTokenJWSAlgs();
		assertTrue(idTokenJWSAlgs.contains(JWSAlgorithm.RS256));
		assertTrue(idTokenJWSAlgs.contains(JWSAlgorithm.ES256));
		assertTrue(idTokenJWSAlgs.contains(JWSAlgorithm.HS256));
		assertEquals(3, idTokenJWSAlgs.size());
		
		List<JWEAlgorithm> idTokenJWEAlgs = op.getIDTokenJWEAlgs();
		assertTrue(idTokenJWEAlgs.contains(JWEAlgorithm.RSA1_5));
		assertTrue(idTokenJWEAlgs.contains(JWEAlgorithm.A128KW));
		assertEquals(2, idTokenJWEAlgs.size());
		
		List<EncryptionMethod> idTokenEncs = op.getIDTokenJWEEncs();
		assertTrue(idTokenEncs.contains(EncryptionMethod.A128CBC_HS256));
		assertTrue(idTokenEncs.contains(EncryptionMethod.A128GCM));
		assertEquals(2, idTokenEncs.size());
		
		// Request object
		List<JWSAlgorithm> requestObjectJWSAlgs = op.getRequestObjectJWSAlgs();
		assertTrue(requestObjectJWSAlgs.contains(JWSAlgorithm.NONE));
		assertTrue(requestObjectJWSAlgs.contains(JWSAlgorithm.RS256));
		assertTrue(requestObjectJWSAlgs.contains(JWSAlgorithm.ES256));
		
		List<Display> displayTypes = op.getDisplays();
		assertTrue(displayTypes.contains(Display.PAGE));
		assertTrue(displayTypes.contains(Display.POPUP));
		assertEquals(2, displayTypes.size());
		
		List<ClaimType> claimTypes = op.getClaimTypes();
		assertTrue(claimTypes.contains(ClaimType.NORMAL));
		assertTrue(claimTypes.contains(ClaimType.DISTRIBUTED));
		assertEquals(2, claimTypes.size());
		
		List<String> claims = op.getClaims();
		assertTrue(claims.contains("sub"));
		assertTrue(claims.contains("iss"));
		assertTrue(claims.contains("auth_time"));
		assertTrue(claims.contains("acr"));
		assertTrue(claims.contains("name"));
		assertTrue(claims.contains("given_name"));
		assertTrue(claims.contains("family_name"));
		assertTrue(claims.contains("nickname"));
		assertTrue(claims.contains("profile"));
		assertTrue(claims.contains("picture"));
		assertTrue(claims.contains("website"));
		assertTrue(claims.contains("email"));
		assertTrue(claims.contains("email_verified"));
		assertTrue(claims.contains("locale"));
		assertTrue(claims.contains("zoneinfo"));
		assertTrue(claims.contains("http://example.info/claims/groups"));
		assertEquals(16, claims.size());
		
		assertTrue(op.supportsClaimsParam());
		
		assertEquals("http://server.example.com/connect/service_documentation.html", op.getServiceDocsURI().toString());
		
		List<LangTag> uiLocales = op.getUILocales();
		assertTrue(uiLocales.contains(LangTag.parse("en-US")));
		assertTrue(uiLocales.contains(LangTag.parse("en-GB")));
		assertTrue(uiLocales.contains(LangTag.parse("en-CA")));
		assertTrue(uiLocales.contains(LangTag.parse("fr-FR")));
		assertTrue(uiLocales.contains(LangTag.parse("fr-CA")));
		assertEquals(5, uiLocales.size());
		
		// logout channels
		assertFalse(op.supportsFrontChannelLogout());
		assertFalse(op.supportsFrontChannelLogoutSession());
		assertFalse(op.supportsBackChannelLogout());
		assertFalse(op.supportsBackChannelLogoutSession());
		
		assertNull(op.getMtlsEndpointAliases());
		assertFalse(op.supportsTLSClientCertificateBoundAccessTokens());
		assertFalse(op.supportsMutualTLSSenderConstrainedAccessTokens());
		
		assertNull(op.getAuthorizationJWSAlgs());
		assertNull(op.getAuthorizationJWEAlgs());
		assertNull(op.getAuthorizationJWEEncs());

		assertTrue(op.getCustomParameters().isEmpty());
	}


	public void testGettersAndSetters()
		throws Exception {

		Issuer issuer = new Issuer("https://c2id.com");

		List<SubjectType> subjectTypes = new LinkedList<>();
		subjectTypes.add(SubjectType.PAIRWISE);
		subjectTypes.add(SubjectType.PUBLIC);

		URI jwkSetURI = new URI("https://c2id.com/jwks.json");

		OIDCProviderMetadata meta = new OIDCProviderMetadata(issuer, subjectTypes, jwkSetURI);

		assertEquals(issuer.getValue(), meta.getIssuer().getValue());
		assertEquals(SubjectType.PAIRWISE, meta.getSubjectTypes().get(0));
		assertEquals(SubjectType.PUBLIC, meta.getSubjectTypes().get(1));
		assertEquals(jwkSetURI.toString(), meta.getJWKSetURI().toString());

		meta.setAuthorizationEndpointURI(new URI("https://c2id.com/authz"));
		assertEquals("https://c2id.com/authz", meta.getAuthorizationEndpointURI().toString());

		meta.setTokenEndpointURI(new URI("https://c2id.com/token"));
		assertEquals("https://c2id.com/token", meta.getTokenEndpointURI().toString());

		meta.setUserInfoEndpointURI(new URI("https://c2id.com/userinfo"));
		assertEquals("https://c2id.com/userinfo", meta.getUserInfoEndpointURI().toString());

		meta.setRegistrationEndpointURI(new URI("https://c2id.com/reg"));
		assertEquals("https://c2id.com/reg", meta.getRegistrationEndpointURI().toString());
		
		meta.setIntrospectionEndpointURI(new URI("https://c2id.com/inspect"));
		assertEquals("https://c2id.com/inspect", meta.getIntrospectionEndpointURI().toString());
		
		meta.setRevocationEndpointURI(new URI("https://c2id.com/revoke"));
		assertEquals("https://c2id.com/revoke", meta.getRevocationEndpointURI().toString());

		meta.setCheckSessionIframeURI(new URI("https://c2id.com/session"));
		assertEquals("https://c2id.com/session", meta.getCheckSessionIframeURI().toString());

		meta.setEndSessionEndpointURI(new URI("https://c2id.com/logout"));
		assertEquals("https://c2id.com/logout", meta.getEndSessionEndpointURI().toString());
		
		meta.setFederationRegistrationEndpointURI(new URI("https://c2id.com/fed"));
		assertEquals("https://c2id.com/fed", meta.getFederationRegistrationEndpointURI().toString());
		
		meta.setDeviceAuthorizationEndpointURI(new URI("https://c2id.com/device"));
		assertEquals("https://c2id.com/device", meta.getDeviceAuthorizationEndpointURI().toString());

		meta.setScopes(Scope.parse("openid email profile"));
		assertTrue(Scope.parse("openid email profile").containsAll(meta.getScopes()));

		List<ResponseType> responseTypes = new LinkedList<>();
		ResponseType rt1 = new ResponseType();
		rt1.add(ResponseType.Value.CODE);
		responseTypes.add(rt1);
		meta.setResponseTypes(responseTypes);
		responseTypes = meta.getResponseTypes();
		assertEquals(ResponseType.Value.CODE, responseTypes.iterator().next().iterator().next());
		assertEquals(1, responseTypes.size());

		List<ResponseMode> responseModes = new LinkedList<>();
		responseModes.add(ResponseMode.QUERY);
		responseModes.add(ResponseMode.FRAGMENT);
		meta.setResponseModes(responseModes);
		assertTrue(meta.getResponseModes().contains(ResponseMode.QUERY));
		assertTrue(meta.getResponseModes().contains(ResponseMode.FRAGMENT));
		assertEquals(2, meta.getResponseModes().size());

		List<GrantType> grantTypes = new LinkedList<>();
		grantTypes.add(GrantType.AUTHORIZATION_CODE);
		grantTypes.add(GrantType.REFRESH_TOKEN);
		meta.setGrantTypes(grantTypes);
		assertTrue(meta.getGrantTypes().contains(GrantType.AUTHORIZATION_CODE));
		assertTrue(meta.getGrantTypes().contains(GrantType.REFRESH_TOKEN));
		assertEquals(2, meta.getGrantTypes().size());

		List<CodeChallengeMethod> codeChallengeMethods = Arrays.asList(CodeChallengeMethod.S256, CodeChallengeMethod.S256);
		meta.setCodeChallengeMethods(codeChallengeMethods);
		assertEquals(codeChallengeMethods, meta.getCodeChallengeMethods());

		List<ACR> acrList = new LinkedList<>();
		acrList.add(new ACR("1"));
		meta.setACRs(acrList);
		assertEquals("1", meta.getACRs().get(0).getValue());
		
		meta.setTokenEndpointAuthMethods(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));
		assertEquals(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC), meta.getTokenEndpointAuthMethods());

		meta.setTokenEndpointJWSAlgs(Arrays.asList(JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512));
		assertEquals(Arrays.asList(JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512), meta.getTokenEndpointJWSAlgs());
		
		meta.setIntrospectionEndpointAuthMethods(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_POST));
		assertEquals(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_POST), meta.getIntrospectionEndpointAuthMethods());
		
		meta.setIntrospectionEndpointJWSAlgs(Collections.singletonList(JWSAlgorithm.HS256));
		assertEquals(Collections.singletonList(JWSAlgorithm.HS256), meta.getIntrospectionEndpointJWSAlgs());
		
		meta.setRevocationEndpointAuthMethods(Collections.singletonList(ClientAuthenticationMethod.PRIVATE_KEY_JWT));
		assertEquals(Collections.singletonList(ClientAuthenticationMethod.PRIVATE_KEY_JWT), meta.getRevocationEndpointAuthMethods());
		
		meta.setRevocationEndpointJWSAlgs(Collections.singletonList(JWSAlgorithm.RS256));
		assertEquals(Collections.singletonList(JWSAlgorithm.RS256), meta.getRevocationEndpointJWSAlgs());

		meta.setRequestObjectEndpoint(new URI("https://c2id.com/requests"));
		assertEquals(new URI("https://c2id.com/requests"), meta.getRequestObjectEndpoint());
		
		meta.setPushedAuthorizationRequestEndpointURI(new URI("https://c2id.com/par"));
		assertEquals(new URI("https://c2id.com/par"), meta.getPushedAuthorizationRequestEndpointURI());
		
		List<JWSAlgorithm> requestObjectJWSAlgs = new LinkedList<>();
		requestObjectJWSAlgs.add(JWSAlgorithm.HS256);
		meta.setRequestObjectJWSAlgs(requestObjectJWSAlgs);
		assertEquals(JWSAlgorithm.HS256, meta.getRequestObjectJWSAlgs().get(0));

		List<JWEAlgorithm> requestObjectJWEAlgs = new LinkedList<>();
		requestObjectJWEAlgs.add(JWEAlgorithm.A128KW);
		meta.setRequestObjectJWEAlgs(requestObjectJWEAlgs);
		assertEquals(JWEAlgorithm.A128KW, meta.getRequestObjectJWEAlgs().get(0));

		List<EncryptionMethod> requestObjectEncs = new LinkedList<>();
		requestObjectEncs.add(EncryptionMethod.A128GCM);
		meta.setRequestObjectJWEEncs(requestObjectEncs);
		assertEquals(EncryptionMethod.A128GCM, meta.getRequestObjectJWEEncs().get(0));

		List<JWSAlgorithm> idTokenJWSAlgs = new LinkedList<>();
		idTokenJWSAlgs.add(JWSAlgorithm.RS256);
		meta.setIDTokenJWSAlgs(idTokenJWSAlgs);
		assertEquals(JWSAlgorithm.RS256, meta.getIDTokenJWSAlgs().get(0));

		List<JWEAlgorithm> idTokenJWEalgs = new LinkedList<>();
		idTokenJWEalgs.add(JWEAlgorithm.A256KW);
		meta.setIDTokenJWEAlgs(idTokenJWEalgs);

		List<EncryptionMethod> idTokenEncs = new LinkedList<>();
		idTokenEncs.add(EncryptionMethod.A128GCM);
		meta.setIDTokenJWEEncs(idTokenEncs);
		assertEquals(EncryptionMethod.A128GCM, meta.getIDTokenJWEEncs().get(0));

		List<JWSAlgorithm> userInfoJWSAlgs = new LinkedList<>();
		userInfoJWSAlgs.add(JWSAlgorithm.RS256);
		meta.setUserInfoJWSAlgs(userInfoJWSAlgs);
		assertEquals(JWSAlgorithm.RS256, meta.getUserInfoJWSAlgs().get(0));

		List<JWEAlgorithm> userInfoJWEAlgs = new LinkedList<>();
		userInfoJWEAlgs.add(JWEAlgorithm.RSA1_5);
		meta.setUserInfoJWEAlgs(userInfoJWEAlgs);
		assertEquals(JWEAlgorithm.RSA1_5, meta.getUserInfoJWEAlgs().get(0));

		List<EncryptionMethod> userInfoEncs = new LinkedList<>();
		userInfoEncs.add(EncryptionMethod.A128CBC_HS256);
		meta.setUserInfoJWEEncs(userInfoEncs);
		assertEquals(EncryptionMethod.A128CBC_HS256, meta.getUserInfoJWEEncs().get(0));

		List<Display> displays = new LinkedList<>();
		displays.add(Display.PAGE);
		displays.add(Display.POPUP);
		meta.setDisplays(displays);
		assertEquals(Display.PAGE, meta.getDisplays().get(0));
		assertEquals(Display.POPUP, meta.getDisplays().get(1));
		assertEquals(2, meta.getDisplays().size());

		List<ClaimType> claimTypes = new LinkedList<>();
		claimTypes.add(ClaimType.NORMAL);
		meta.setClaimTypes(claimTypes);
		assertEquals(ClaimType.NORMAL, meta.getClaimTypes().get(0));

		List<String> claims = new LinkedList<>();
		claims.add("name");
		claims.add("email");
		meta.setClaims(claims);
		assertEquals("name", meta.getClaims().get(0));
		assertEquals("email", meta.getClaims().get(1));
		assertEquals(2, meta.getClaims().size());

		List<LangTag> claimLocales = new LinkedList<>();
		claimLocales.add(LangTag.parse("en-GB"));
		meta.setClaimLocales(claimLocales);
		assertEquals("en-GB", meta.getClaimsLocales().get(0).toString());

		List<LangTag> uiLocales = new LinkedList<>();
		uiLocales.add(LangTag.parse("bg-BG"));
		meta.setUILocales(uiLocales);
		assertEquals("bg-BG", meta.getUILocales().get(0).toString());

		meta.setServiceDocsURI(new URI("https://c2id.com/docs"));
		assertEquals("https://c2id.com/docs", meta.getServiceDocsURI().toString());

		meta.setPolicyURI(new URI("https://c2id.com/policy"));
		assertEquals("https://c2id.com/policy", meta.getPolicyURI().toString());

		meta.setTermsOfServiceURI(new URI("https://c2id.com/tos"));
		assertEquals("https://c2id.com/tos", meta.getTermsOfServiceURI().toString());

		meta.setSupportsClaimsParams(true);
		assertTrue(meta.supportsClaimsParam());

		meta.setSupportsRequestParam(true);
		assertTrue(meta.supportsRequestParam());

		meta.setSupportsRequestURIParam(true);
		assertTrue(meta.supportsRequestURIParam());
		
		meta.setBackChannelAuthenticationEndpointURI(new URI("https://c2id.com/ciba"));
		assertEquals("https://c2id.com/ciba", meta.getBackChannelAuthenticationEndpointURI().toString());
		
		userInfoJWSAlgs = new LinkedList<>();
		userInfoJWSAlgs.add(JWSAlgorithm.RS256);
		meta.setBackChannelAuthenticationRequestJWSAlgs(userInfoJWSAlgs);
		assertEquals(JWSAlgorithm.RS256, meta.getBackChannelAuthenticationRequestJWSAlgs().get(0));

		List<BackChannelTokenDeliveryMode> deliveryModes = new LinkedList<>();
		deliveryModes.add(BackChannelTokenDeliveryMode.PING);
		meta.setBackChannelTokenDeliveryModes(deliveryModes); 
		assertEquals(BackChannelTokenDeliveryMode.PING, meta.getBackChannelTokenDeliveryModes().get(0));
		
		meta.setSupportsBackChannelUserCodeParam(true);
		assertTrue(meta.supportsBackChannelUserCodeParam());
		
		meta.setRequiresRequestURIRegistration(true);
		assertTrue(meta.requiresRequestURIRegistration());
		
		meta.setSupportsAuthorizationResponseIssuerParam(true);
		assertTrue(meta.supportsAuthorizationResponseIssuerParam());
		
		assertFalse(meta.supportsFrontChannelLogout());
		meta.setSupportsFrontChannelLogout(true);
		assertTrue(meta.supportsFrontChannelLogout());
		
		assertFalse(meta.supportsFrontChannelLogoutSession());
		meta.setSupportsFrontChannelLogoutSession(true);
		assertTrue(meta.supportsFrontChannelLogoutSession());
		
		assertFalse(meta.supportsBackChannelLogout());
		meta.setSupportsBackChannelLogout(true);
		assertTrue(meta.supportsBackChannelLogout());
		
		assertFalse(meta.supportsBackChannelLogoutSession());
		meta.setSupportsBackChannelLogoutSession(true);
		assertTrue(meta.supportsBackChannelLogoutSession());
		
		assertNull(meta.getPromptTypes());
		meta.setPromptTypes(Arrays.asList(Prompt.Type.LOGIN, Prompt.Type.CREATE));
		assertEquals(Arrays.asList(Prompt.Type.LOGIN, Prompt.Type.CREATE), meta.getPromptTypes());
		
		AuthorizationServerEndpointMetadata asEndpoints = new AuthorizationServerEndpointMetadata();
		asEndpoints.setAuthorizationEndpointURI(meta.getAuthorizationEndpointURI());
		asEndpoints.setTokenEndpointURI(meta.getTokenEndpointURI());
		asEndpoints.setRegistrationEndpointURI(meta.getRegistrationEndpointURI());
		asEndpoints.setIntrospectionEndpointURI(meta.getIntrospectionEndpointURI());
		asEndpoints.setRevocationEndpointURI(meta.getRevocationEndpointURI());
		asEndpoints.setDeviceAuthorizationEndpointURI(meta.getDeviceAuthorizationEndpointURI());
		asEndpoints.setRequestObjectEndpoint(meta.getRequestObjectEndpoint());
		asEndpoints.setPushedAuthorizationRequestEndpointURI(meta.getPushedAuthorizationRequestEndpointURI());
		assertNull(meta.getMtlsEndpointAliases());
		
		meta.setMtlsEndpointAliases(asEndpoints);
		assertTrue(meta.getMtlsEndpointAliases() instanceof OIDCProviderEndpointMetadata);
		assertEquals(meta.getMtlsEndpointAliases().getAuthorizationEndpointURI(), meta.getAuthorizationEndpointURI());
		assertEquals(meta.getMtlsEndpointAliases().getTokenEndpointURI(), meta.getTokenEndpointURI());
		assertEquals(meta.getMtlsEndpointAliases().getRegistrationEndpointURI(), meta.getRegistrationEndpointURI());
		assertEquals(meta.getMtlsEndpointAliases().getIntrospectionEndpointURI(), meta.getIntrospectionEndpointURI());
		assertEquals(meta.getMtlsEndpointAliases().getRevocationEndpointURI(), meta.getRevocationEndpointURI());
		assertEquals(meta.getMtlsEndpointAliases().getDeviceAuthorizationEndpointURI(), meta.getDeviceAuthorizationEndpointURI());
		assertEquals(meta.getMtlsEndpointAliases().getRequestObjectEndpoint(), meta.getRequestObjectEndpoint());
		assertEquals(meta.getMtlsEndpointAliases().getPushedAuthorizationRequestEndpointURI(), meta.getPushedAuthorizationRequestEndpointURI());
		assertNull(meta.getMtlsEndpointAliases().getUserInfoEndpointURI());
		assertNull(meta.getMtlsEndpointAliases().getFederationRegistrationEndpointURI());
		
		meta.getMtlsEndpointAliases().setUserInfoEndpointURI(meta.getUserInfoEndpointURI());
		meta.getMtlsEndpointAliases().setFederationRegistrationEndpointURI(meta.getFederationRegistrationEndpointURI());
		assertEquals(meta.getMtlsEndpointAliases().getUserInfoEndpointURI(), meta.getUserInfoEndpointURI());
		assertEquals(meta.getMtlsEndpointAliases().getFederationRegistrationEndpointURI(), meta.getFederationRegistrationEndpointURI());
		
		assertFalse(meta.supportsTLSClientCertificateBoundAccessTokens());
		assertFalse(meta.supportsMutualTLSSenderConstrainedAccessTokens());
		meta.setSupportsTLSClientCertificateBoundAccessTokens(true);
		meta.setSupportsMutualTLSSenderConstrainedAccessTokens(true);
		assertTrue(meta.supportsTLSClientCertificateBoundAccessTokens());
		assertTrue(meta.supportsMutualTLSSenderConstrainedAccessTokens());
		
		List<JWSAlgorithm> authzJWSAlgs = Collections.singletonList(JWSAlgorithm.ES256);
		meta.setAuthorizationJWSAlgs(authzJWSAlgs);
		assertEquals(authzJWSAlgs, meta.getAuthorizationJWSAlgs());
		
		List<JWEAlgorithm> authzJWEAlgs = Collections.singletonList(JWEAlgorithm.ECDH_ES);
		meta.setAuthorizationJWEAlgs(authzJWEAlgs);
		assertEquals(authzJWEAlgs, meta.getAuthorizationJWEAlgs());
		
		List<EncryptionMethod> authzJWEEncs= Collections.singletonList(EncryptionMethod.A256GCM);
		meta.setAuthorizationJWEEncs(authzJWEEncs);
		assertEquals(authzJWEEncs, meta.getAuthorizationJWEEncs());
		
		List<ClientRegistrationType> federationTypes = Arrays.asList(ClientRegistrationType.AUTOMATIC, ClientRegistrationType.EXPLICIT);
		meta.setClientRegistrationTypes(federationTypes);
		assertEquals(federationTypes, meta.getClientRegistrationTypes());
		
		String orgName = "Federated Org";
		meta.setOrganizationName(orgName);
		assertEquals(orgName, meta.getOrganizationName());
		
		meta.setCustomParameter("x-custom", "xyz");

		assertEquals(1, meta.getCustomParameters().size());
		assertEquals("xyz", meta.getCustomParameter("x-custom"));

		String json = meta.toJSONObject().toJSONString();

		meta = OIDCProviderMetadata.parse(json);

		assertEquals(issuer.getValue(), meta.getIssuer().getValue());
		assertEquals(SubjectType.PAIRWISE, meta.getSubjectTypes().get(0));
		assertEquals(SubjectType.PUBLIC, meta.getSubjectTypes().get(1));
		assertEquals(jwkSetURI.toString(), meta.getJWKSetURI().toString());

		assertEquals("https://c2id.com/authz", meta.getAuthorizationEndpointURI().toString());
		assertEquals("https://c2id.com/token", meta.getTokenEndpointURI().toString());
		assertEquals("https://c2id.com/userinfo", meta.getUserInfoEndpointURI().toString());
		assertEquals("https://c2id.com/fed", meta.getFederationRegistrationEndpointURI().toString());
		assertEquals("https://c2id.com/reg", meta.getRegistrationEndpointURI().toString());
		assertEquals("https://c2id.com/inspect", meta.getIntrospectionEndpointURI().toString());
		assertEquals("https://c2id.com/revoke", meta.getRevocationEndpointURI().toString());
		assertEquals("https://c2id.com/session", meta.getCheckSessionIframeURI().toString());
		assertEquals("https://c2id.com/logout", meta.getEndSessionEndpointURI().toString());
		assertEquals("https://c2id.com/requests", meta.getRequestObjectEndpoint().toString());
		assertEquals("https://c2id.com/par", meta.getPushedAuthorizationRequestEndpointURI().toString());
		assertEquals("https://c2id.com/device", meta.getDeviceAuthorizationEndpointURI().toString());
		assertEquals("https://c2id.com/ciba", meta.getBackChannelAuthenticationEndpointURI().toString());
		assertEquals("https://c2id.com/ciba", meta.getBackChannelAuthenticationEndpoint().toString());
		
		assertTrue(Scope.parse("openid email profile").containsAll(meta.getScopes()));

		assertEquals(ResponseType.Value.CODE, responseTypes.iterator().next().iterator().next());
		assertEquals(1, responseTypes.size());

		assertTrue(meta.getResponseModes().contains(ResponseMode.QUERY));
		assertTrue(meta.getResponseModes().contains(ResponseMode.FRAGMENT));
		assertEquals(2, meta.getResponseModes().size());

		assertTrue(meta.getGrantTypes().contains(GrantType.AUTHORIZATION_CODE));
		assertTrue(meta.getGrantTypes().contains(GrantType.REFRESH_TOKEN));
		assertEquals(2, meta.getGrantTypes().size());

		assertEquals(codeChallengeMethods, meta.getCodeChallengeMethods());

		assertEquals("1", meta.getACRs().get(0).getValue());

		assertEquals(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC), meta.getTokenEndpointAuthMethods());
		
		assertEquals(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC), meta.getTokenEndpointAuthMethods());
		assertEquals(Arrays.asList(JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512), meta.getTokenEndpointJWSAlgs());
		
		assertEquals(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_POST), meta.getIntrospectionEndpointAuthMethods());
		assertEquals(Collections.singletonList(JWSAlgorithm.HS256), meta.getIntrospectionEndpointJWSAlgs());
		
		assertEquals(Collections.singletonList(ClientAuthenticationMethod.PRIVATE_KEY_JWT), meta.getRevocationEndpointAuthMethods());
		assertEquals(Collections.singletonList(JWSAlgorithm.RS256), meta.getRevocationEndpointJWSAlgs());
		
		assertEquals(new URI("https://c2id.com/requests"), meta.getRequestObjectEndpoint());
		
		assertEquals(JWSAlgorithm.HS256, meta.getRequestObjectJWSAlgs().get(0));

		assertEquals(JWEAlgorithm.A128KW, meta.getRequestObjectJWEAlgs().get(0));

		assertEquals(EncryptionMethod.A128GCM, meta.getRequestObjectJWEEncs().get(0));

		assertEquals(JWSAlgorithm.RS256, meta.getIDTokenJWSAlgs().get(0));

		assertEquals(EncryptionMethod.A128GCM, meta.getIDTokenJWEEncs().get(0));

		assertEquals(JWSAlgorithm.RS256, meta.getUserInfoJWSAlgs().get(0));

		assertEquals(JWEAlgorithm.RSA1_5, meta.getUserInfoJWEAlgs().get(0));

		assertEquals(EncryptionMethod.A128CBC_HS256, meta.getUserInfoJWEEncs().get(0));

		assertEquals(Display.PAGE, meta.getDisplays().get(0));
		assertEquals(Display.POPUP, meta.getDisplays().get(1));
		assertEquals(2, meta.getDisplays().size());

		assertEquals(ClaimType.NORMAL, meta.getClaimTypes().get(0));

		assertEquals("name", meta.getClaims().get(0));
		assertEquals("email", meta.getClaims().get(1));
		assertEquals(2, meta.getClaims().size());

		assertEquals("en-GB", meta.getClaimsLocales().get(0).toString());

		assertEquals("bg-BG", meta.getUILocales().get(0).toString());

		assertEquals("https://c2id.com/docs", meta.getServiceDocsURI().toString());

		assertEquals("https://c2id.com/policy", meta.getPolicyURI().toString());

		assertEquals("https://c2id.com/tos", meta.getTermsOfServiceURI().toString());

		assertTrue(meta.supportsClaimsParam());

		assertTrue(meta.supportsRequestParam());

		assertTrue(meta.supportsRequestURIParam());

		assertTrue(meta.requiresRequestURIRegistration());
		
		assertTrue(meta.supportsAuthorizationResponseIssuerParam());
		
		assertTrue(meta.supportsFrontChannelLogout());
		assertTrue(meta.supportsFrontChannelLogoutSession());
		assertTrue(meta.supportsBackChannelLogout());
		assertTrue(meta.supportsBackChannelLogoutSession());
		
		assertEquals(Arrays.asList(Prompt.Type.LOGIN, Prompt.Type.CREATE), meta.getPromptTypes());
		
		assertEquals("https://c2id.com/ciba", meta.getBackChannelAuthenticationEndpointURI().toString());
		assertEquals(JWSAlgorithm.RS256, meta.getBackChannelAuthenticationRequestJWSAlgs().get(0));
		assertEquals(BackChannelTokenDeliveryMode.PING, meta.getBackChannelTokenDeliveryModes().get(0));
		assertTrue(meta.supportsBackChannelUserCodeParam());
		
		assertTrue(meta.supportsTLSClientCertificateBoundAccessTokens());
		
		assertEquals(authzJWSAlgs, meta.getAuthorizationJWSAlgs());
		assertEquals(authzJWEAlgs, meta.getAuthorizationJWEAlgs());
		assertEquals(authzJWEEncs, meta.getAuthorizationJWEEncs());
		
		assertEquals(federationTypes, meta.getClientRegistrationTypes());
		assertEquals(orgName, meta.getOrganizationName());
		
		assertEquals(1, meta.getCustomParameters().size());
		assertEquals("xyz", meta.getCustomParameter("x-custom"));
	}


	public void testRejectNoneAlgForTokenJWTAuth()
		throws Exception {

		Issuer issuer = new Issuer("https://c2id.com");

		List<SubjectType> subjectTypes = new ArrayList<>();
		subjectTypes.add(SubjectType.PUBLIC);

		URI jwksURI = new URI("https://c2id.com/jwks.json");

		OIDCProviderMetadata meta = new OIDCProviderMetadata(issuer, subjectTypes, jwksURI);

		List<JWSAlgorithm> tokenEndpointJWTAlgs = new ArrayList<>();
		tokenEndpointJWTAlgs.add(new JWSAlgorithm("none"));

		try {
			meta.setTokenEndpointJWSAlgs(tokenEndpointJWTAlgs);

			fail("Failed to raise IllegalArgumentException");

		} catch (IllegalArgumentException e) {
			// ok
		}


		// Simulate JSON object with none token endpoint JWT algs
		JSONObject jsonObject = meta.toJSONObject();

		List<String> stringList = new ArrayList<>();
		stringList.add("none");

		jsonObject.put("token_endpoint_auth_signing_alg_values_supported", stringList);


		try {
			OIDCProviderMetadata.parse(jsonObject.toJSONString());

			fail("Failed to raise ParseException");

		} catch (ParseException e) {
			// ok
		}
	}


	public void testApplyDefaults()
		throws Exception {

		Issuer issuer = new Issuer("https://c2id.com");

		List<SubjectType> subjectTypes = new ArrayList<>();
		subjectTypes.add(SubjectType.PUBLIC);

		URI jwksURI = new URI("https://c2id.com/jwks.json");

		OIDCProviderMetadata meta = new OIDCProviderMetadata(issuer, subjectTypes, jwksURI);

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

		List<ClaimType> claimTypes = meta.getClaimTypes();
		assertTrue(claimTypes.contains(ClaimType.NORMAL));
		assertEquals(1, claimTypes.size());
		
		assertFalse(meta.supportsClaimsParam());
		assertFalse(meta.supportsRequestParam());
		assertTrue(meta.supportsRequestURIParam());
		assertFalse(meta.requiresRequestURIRegistration());
		assertFalse(meta.supportsTLSClientCertificateBoundAccessTokens());
		
		JSONObject jsonObject = meta.toJSONObject();
		
		assertEquals(issuer.getValue(), jsonObject.get("issuer"));
		assertEquals(jwksURI.toString(), jsonObject.get("jwks_uri"));
		assertEquals(Arrays.asList("query","fragment"), JSONObjectUtils.getStringList(jsonObject, "response_modes_supported"));
		assertEquals(Arrays.asList("authorization_code","implicit"), JSONObjectUtils.getStringList(jsonObject, "grant_types_supported"));
		assertEquals(Collections.singletonList("client_secret_basic"), JSONObjectUtils.getStringList(jsonObject, "token_endpoint_auth_methods_supported"));
		assertEquals(Collections.singletonList("public"), JSONObjectUtils.getStringList(jsonObject, "subject_types_supported"));
		assertEquals(Collections.singletonList("normal"), JSONObjectUtils.getStringList(jsonObject, "claim_types_supported"));
		assertTrue(JSONObjectUtils.getBoolean(jsonObject, "request_uri_parameter_supported"));
		assertEquals(8, jsonObject.size());
		
		meta = OIDCProviderMetadata.parse(jsonObject.toJSONString());
		
		assertEquals(issuer, meta.getIssuer());
		
		assertEquals(jwksURI, meta.getJWKSetURI());
		
		responseModes = meta.getResponseModes();
		assertTrue(responseModes.contains(ResponseMode.QUERY));
		assertTrue(responseModes.contains(ResponseMode.FRAGMENT));
		assertEquals(2, responseModes.size());
		
		grantTypes = meta.getGrantTypes();
		assertTrue(grantTypes.contains(GrantType.AUTHORIZATION_CODE));
		assertTrue(grantTypes.contains(GrantType.IMPLICIT));
		assertEquals(2, grantTypes.size());
		
		assertEquals(Collections.singletonList(ClientAuthenticationMethod.CLIENT_SECRET_BASIC), meta.getTokenEndpointAuthMethods());
		
		claimTypes = meta.getClaimTypes();
		assertTrue(claimTypes.contains(ClaimType.NORMAL));
		assertEquals(1, claimTypes.size());
		
		assertFalse(meta.supportsClaimsParam());
		assertFalse(meta.supportsRequestParam());
		assertTrue(meta.supportsRequestURIParam());
		assertFalse(meta.requiresRequestURIRegistration());
		assertFalse(meta.supportsTLSClientCertificateBoundAccessTokens());
	}
	
	
	// request_uri_parameter_supported
	//    OPTIONAL. Boolean value specifying whether the OP supports use of
	//    the request_uri parameter, with true indicating support. If
	//    omitted, the default value is true.
	public void testRequestURIParamSupported_defaultTrue()
		throws ParseException {
		
		OIDCProviderMetadata op = new OIDCProviderMetadata(
			new Issuer("https://c2id.com"),
			Arrays.asList(SubjectType.PUBLIC, SubjectType.PAIRWISE),
			URI.create("https://c2id.com/jwks.json"));
		
		assertTrue(op.supportsRequestURIParam());
		
		op.applyDefaults();
		assertTrue(op.supportsRequestURIParam());
		
		JSONObject jsonObject = op.toJSONObject();
		assertTrue("Always output", JSONObjectUtils.getBoolean(jsonObject, "request_uri_parameter_supported"));
		
		// Remove to test default parsing
		jsonObject.remove("request_uri_parameter_supported");
		op = OIDCProviderMetadata.parse(jsonObject);
		assertTrue(op.supportsRequestURIParam());
	}


	public void testWithCustomParameters()
		throws Exception {

		Issuer issuer = new Issuer("https://c2id.com");

		List<SubjectType> subjectTypes = new ArrayList<>();
		subjectTypes.add(SubjectType.PUBLIC);

		URI jwksURI = new URI("https://c2id.com/jwks.json");

		OIDCProviderMetadata meta = new OIDCProviderMetadata(issuer, subjectTypes, jwksURI);

		meta.applyDefaults();

		assertTrue(meta.getCustomParameters().isEmpty());

		meta.setCustomParameter("token_introspection_endpoint", "https://c2id.com/token/introspect");
		meta.setCustomParameter("token_revocation_endpoint", "https://c2id.com/token/revoke");

		assertEquals("https://c2id.com/token/introspect", meta.getCustomParameter("token_introspection_endpoint"));
		assertEquals("https://c2id.com/token/revoke", meta.getCustomParameter("token_revocation_endpoint"));
		assertEquals(URI.create("https://c2id.com/token/introspect"), meta.getCustomURIParameter("token_introspection_endpoint"));
		assertEquals(URI.create("https://c2id.com/token/revoke"), meta.getCustomURIParameter("token_revocation_endpoint"));

		assertEquals("https://c2id.com/token/introspect", meta.getCustomParameters().get("token_introspection_endpoint"));
		assertEquals("https://c2id.com/token/revoke", meta.getCustomParameters().get("token_revocation_endpoint"));
		assertEquals(2, meta.getCustomParameters().size());

		JSONObject o = meta.toJSONObject();

		meta = OIDCProviderMetadata.parse(o);

		assertEquals("https://c2id.com/token/introspect", meta.getCustomParameter("token_introspection_endpoint"));
		assertEquals("https://c2id.com/token/revoke", meta.getCustomParameter("token_revocation_endpoint"));
		assertEquals(URI.create("https://c2id.com/token/introspect"), meta.getCustomURIParameter("token_introspection_endpoint"));
		assertEquals(URI.create("https://c2id.com/token/revoke"), meta.getCustomURIParameter("token_revocation_endpoint"));

		assertEquals("https://c2id.com/token/introspect", meta.getCustomParameters().get("token_introspection_endpoint"));
		assertEquals("https://c2id.com/token/revoke", meta.getCustomParameters().get("token_revocation_endpoint"));
		assertEquals(2, meta.getCustomParameters().size());
	}
	
	
	public void testParseNullValues()
		throws Exception {
		
		JSONObject jsonObject = new JSONObject();
		
		for (String paramName: OIDCClientMetadata.getRegisteredParameterNames()) {
			jsonObject.put(paramName, null);
		}
		
		// Mandatory
		jsonObject.put("issuer", "https://c2id.com");
		jsonObject.put("subject_types_supported", Arrays.asList("public", "pairwise"));
		jsonObject.put("jwks_uri", "https://c2id.com/jwks.json");
		
		OIDCProviderMetadata.parse(jsonObject);
	}
	
	
	public void testPreserveTokenEndpointJWSAlgsParseOrder()
		throws Exception {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("issuer", "https://c2id.com");
		jsonObject.put("subject_types_supported", Arrays.asList("public", "pairwise"));
		jsonObject.put("jwks_uri", "https://c2id.com/jwks.json");
		jsonObject.put("token_endpoint_auth_signing_alg_values_supported", Arrays.asList("RS256", "PS256", "HS256", "ES256"));
		
		OIDCProviderMetadata opMetadata = OIDCProviderMetadata.parse(jsonObject.toJSONString());
		
		assertEquals(JWSAlgorithm.RS256, opMetadata.getTokenEndpointJWSAlgs().get(0));
		assertEquals(JWSAlgorithm.PS256, opMetadata.getTokenEndpointJWSAlgs().get(1));
		assertEquals(JWSAlgorithm.HS256, opMetadata.getTokenEndpointJWSAlgs().get(2));
		assertEquals(JWSAlgorithm.ES256, opMetadata.getTokenEndpointJWSAlgs().get(3));
		assertEquals(4, opMetadata.getTokenEndpointJWSAlgs().size());
	}
	
	
	// iss 212
	public void testJOSEAlgParse_referenceEquality()
		throws Exception {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("issuer", "https://c2id.com");
		jsonObject.put("subject_types_supported", Arrays.asList("public", "pairwise"));
		jsonObject.put("jwks_uri", "https://c2id.com/jwks.json");
		
		jsonObject.put("token_endpoint_auth_signing_alg_values_supported", Collections.singletonList("RS256"));
		
		jsonObject.put("request_object_signing_alg_values_supported", Collections.singletonList("RS256"));
		jsonObject.put("request_object_encryption_alg_values_supported", Collections.singletonList("RSA-OAEP"));
		jsonObject.put("request_object_encryption_enc_values_supported", Collections.singletonList("A128GCM"));
		
		jsonObject.put("id_token_signing_alg_values_supported", Collections.singletonList("RS256"));
		jsonObject.put("id_token_encryption_alg_values_supported", Collections.singletonList("RSA-OAEP"));
		jsonObject.put("id_token_encryption_enc_values_supported", Collections.singletonList("A128GCM"));
		
		jsonObject.put("userinfo_signing_alg_values_supported", Collections.singletonList("RS256"));
		jsonObject.put("userinfo_encryption_alg_values_supported", Collections.singletonList("RSA-OAEP"));
		jsonObject.put("userinfo_encryption_enc_values_supported", Collections.singletonList("A128GCM"));
		
		OIDCProviderMetadata opMetadata = OIDCProviderMetadata.parse(jsonObject.toJSONString());
		
		assertSame(JWSAlgorithm.RS256, opMetadata.getTokenEndpointJWSAlgs().get(0));
		
		assertSame(JWSAlgorithm.RS256, opMetadata.getRequestObjectJWSAlgs().get(0));
		assertSame(JWEAlgorithm.RSA_OAEP, opMetadata.getRequestObjectJWEAlgs().get(0));
		assertSame(EncryptionMethod.A128GCM, opMetadata.getRequestObjectJWEEncs().get(0));
		
		
		assertSame(JWSAlgorithm.RS256, opMetadata.getIDTokenJWSAlgs().get(0));
		assertSame(JWEAlgorithm.RSA_OAEP, opMetadata.getIDTokenJWEAlgs().get(0));
		assertSame(EncryptionMethod.A128GCM, opMetadata.getIDTokenJWEEncs().get(0));
		
		assertSame(JWSAlgorithm.RS256, opMetadata.getUserInfoJWSAlgs().get(0));
		assertSame(JWEAlgorithm.RSA_OAEP, opMetadata.getUserInfoJWEAlgs().get(0));
		assertSame(EncryptionMethod.A128GCM, opMetadata.getUserInfoJWEEncs().get(0));
	}
	
	
	public void testOutputFrontChannelLogoutSessionSupported()
		throws ParseException {
		
		OIDCProviderMetadata meta = new OIDCProviderMetadata(
			new Issuer("https://c2id.com"),
			Collections.singletonList(SubjectType.PUBLIC),
			URI.create("https://c2id.com/jwks.json"));
		
		meta.applyDefaults();
		
		JSONObject out = meta.toJSONObject();
		assertFalse(JSONObjectUtils.containsKey(out, "frontchannel_logout_supported"));
		assertFalse(JSONObjectUtils.containsKey(out, "frontchannel_logout_session_supported"));
		
		meta.setSupportsFrontChannelLogout(true);
		out = meta.toJSONObject();
		assertTrue(JSONObjectUtils.getBoolean(out, "frontchannel_logout_supported"));
		assertFalse(JSONObjectUtils.getBoolean(out, "frontchannel_logout_session_supported"));
		
		meta.setSupportsFrontChannelLogoutSession(true);
		out = meta.toJSONObject();
		assertTrue(JSONObjectUtils.getBoolean(out, "frontchannel_logout_supported"));
		assertTrue(JSONObjectUtils.getBoolean(out, "frontchannel_logout_session_supported"));
	}
	
	
	public void testOutputBackChannelLogoutSessionSupported()
		throws ParseException {
		
		OIDCProviderMetadata meta = new OIDCProviderMetadata(
			new Issuer("https://c2id.com"),
			Collections.singletonList(SubjectType.PUBLIC),
			URI.create("https://c2id.com/jwks.json"));
		
		meta.applyDefaults();
		
		JSONObject out = meta.toJSONObject();
		assertFalse(JSONObjectUtils.containsKey(out, "backchannel_logout_supported"));
		assertFalse(JSONObjectUtils.containsKey(out, "backchannel_logout_session_supported"));
		
		meta.setSupportsBackChannelLogout(true);
		out = meta.toJSONObject();
		assertTrue(JSONObjectUtils.getBoolean(out, "backchannel_logout_supported"));
		assertFalse(JSONObjectUtils.getBoolean(out, "backchannel_logout_session_supported"));
		
		meta.setSupportsBackChannelLogoutSession(true);
		out = meta.toJSONObject();
		assertTrue(JSONObjectUtils.getBoolean(out, "backchannel_logout_supported"));
		assertTrue(JSONObjectUtils.getBoolean(out, "backchannel_logout_session_supported"));
	}
	
	
	public void testParseDefaultFrontAndBackChannelLogoutSupport()
		throws ParseException {
		
		OIDCProviderMetadata meta = new OIDCProviderMetadata(
			new Issuer("https://c2id.com"),
			Collections.singletonList(SubjectType.PUBLIC),
			URI.create("https://c2id.com/jwks.json"));
		
		meta.applyDefaults();
		
		JSONObject out = meta.toJSONObject();
		
		// default - not set
		assertNull(out.get("frontchannel_logout_supported"));
		assertNull(out.get("frontchannel_logout_session_supported"));
		assertNull(out.get("backchannel_logout_supported"));
		assertNull(out.get("backchannel_logout_session_supported"));
		
		meta = OIDCProviderMetadata.parse(out.toJSONString());
		
		assertFalse(meta.supportsFrontChannelLogout());
		assertFalse(meta.supportsFrontChannelLogoutSession());
		assertFalse(meta.supportsBackChannelLogout());
		assertFalse(meta.supportsBackChannelLogoutSession());
	}
	
	
	public void testParseBasicFrontAndBackChannelLogoutSupport()
		throws ParseException {
		
		OIDCProviderMetadata meta = new OIDCProviderMetadata(
			new Issuer("https://c2id.com"),
			Collections.singletonList(SubjectType.PUBLIC),
			URI.create("https://c2id.com/jwks.json"));
		
		meta.applyDefaults();
		meta.setSupportsFrontChannelLogout(true);
		meta.setSupportsBackChannelLogout(true);
		
		JSONObject out = meta.toJSONObject();
		
		// Optional session supported flag defaults to false
		assertNotNull(out.remove("frontchannel_logout_session_supported"));
		assertNotNull(out.remove("backchannel_logout_session_supported"));
		
		meta = OIDCProviderMetadata.parse(out.toJSONString());
		
		assertTrue(meta.supportsFrontChannelLogout());
		assertFalse(meta.supportsFrontChannelLogoutSession());
		assertTrue(meta.supportsBackChannelLogout());
		assertFalse(meta.supportsBackChannelLogoutSession());
	}
	
	
	public void testOutputTLSClientCertificateBoundAccessTokensSupport()
		throws ParseException {
		
		OIDCProviderMetadata meta = new OIDCProviderMetadata(
			new Issuer("https://c2id.com"),
			Collections.singletonList(SubjectType.PUBLIC),
			URI.create("https://c2id.com/jwks.json"));
		
		meta.applyDefaults();
		
		JSONObject jsonObject = meta.toJSONObject();
		
		assertNull(jsonObject.get("tls_client_certificate_bound_access_tokens"));
		
		assertFalse(OIDCProviderMetadata.parse(jsonObject).supportsTLSClientCertificateBoundAccessTokens());
		
		// default to false
		assertNull(jsonObject.remove("tls_client_certificate_bound_access_tokens"));
		
		assertFalse(OIDCProviderMetadata.parse(jsonObject).supportsTLSClientCertificateBoundAccessTokens());
		
		meta.setSupportsTLSClientCertificateBoundAccessTokens(true);
		
		jsonObject = meta.toJSONObject();
		
		assertTrue((Boolean)jsonObject.get("tls_client_certificate_bound_access_tokens"));
		
		assertTrue(OIDCProviderMetadata.parse(jsonObject).supportsTLSClientCertificateBoundAccessTokens());
	}
	
	
	public void testPAR()
		throws ParseException {
		
		OIDCProviderMetadata metadata = new OIDCProviderMetadata(new Issuer("https://c2id.com"), Collections.singletonList(SubjectType.PUBLIC), URI.create("https://c2id.com/jwks.json"));
		
		assertNull(metadata.getPushedAuthorizationRequestEndpointURI());
		assertFalse(metadata.requiresPushedAuthorizationRequests());
		
		metadata.applyDefaults();
		assertNull(metadata.getPushedAuthorizationRequestEndpointURI());
		assertFalse(metadata.requiresPushedAuthorizationRequests());
		
		URI parEndpoint = URI.create("https://c2id.com/par");
		metadata.setPushedAuthorizationRequestEndpointURI(parEndpoint);
		assertEquals(parEndpoint, metadata.getPushedAuthorizationRequestEndpointURI());
		
		JSONObject jsonObject = metadata.toJSONObject();
		assertEquals(parEndpoint.toString(), jsonObject.get("pushed_authorization_request_endpoint"));
		assertFalse(jsonObject.containsKey("require_pushed_authorization_requests"));
		
		metadata = OIDCProviderMetadata.parse(jsonObject.toJSONString());
		assertEquals(parEndpoint, metadata.getPushedAuthorizationRequestEndpointURI());
		assertFalse(metadata.requiresPushedAuthorizationRequests());
	}
	
	
	public void testPAR_requiredByOP()
		throws ParseException {
		
		OIDCProviderMetadata metadata = new OIDCProviderMetadata(new Issuer("https://c2id.com"), Collections.singletonList(SubjectType.PUBLIC), URI.create("https://c2id.com/jwks.json"));
		metadata.applyDefaults();
		assertNull(metadata.getPushedAuthorizationRequestEndpointURI());
		assertFalse(metadata.requiresPushedAuthorizationRequests());
		
		URI parEndpoint = URI.create("https://c2id.com/par");
		metadata.setPushedAuthorizationRequestEndpointURI(parEndpoint);
		assertEquals(parEndpoint, metadata.getPushedAuthorizationRequestEndpointURI());
		
		metadata.requiresPushedAuthorizationRequests(true);
		assertTrue(metadata.requiresPushedAuthorizationRequests());
		
		JSONObject jsonObject = metadata.toJSONObject();
		assertEquals(parEndpoint.toString(), jsonObject.get("pushed_authorization_request_endpoint"));
		assertTrue((Boolean) jsonObject.get("require_pushed_authorization_requests"));
		
		metadata = OIDCProviderMetadata.parse(jsonObject.toJSONString());
		assertEquals(parEndpoint, metadata.getPushedAuthorizationRequestEndpointURI());
		assertTrue(metadata.requiresPushedAuthorizationRequests());
	}
	
	
	public void testIdentityAssurance_ignoreDocumentRelatedMetadataInJSONOutput()
		throws ParseException {
		
		OIDCProviderMetadata metadata = new OIDCProviderMetadata(new Issuer("https://c2id.com"), Collections.singletonList(SubjectType.PUBLIC), URI.create("https://c2id.com/jwks.json"));
		metadata.setSupportsVerifiedClaims(true);
		metadata.setIdentityTrustFrameworks(Collections.singletonList(IdentityTrustFramework.EIDAS));
		metadata.setIdentityEvidenceTypes(Collections.singletonList(IdentityEvidenceType.ELECTRONIC_SIGNATURE));
		metadata.setVerifiedClaims(Arrays.asList("email", "given_name", "family_name"));
		
		// Must be ignored in JSON output
		metadata.setDocumentTypes(Arrays.asList(DocumentType.IDCARD, DocumentType.PASSPORT));
		metadata.setDocumentMethods(Arrays.asList(IdentityVerificationMethod.EID, IdentityVerificationMethod.PIPP));
		metadata.setDocumentValidationMethods(Arrays.asList(ValidationMethodType.VPIP, ValidationMethodType.DATA));
		metadata.setDocumentVerificationMethods(Arrays.asList(VerificationMethodType.PVR, VerificationMethodType.PVP));
		
		JSONObject jsonObject = metadata.toJSONObject();
		
		List<String> mustNotBePresent = Arrays.asList(
			"documents_supported",
			"documents_methods_supported",
			"documents_validation_methods_supported",
			"documents_verification_methods_supported"
		);
		
		for (String fieldName: mustNotBePresent) {
			assertFalse(jsonObject.containsKey(fieldName));
		}
		
		metadata = OIDCProviderMetadata.parse(jsonObject);
		
		assertTrue(metadata.supportsVerifiedClaims());
		assertEquals(Collections.singletonList(IdentityTrustFramework.EIDAS), metadata.getIdentityTrustFrameworks());
		assertEquals(Collections.singletonList(IdentityEvidenceType.ELECTRONIC_SIGNATURE), metadata.getIdentityEvidenceTypes());
		assertEquals(Arrays.asList("email", "given_name", "family_name"), metadata.getVerifiedClaims());
	}
	
	
	public void testIdentityAssurance()
		throws ParseException {
		
		OIDCProviderMetadata metadata = new OIDCProviderMetadata(new Issuer("https://c2id.com"), Collections.singletonList(SubjectType.PUBLIC), URI.create("https://c2id.com/jwks.json"));
		assertFalse(metadata.supportsVerifiedClaims());
		assertNull(metadata.getIdentityTrustFrameworks());
		assertNull(metadata.getIdentityEvidenceTypes());
		assertNull(metadata.getDocumentTypes());
		assertNull(metadata.getDocumentMethods());
		assertNull(metadata.getDocumentValidationMethods());
		assertNull(metadata.getDocumentVerificationMethods());
		assertNull(metadata.getIdentityDocumentTypes());
		assertNull(metadata.getIdentityVerificationMethods());
		assertNull(metadata.getElectronicRecordTypes());
		assertNull(metadata.getVerifiedClaims());
		assertNull(metadata.getAttachmentTypes());
		assertNull(metadata.getAttachmentDigestAlgs());
		
		List<String> iaMetadataFieldNames = Arrays.asList(
			"verified_claims_supported",
			"trust_frameworks_supported",
			"evidence_supported",
			"documents_supported",
			"documents_methods_supported",
			"documents_validation_methods_supported",
			"documents_verification_methods_supported",
			"id_documents_supported",
			"id_documents_verification_methods_supported",
			"electronic_records_supported",
			"claims_in_verified_claims_supported",
			"attachments_supported",
			"digest_algorithms_supported"
		);
		
		JSONObject jsonObject = metadata.toJSONObject();
		for (String fieldName: iaMetadataFieldNames) {
			assertFalse("Must not be present: " + fieldName, jsonObject.containsKey(fieldName));
		}
		
		metadata.setSupportsVerifiedClaims(true);
		metadata.setIdentityTrustFrameworks(Arrays.asList(IdentityTrustFramework.NIST_800_63A, IdentityTrustFramework.EIDAS));
		metadata.setIdentityEvidenceTypes(Arrays.asList(IdentityEvidenceType.DOCUMENT, IdentityEvidenceType.ID_DOCUMENT, IdentityEvidenceType.ELECTRONIC_SIGNATURE, IdentityEvidenceType.QES));
		metadata.setDocumentTypes(Arrays.asList(DocumentType.IDCARD, DocumentType.PASSPORT));
		metadata.setDocumentMethods(Arrays.asList(IdentityVerificationMethod.EID, IdentityVerificationMethod.PIPP));
		metadata.setDocumentValidationMethods(Arrays.asList(ValidationMethodType.VPIP, ValidationMethodType.DATA));
		metadata.setDocumentVerificationMethods(Arrays.asList(VerificationMethodType.PVR, VerificationMethodType.PVP));
		metadata.setIdentityDocumentTypes(Arrays.asList(IDDocumentType.IDCARD, IDDocumentType.PASSPORT));
		metadata.setIdentityVerificationMethods(Arrays.asList(IdentityVerificationMethod.EID, IdentityVerificationMethod.PIPP));
		metadata.setElectronicRecordTypes(Arrays.asList(ElectronicRecordType.POPULATION_REGISTER, ElectronicRecordType.BANK_ACCOUNT));
		metadata.setVerifiedClaims(Arrays.asList("email", "address"));
		metadata.setAttachmentTypes(Arrays.asList(AttachmentType.EMBEDDED, AttachmentType.EXTERNAL));
		metadata.setAttachmentDigestAlgs(Arrays.asList(HashAlgorithm.SHA_256, HashAlgorithm.SHA_384, HashAlgorithm.SHA_512));
		
		assertTrue(metadata.supportsVerifiedClaims());
		assertEquals(Arrays.asList(IdentityTrustFramework.NIST_800_63A, IdentityTrustFramework.EIDAS), metadata.getIdentityTrustFrameworks());
		assertEquals(Arrays.asList(IdentityEvidenceType.DOCUMENT, IdentityEvidenceType.ID_DOCUMENT, IdentityEvidenceType.ELECTRONIC_SIGNATURE, IdentityEvidenceType.QES), metadata.getIdentityEvidenceTypes());
		assertEquals(Arrays.asList(DocumentType.IDCARD, DocumentType.PASSPORT), metadata.getDocumentTypes());
		assertEquals(Arrays.asList(IdentityVerificationMethod.EID, IdentityVerificationMethod.PIPP), metadata.getDocumentMethods());
		assertEquals(Arrays.asList(ValidationMethodType.VPIP, ValidationMethodType.DATA), metadata.getDocumentValidationMethods());
		assertEquals(Arrays.asList(VerificationMethodType.PVR, VerificationMethodType.PVP), metadata.getDocumentVerificationMethods());
		assertEquals(Arrays.asList(IDDocumentType.IDCARD, IDDocumentType.PASSPORT), metadata.getIdentityDocumentTypes());
		assertEquals(Arrays.asList(IdentityVerificationMethod.EID, IdentityVerificationMethod.PIPP), metadata.getIdentityVerificationMethods());
		assertEquals(Arrays.asList(ElectronicRecordType.POPULATION_REGISTER, ElectronicRecordType.BANK_ACCOUNT), metadata.getElectronicRecordTypes());
		assertEquals(Arrays.asList("email", "address"), metadata.getVerifiedClaims());
		assertEquals(Arrays.asList(AttachmentType.EMBEDDED, AttachmentType.EXTERNAL), metadata.getAttachmentTypes());
		assertEquals(Arrays.asList(HashAlgorithm.SHA_256, HashAlgorithm.SHA_384, HashAlgorithm.SHA_512), metadata.getAttachmentDigestAlgs());
		
		jsonObject = metadata.toJSONObject();
		for (String fieldName: iaMetadataFieldNames) {
			assertTrue("Must be present: " + fieldName, jsonObject.containsKey(fieldName));
		}
		
		assertTrue(JSONObjectUtils.getBoolean(jsonObject, "verified_claims_supported"));
		assertEquals(Arrays.asList("nist_800_63A", "eidas"), jsonObject.get("trust_frameworks_supported"));
		assertEquals(Arrays.asList("document", "id_document", "electronic_signature", "qes"), jsonObject.get("evidence_supported"));
		assertEquals(Arrays.asList("idcard", "passport"), jsonObject.get("documents_supported"));
		assertEquals(Arrays.asList("eid", "pipp"), jsonObject.get("documents_methods_supported"));
		assertEquals(Arrays.asList("vpip", "data"), jsonObject.get("documents_validation_methods_supported"));
		assertEquals(Arrays.asList("pvr", "pvp"), jsonObject.get("documents_verification_methods_supported"));
		assertEquals(Arrays.asList("idcard", "passport"), jsonObject.get("id_documents_supported"));
		assertEquals(Arrays.asList("eid", "pipp"), jsonObject.get("id_documents_verification_methods_supported"));
		assertEquals(Arrays.asList("email", "address"), jsonObject.get("claims_in_verified_claims_supported"));
		assertEquals(Arrays.asList("embedded", "external"), jsonObject.get("attachments_supported"));
		assertEquals(Arrays.asList("sha-256", "sha-384", "sha-512"), jsonObject.get("digest_algorithms_supported"));
		
		metadata = OIDCProviderMetadata.parse(jsonObject.toJSONString());
		
		assertTrue(metadata.supportsVerifiedClaims());
		assertEquals(Arrays.asList(IdentityTrustFramework.NIST_800_63A, IdentityTrustFramework.EIDAS), metadata.getIdentityTrustFrameworks());
		assertEquals(Arrays.asList(IdentityEvidenceType.DOCUMENT, IdentityEvidenceType.ID_DOCUMENT, IdentityEvidenceType.ELECTRONIC_SIGNATURE, IdentityEvidenceType.QES), metadata.getIdentityEvidenceTypes());
		assertEquals(Arrays.asList(DocumentType.IDCARD, DocumentType.PASSPORT), metadata.getDocumentTypes());
		assertEquals(Arrays.asList(IdentityVerificationMethod.EID, IdentityVerificationMethod.PIPP), metadata.getDocumentMethods());
		assertEquals(Arrays.asList(ValidationMethodType.VPIP, ValidationMethodType.DATA), metadata.getDocumentValidationMethods());
		assertEquals(Arrays.asList(VerificationMethodType.PVR, VerificationMethodType.PVP), metadata.getDocumentVerificationMethods());
		assertEquals(Arrays.asList(IDDocumentType.IDCARD, IDDocumentType.PASSPORT), metadata.getIdentityDocumentTypes());
		assertEquals(Arrays.asList(IdentityVerificationMethod.EID, IdentityVerificationMethod.PIPP), metadata.getIdentityVerificationMethods());
		assertEquals(Arrays.asList(ElectronicRecordType.POPULATION_REGISTER, ElectronicRecordType.BANK_ACCOUNT), metadata.getElectronicRecordTypes());
		assertEquals(Arrays.asList("email", "address"), metadata.getVerifiedClaims());
		assertEquals(Arrays.asList(AttachmentType.EMBEDDED, AttachmentType.EXTERNAL), metadata.getAttachmentTypes());
		assertEquals(Arrays.asList(HashAlgorithm.SHA_256, HashAlgorithm.SHA_384, HashAlgorithm.SHA_512), metadata.getAttachmentDigestAlgs());
	}
	
	
	public void testIdentityAssurance_parseExample()
		throws ParseException {
		
		String json = "{" +
			"   \"verified_claims_supported\":true," +
			"   \"trust_frameworks_supported\":[" +
			"     \"nist_800_63A\"" +
			"   ]," +
			"   \"evidence_supported\": [" +
			"      \"document\"," +
			"      \"electronic_record\"," +
			"      \"vouch\"," +
			"      \"electronic_signature\"" +
			"   ]," +
			"   \"documents_supported\": [" +
			"       \"idcard\"," +
			"       \"passport\"," +
			"       \"driving_permit\"" +
			"   ]," +
			"   \"documents_methods_supported\": [" +
			"       \"pipp\"," +
			"       \"sripp\"," +
			"       \"eid\"" +
			"   ]," +
			"   \"electronic_records_supported\": [" +
			"       \"secure_mail\"" +
			"   ]," +
			"   \"claims_in_verified_claims_supported\": [" +
			"      \"given_name\"," +
			"      \"family_name\"," +
			"      \"birthdate\"," +
			"      \"place_of_birth\"," +
			"      \"nationalities\"," +
			"      \"address\"" +
			"   ]," +
			"  \"attachments_supported\": [" +
			"    \"external\"," +
			"    \"embedded\"" +
			"  ]," +
			"  \"digest_algorithms_supported\": [" +
			"    \"sha-256\"" +
			"  ]" +
			"}";
		
		JSONObject jsonObject = JSONObjectUtils.parse(json);
		jsonObject.put("issuer", new Issuer("https://op.example.com").getValue());
		jsonObject.put("subject_types_supported", Arrays.asList(SubjectType.PUBLIC.toString(), SubjectType.PAIRWISE.toString()));
		jsonObject.put("jwks_uri", URI.create("https://op.example.com/jwks.json").toString());
		
		OIDCProviderMetadata metadata = OIDCProviderMetadata.parse(jsonObject);
		
		assertTrue(metadata.supportsVerifiedClaims());
		assertEquals(Collections.singletonList(IdentityTrustFramework.NIST_800_63A), metadata.getIdentityTrustFrameworks());
		assertEquals(
			Arrays.asList(
				IdentityEvidenceType.DOCUMENT,
				IdentityEvidenceType.ELECTRONIC_RECORD,
				IdentityEvidenceType.VOUCH,
				IdentityEvidenceType.ELECTRONIC_SIGNATURE),
			metadata.getIdentityEvidenceTypes());
		assertEquals(
			Arrays.asList(
				DocumentType.IDCARD,
				DocumentType.PASSPORT,
				DocumentType.DRIVING_PERMIT),
			metadata.getDocumentTypes());
		assertEquals(
			Arrays.asList(
				IdentityVerificationMethod.PIPP,
				IdentityVerificationMethod.SRIPP,
				IdentityVerificationMethod.EID),
			metadata.getDocumentMethods());
		assertEquals(Collections.singletonList(new ElectronicRecordType("secure_mail")), metadata.getElectronicRecordTypes());
		assertEquals(Arrays.asList(
				"given_name",
				"family_name",
				"birthdate",
				"place_of_birth",
				"nationalities",
				"address"
			),
			metadata.getVerifiedClaims());
		assertEquals(Arrays.asList(AttachmentType.EXTERNAL, AttachmentType.EMBEDDED), metadata.getAttachmentTypes());
		assertEquals(Collections.singletonList(HashAlgorithm.SHA_256), metadata.getAttachmentDigestAlgs());
	}
	
	public void testIdentityAssurance_parseExample_deprecated()
		throws ParseException {
		
		String json = "{  " +
			"   \"issuer\":\"https://server.example.com\"," +
			"   \"subject_types_supported\":[\"public\", \"pairwise\"]," +
			"   \"jwks_uri\":\"https://server.example.com/jwks.json\"," +
			
			"   \"verified_claims_supported\":true," +
			"   \"trust_frameworks_supported\":[" +
			"     \"nist_800_63A_ial_2\"," +
			"     \"nist_800_63A_ial_3\"" +
			"   ]," +
			"   \"evidence_supported\":[" +
			"      \"id_document\"," +
			"      \"utility_bill\"," +
			"      \"qes\"" +
			"   ]," +
			"   \"id_documents_supported\":[  " +
			"       \"idcard\"," +
			"       \"passport\"," +
			"       \"driving_permit\"" +
			"   ]," +
			"   \"id_documents_verification_methods_supported\":[  " +
			"       \"pipp\"," +
			"       \"sripp\"," +
			"       \"eid\"" +
			"   ]," +
			"   \"claims_in_verified_claims_supported\":[  " +
			"      \"given_name\"," +
			"      \"family_name\"," +
			"      \"birthdate\"," +
			"      \"place_of_birth\"," +
			"      \"nationality\"," +
			"      \"address\"" +
			"   ]" +
			"}";
		
		OIDCProviderMetadata metadata = OIDCProviderMetadata.parse(json);
		
		assertEquals(new Issuer("https://server.example.com"), metadata.getIssuer());
		assertEquals(Arrays.asList(SubjectType.PUBLIC, SubjectType.PAIRWISE), metadata.getSubjectTypes());
		assertEquals(URI.create("https://server.example.com/jwks.json"), metadata.getJWKSetURI());
		
		assertTrue(metadata.supportsVerifiedClaims());
		assertEquals(Arrays.asList(IdentityTrustFramework.NIST_800_63A_IAL_2, IdentityTrustFramework.NIST_800_63A_IAL_3), metadata.getIdentityTrustFrameworks());
		assertEquals(Arrays.asList(IDDocumentType.IDCARD, IDDocumentType.PASSPORT, IDDocumentType.DRIVING_PERMIT), metadata.getIdentityDocumentTypes());
		assertEquals(Arrays.asList(IdentityVerificationMethod.PIPP, IdentityVerificationMethod.SRIPP, IdentityVerificationMethod.EID), metadata.getIdentityVerificationMethods());
		assertEquals(Arrays.asList("given_name", "family_name", "birthdate", "place_of_birth", "nationality", "address"), metadata.getVerifiedClaims());
	}
	
	
	// https://openid.net/specs/openid-connect-federation-1_0.html#rfc.appendix.A.1.8
	// Example fixed by adding missing issuer, jwks_uri
	public void testParseFederationExample()
		throws Exception {
		
		String json = "{" +
			"   \"issuer\":\"https://op.umu.se/openid\"," +
			"   \"signed_jwks_uri\":\"https://op.umu.se/openid/signed_jwks.jose\"," +
			"   \"authorization_endpoint\":\"https://op.umu.se/openid/authorization\"," +
			"   \"client_registration_types_supported\":[" +
			"      \"automatic\"," +
			"      \"explicit\"" +
			"   ]," +
			"   \"grant_types_supported\":[" +
			"      \"authorization_code\"," +
			"      \"implicit\"," +
			"      \"urn:ietf:params:oauth:grant-type:jwt-bearer\"" +
			"   ]," +
			"   \"id_token_signing_alg_values_supported\":[" +
			"      \"ES256\"," +
			"      \"RS256\"" +
			"   ]," +
			"   \"logo_uri\":\"https://www.umu.se/img/umu-logo-left-neg-SE.svg\"," +
			"   \"op_policy_uri\":\"https://www.umu.se/en/legal-information/\"," +
			"   \"response_types_supported\":[" +
			"      \"code\"," +
			"      \"code id_token\"," +
			"      \"token\"" +
			"   ]," +
			"   \"subject_types_supported\":[" +
			"      \"pairwise\"," +
			"      \"public\"" +
			"   ]," +
			"   \"token_endpoint\":\"https://op.umu.se/openid/token\"," +
			"   \"federation_registration_endpoint\":\"https://op.umu.se/openid/fedreg\"," +
			"   \"token_endpoint_auth_methods_supported\":[" +
			"      \"client_secret_post\"," +
			"      \"client_secret_basic\"," +
			"      \"client_secret_jwt\"," +
			"      \"private_key_jwt\"" +
			"   ]," +
			"   \"pushed_authorization_request_endpoint\":\"https://op.umu.se/openid/par\"," +
			"   \"request_authentication_methods_supported\": {" +
			"      \"authorization_endpoint\": [" +
			"          \"request_object\"" +
			"      ]," +
			"      \"pushed_authorization_request_endpoint\": [" +
			"          \"request_object\"," +
			"          \"private_key_jwt\"," +
			"          \"tls_client_auth\"," +
			"          \"self_signed_tls_client_auth\"" +
			"      ]" +
			"  }" +
			"}";
		
		OIDCProviderMetadata meta = OIDCProviderMetadata.parse(json);
		
		assertEquals(new Issuer("https://op.umu.se/openid"), meta.getIssuer());
		
		assertNull(meta.getJWKSetURI());
		assertEquals(URI.create("https://op.umu.se/openid/signed_jwks.jose"), meta.getSignedJWKSetURI());
		assertNull(meta.getJWKSet());
		
		assertEquals(Arrays.asList(ClientRegistrationType.AUTOMATIC, ClientRegistrationType.EXPLICIT), meta.getClientRegistrationTypes());
		
		assertEquals(Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT, GrantType.JWT_BEARER), meta.getGrantTypes());
		
		assertEquals(Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.RS256), meta.getIDTokenJWSAlgs());
		
		assertEquals(URI.create("https://www.umu.se/img/umu-logo-left-neg-SE.svg"), meta.getCustomURIParameter("logo_uri"));
		assertEquals(URI.create("https://www.umu.se/en/legal-information/"), meta.getPolicyURI());
		
		assertEquals(Arrays.asList(ResponseType.CODE, ResponseType.CODE_IDTOKEN, ResponseType.TOKEN), meta.getResponseTypes());
		
		assertEquals(Arrays.asList(SubjectType.PAIRWISE, SubjectType.PUBLIC), meta.getSubjectTypes());
		
		assertEquals(URI.create("https://op.umu.se/openid/token"), meta.getTokenEndpointURI());
		assertEquals(URI.create("https://op.umu.se/openid/fedreg"), meta.getFederationRegistrationEndpointURI());
		assertEquals(URI.create("https://op.umu.se/openid/authorization"), meta.getAuthorizationEndpointURI());
		assertEquals(URI.create("https://op.umu.se/openid/par"), meta.getPushedAuthorizationRequestEndpointURI());
		
		assertEquals(Arrays.asList(
			ClientAuthenticationMethod.CLIENT_SECRET_POST,
			ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
			ClientAuthenticationMethod.CLIENT_SECRET_JWT,
			ClientAuthenticationMethod.PRIVATE_KEY_JWT),
			meta.getTokenEndpointAuthMethods());
		
		assertEquals(
			Collections.singletonList(ClientAuthenticationMethod.REQUEST_OBJECT),
			meta.getClientRegistrationAuthnMethods().get(EndpointName.AUTHORIZATION)
		);
		assertEquals(
			Arrays.asList(ClientAuthenticationMethod.REQUEST_OBJECT, ClientAuthenticationMethod.PRIVATE_KEY_JWT, ClientAuthenticationMethod.TLS_CLIENT_AUTH, ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH),
			meta.getClientRegistrationAuthnMethods().get(EndpointName.PAR)
		);
	}
	
	
	public void testFederationFields_regularConstructor_automaticRegistration() throws Exception {
		
		URI jwksURI = URI.create("https://c2id.com/jwks.json");
		
		OIDCProviderMetadata meta = new OIDCProviderMetadata(
			new Issuer("https://c2id.com"),
			Arrays.asList(SubjectType.PAIRWISE, SubjectType.PUBLIC),
			jwksURI
		);
		
		assertNull(meta.getOrganizationName());
		assertEquals(jwksURI, meta.getJWKSetURI());
		assertNull(meta.getSignedJWKSetURI());
		assertNull(meta.getJWKSet());
		assertNull(meta.getClientRegistrationTypes());
		assertNull(meta.getClientRegistrationAuthnMethods());
		assertNull(meta.getClientRegistrationAuthnJWSAlgs());
		assertNull(meta.getFederationRegistrationEndpointURI());
		
		String orgName = "Connect2id";
		meta.setOrganizationName(orgName);
		assertEquals(orgName, meta.getOrganizationName());
		
		List<ClientRegistrationType> clientRegistrationTypes = Collections.singletonList(ClientRegistrationType.AUTOMATIC);
		meta.setClientRegistrationTypes(clientRegistrationTypes);
		assertEquals(clientRegistrationTypes, meta.getClientRegistrationTypes());
		
		Map<EndpointName,List<ClientAuthenticationMethod>> clientAuthMethods = new HashMap<>();
		clientAuthMethods.put(EndpointName.AUTHORIZATION, Collections.singletonList(ClientAuthenticationMethod.REQUEST_OBJECT));
		clientAuthMethods.put(EndpointName.PAR, Arrays.asList(ClientAuthenticationMethod.PRIVATE_KEY_JWT, ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH));
		meta.setClientRegistrationAuthnMethods(clientAuthMethods);
		assertEquals(clientAuthMethods, meta.getClientRegistrationAuthnMethods());
		
		meta.setClientRegistrationAuthnJWSAlgs(Collections.singletonList(JWSAlgorithm.RS256));
		assertEquals(Collections.singletonList(JWSAlgorithm.RS256), meta.getClientRegistrationAuthnJWSAlgs());
		
		JSONObject jsonObject = meta.toJSONObject();
		
		assertEquals(Collections.singletonList("automatic"), JSONObjectUtils.getStringList(jsonObject, "client_registration_types_supported"));
		
		JSONObject clientAuthMethodsJSONObject = JSONObjectUtils.getJSONObject(jsonObject, "request_authentication_methods_supported");
		assertEquals(Collections.singletonList(ClientAuthenticationMethod.REQUEST_OBJECT.getValue()), JSONObjectUtils.getStringList(clientAuthMethodsJSONObject, "authorization_endpoint"));
		assertEquals(Arrays.asList(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue(), ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH.getValue()), JSONObjectUtils.getStringList(clientAuthMethodsJSONObject, "pushed_authorization_request_endpoint"));
		assertEquals(2, clientAuthMethodsJSONObject.size());
		
		assertEquals(Collections.singletonList(JWSAlgorithm.RS256.getName()), JSONObjectUtils.getStringList(jsonObject, "request_authentication_signing_alg_values_supported"));
		
		assertEquals(orgName, JSONObjectUtils.getString(jsonObject, "organization_name"));
		
		assertEquals(8, jsonObject.size());
		
		String json = jsonObject.toJSONString();
		
		meta = OIDCProviderMetadata.parse(json);
		
		assertEquals(orgName, meta.getOrganizationName());
		assertEquals(jwksURI, meta.getJWKSetURI());
		assertNull(meta.getSignedJWKSetURI());
		assertNull(meta.getJWKSet());
		assertEquals(clientRegistrationTypes, meta.getClientRegistrationTypes());
		assertEquals(clientAuthMethods, meta.getClientRegistrationAuthnMethods());
		assertEquals(Collections.singletonList(JWSAlgorithm.RS256), meta.getClientRegistrationAuthnJWSAlgs());
		assertNull(meta.getFederationRegistrationEndpointURI());
	}
	
	
	public void testFederationFields_regularConstructor_explicitRegistration() throws Exception {
		
		URI jwksURI = URI.create("https://c2id.com/jwks.json");
		
		OIDCProviderMetadata meta = new OIDCProviderMetadata(
			new Issuer("https://c2id.com"),
			Arrays.asList(SubjectType.PAIRWISE, SubjectType.PUBLIC),
			jwksURI
		);
		
		assertNull(meta.getOrganizationName());
		assertEquals(jwksURI, meta.getJWKSetURI());
		assertNull(meta.getSignedJWKSetURI());
		assertNull(meta.getJWKSet());
		assertNull(meta.getClientRegistrationTypes());
		assertNull(meta.getClientRegistrationAuthnMethods());
		assertNull(meta.getClientRegistrationAuthnJWSAlgs());
		assertNull(meta.getFederationRegistrationEndpointURI());
		
		String orgName = "Connect2id";
		meta.setOrganizationName(orgName);
		assertEquals(orgName, meta.getOrganizationName());
		
		meta.setClientRegistrationTypes(Collections.singletonList(ClientRegistrationType.EXPLICIT));
		assertEquals(Collections.singletonList(ClientRegistrationType.EXPLICIT), meta.getClientRegistrationTypes());
		
		URI fedRegURI = URI.create("https://c2id.com/federation-registration");
		meta.setFederationRegistrationEndpointURI(fedRegURI);
		assertEquals(fedRegURI, meta.getFederationRegistrationEndpointURI());
		
		JSONObject jsonObject = meta.toJSONObject();
		
		assertEquals(Collections.singletonList("explicit"), JSONObjectUtils.getStringList(jsonObject, "client_registration_types_supported"));
		
		assertEquals(orgName, JSONObjectUtils.getString(jsonObject, "organization_name"));
		
		assertEquals(fedRegURI, JSONObjectUtils.getURI(jsonObject, "federation_registration_endpoint"));
		
		assertEquals(7, jsonObject.size());
		
		String json = jsonObject.toJSONString();
		
		meta = OIDCProviderMetadata.parse(json);
		
		assertEquals(orgName, meta.getOrganizationName());
		assertEquals(jwksURI, meta.getJWKSetURI());
		assertNull(meta.getSignedJWKSetURI());
		assertNull(meta.getJWKSet());
		assertEquals(Collections.singletonList(ClientRegistrationType.EXPLICIT), meta.getClientRegistrationTypes());
		assertNull(meta.getClientRegistrationAuthnMethods());
		assertNull(meta.getClientRegistrationAuthnJWSAlgs());
		assertEquals(fedRegURI, meta.getFederationRegistrationEndpointURI());
	}
	
	
	public void testFederationFields_federationConstructor_signedJWKSetURI() throws Exception {
		
		URI signedJWKSetURI = URI.create("https://c2id.com/jwks.jwt");
		
		OIDCProviderMetadata meta = new OIDCProviderMetadata(
			new Issuer("https://c2id.com"),
			Arrays.asList(SubjectType.PAIRWISE, SubjectType.PUBLIC),
			Collections.singletonList(ClientRegistrationType.AUTOMATIC),
			null,
			signedJWKSetURI,
			null
		);
		
		assertNull(meta.getOrganizationName());
		assertNull(meta.getJWKSetURI());
		assertEquals(signedJWKSetURI, meta.getSignedJWKSetURI());
		assertNull(meta.getJWKSet());
		assertEquals(Collections.singletonList(ClientRegistrationType.AUTOMATIC), meta.getClientRegistrationTypes());
		assertNull(meta.getClientRegistrationAuthnMethods());
		assertNull(meta.getClientRegistrationAuthnJWSAlgs());
		assertNull(meta.getFederationRegistrationEndpointURI());
		
		String orgName = "Connect2id";
		meta.setOrganizationName(orgName);
		assertEquals(orgName, meta.getOrganizationName());
		
		Map<EndpointName,List<ClientAuthenticationMethod>> clientAuthMethods = new HashMap<>();
		clientAuthMethods.put(EndpointName.AUTHORIZATION, Collections.singletonList(ClientAuthenticationMethod.REQUEST_OBJECT));
		clientAuthMethods.put(EndpointName.PAR, Arrays.asList(ClientAuthenticationMethod.PRIVATE_KEY_JWT, ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH));
		meta.setClientRegistrationAuthnMethods(clientAuthMethods);
		assertEquals(clientAuthMethods, meta.getClientRegistrationAuthnMethods());
		
		meta.setClientRegistrationAuthnJWSAlgs(Collections.singletonList(JWSAlgorithm.RS256));
		assertEquals(Collections.singletonList(JWSAlgorithm.RS256), meta.getClientRegistrationAuthnJWSAlgs());
		
		JSONObject jsonObject = meta.toJSONObject();
		
		assertEquals(Collections.singletonList("automatic"), JSONObjectUtils.getStringList(jsonObject, "client_registration_types_supported"));
		
		JSONObject clientAuthMethodsJSONObject = JSONObjectUtils.getJSONObject(jsonObject, "request_authentication_methods_supported");
		assertEquals(Collections.singletonList(ClientAuthenticationMethod.REQUEST_OBJECT.getValue()), JSONObjectUtils.getStringList(clientAuthMethodsJSONObject, "authorization_endpoint"));
		assertEquals(Arrays.asList(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue(), ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH.getValue()), JSONObjectUtils.getStringList(clientAuthMethodsJSONObject, "pushed_authorization_request_endpoint"));
		assertEquals(2, clientAuthMethodsJSONObject.size());
		
		assertEquals(Collections.singletonList(JWSAlgorithm.RS256.getName()), JSONObjectUtils.getStringList(jsonObject, "request_authentication_signing_alg_values_supported"));
		
		assertEquals(orgName, JSONObjectUtils.getString(jsonObject, "organization_name"));
		
		assertEquals(8, jsonObject.size());
		
		String json = jsonObject.toJSONString();
		
		meta = OIDCProviderMetadata.parse(json);
		
		assertEquals(orgName, meta.getOrganizationName());
		assertNull(meta.getJWKSetURI());
		assertEquals(signedJWKSetURI, meta.getSignedJWKSetURI());
		assertNull(meta.getJWKSet());
		assertEquals(Collections.singletonList(ClientRegistrationType.AUTOMATIC), meta.getClientRegistrationTypes());
		assertEquals(clientAuthMethods, meta.getClientRegistrationAuthnMethods());
		assertEquals(Collections.singletonList(JWSAlgorithm.RS256), meta.getClientRegistrationAuthnJWSAlgs());
		assertNull(meta.getFederationRegistrationEndpointURI());
	}
	
	
	public void testFederationFields_automaticRegistration_omitFederationRegistrationEndpointFromJSONObject() throws Exception {
		
		Issuer issuer = new Issuer("https://c2id.com");
		URI jwkSetURI = URI.create("https://c2id.com/jwks.json");
		
		OIDCProviderMetadata meta = new OIDCProviderMetadata(
			issuer,
			Collections.singletonList(SubjectType.PAIRWISE),
			Collections.singletonList(ClientRegistrationType.AUTOMATIC),
			jwkSetURI,
			null,
			null
		);
		
		assertEquals(Collections.singletonList(ClientRegistrationType.AUTOMATIC), meta.getClientRegistrationTypes());
		
		Map<EndpointName,List<ClientAuthenticationMethod>> clientAuthMethods = new HashMap<>();
		clientAuthMethods.put(EndpointName.AUTHORIZATION, Collections.singletonList(ClientAuthenticationMethod.REQUEST_OBJECT));
		clientAuthMethods.put(EndpointName.PAR, Arrays.asList(ClientAuthenticationMethod.PRIVATE_KEY_JWT, ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH));
		meta.setClientRegistrationAuthnMethods(clientAuthMethods);
		assertEquals(clientAuthMethods, meta.getClientRegistrationAuthnMethods());
		
		meta.setClientRegistrationAuthnJWSAlgs(Collections.singletonList(JWSAlgorithm.RS256));
		assertEquals(Collections.singletonList(JWSAlgorithm.RS256), meta.getClientRegistrationAuthnJWSAlgs());
		
		meta.setFederationRegistrationEndpointURI(URI.create("https://c2id.com/clients/federation")); // to be omitted
		
		JSONObject jsonObject = meta.toJSONObject();
		
		assertEquals(Collections.singletonList("automatic"), JSONObjectUtils.getStringList(jsonObject, "client_registration_types_supported"));
		
		JSONObject clientAuthMethodsJSONObject = JSONObjectUtils.getJSONObject(jsonObject, "request_authentication_methods_supported");
		assertEquals(Collections.singletonList(ClientAuthenticationMethod.REQUEST_OBJECT.getValue()), JSONObjectUtils.getStringList(clientAuthMethodsJSONObject, "authorization_endpoint"));
		assertEquals(Arrays.asList(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue(), ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH.getValue()), JSONObjectUtils.getStringList(clientAuthMethodsJSONObject, "pushed_authorization_request_endpoint"));
		assertEquals(2, clientAuthMethodsJSONObject.size());
		
		assertEquals(Collections.singletonList(JWSAlgorithm.RS256.getName()), JSONObjectUtils.getStringList(jsonObject, "request_authentication_signing_alg_values_supported"));
		
		assertNull(jsonObject.get("federation_registration_endpoint"));
		
		assertEquals(7, jsonObject.size());
	}
	
	
	public void testFederationFields_explicitRegistration_omitAutomaticFieldsFromJSONObject() throws Exception {
		
		Issuer issuer = new Issuer("https://c2id.com");
		URI jwkSetURI = URI.create("https://c2id.com/jwks.json");
		
		OIDCProviderMetadata meta = new OIDCProviderMetadata(
			issuer,
			Collections.singletonList(SubjectType.PAIRWISE),
			Collections.singletonList(ClientRegistrationType.EXPLICIT),
			jwkSetURI,
			null,
			null
		);
		
		assertEquals(Collections.singletonList(ClientRegistrationType.EXPLICIT), meta.getClientRegistrationTypes());
		
		URI fedReg = URI.create("https://c2id.com/clients/federation");
		meta.setFederationRegistrationEndpointURI(fedReg);
		assertEquals(fedReg, meta.getFederationRegistrationEndpointURI());
		
		// To be omitted
		Map<EndpointName,List<ClientAuthenticationMethod>> clientAuthMethods = new HashMap<>();
		clientAuthMethods.put(EndpointName.AUTHORIZATION, Collections.singletonList(ClientAuthenticationMethod.REQUEST_OBJECT));
		clientAuthMethods.put(EndpointName.PAR, Arrays.asList(ClientAuthenticationMethod.PRIVATE_KEY_JWT, ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH));
		meta.setClientRegistrationAuthnMethods(clientAuthMethods);
		assertEquals(clientAuthMethods, meta.getClientRegistrationAuthnMethods());
		
		// Omitted
		meta.setClientRegistrationAuthnJWSAlgs(Collections.singletonList(JWSAlgorithm.RS256));
		assertEquals(Collections.singletonList(JWSAlgorithm.RS256), meta.getClientRegistrationAuthnJWSAlgs());
		
		meta.setFederationRegistrationEndpointURI(URI.create("https://c2id.com/clients/federation"));
		
		JSONObject jsonObject = meta.toJSONObject();
		
		assertNull(jsonObject.get("request_authentication_methods_supported"));
		assertNull(jsonObject.get("request_authentication_signing_alg_values_supported"));
		
		assertEquals(fedReg, JSONObjectUtils.getURI(jsonObject, "federation_registration_endpoint"));
		
		assertEquals(6, jsonObject.size());
	}
	
	
	public void testFederationConstructor_jwkSetURI() throws Exception {
		
		Issuer issuer = new Issuer("https://c2id.com");
		URI jwkSetURI = URI.create("https://c2id.com/jwks.json");
		
		OIDCProviderMetadata meta = new OIDCProviderMetadata(
			issuer,
			Collections.singletonList(SubjectType.PAIRWISE),
			Collections.singletonList(ClientRegistrationType.AUTOMATIC),
			jwkSetURI,
			null,
			null
		);
		
		assertEquals(issuer, meta.getIssuer());
		assertEquals(Collections.singletonList(SubjectType.PAIRWISE), meta.getSubjectTypes());
		assertEquals(Collections.singletonList(ClientRegistrationType.AUTOMATIC), meta.getClientRegistrationTypes());
		assertEquals(jwkSetURI, meta.getJWKSetURI());
		assertNull(meta.getSignedJWKSetURI());
		assertNull(meta.getJWKSet());
		
		meta = OIDCProviderMetadata.parse(meta.toJSONObject().toJSONString());
		
		assertEquals(issuer, meta.getIssuer());
		assertEquals(Collections.singletonList(SubjectType.PAIRWISE), meta.getSubjectTypes());
		assertEquals(Collections.singletonList(ClientRegistrationType.AUTOMATIC), meta.getClientRegistrationTypes());
		assertEquals(jwkSetURI, meta.getJWKSetURI());
		assertNull(meta.getSignedJWKSetURI());
		assertNull(meta.getJWKSet());
	}
	
	
	public void testFederationConstructor_signedJWKSetURI() throws Exception {
		
		Issuer issuer = new Issuer("https://c2id.com");
		URI signedJWKSetURI = URI.create("https://c2id.com/jwks.jwt");
		
		OIDCProviderMetadata meta = new OIDCProviderMetadata(
			issuer,
			Collections.singletonList(SubjectType.PAIRWISE),
			Collections.singletonList(ClientRegistrationType.AUTOMATIC),
			null,
			signedJWKSetURI,
			null
		);
		
		assertEquals(issuer, meta.getIssuer());
		assertEquals(Collections.singletonList(SubjectType.PAIRWISE), meta.getSubjectTypes());
		assertEquals(Collections.singletonList(ClientRegistrationType.AUTOMATIC), meta.getClientRegistrationTypes());
		assertNull(meta.getJWKSetURI());
		assertEquals(signedJWKSetURI, meta.getSignedJWKSetURI());
		assertNull(meta.getJWKSet());
		
		meta = OIDCProviderMetadata.parse(meta.toJSONObject().toJSONString());
		
		assertEquals(issuer, meta.getIssuer());
		assertEquals(Collections.singletonList(SubjectType.PAIRWISE), meta.getSubjectTypes());
		assertEquals(Collections.singletonList(ClientRegistrationType.AUTOMATIC), meta.getClientRegistrationTypes());
		assertNull(meta.getJWKSetURI());
		assertEquals(signedJWKSetURI, meta.getSignedJWKSetURI());
		assertNull(meta.getJWKSet());
	}
	
	
	public void testFederationConstructor_jwkSet() throws Exception {
		
		Issuer issuer = new Issuer("https://c2id.com");
		
		JWKSet jwkSet = new JWKSet(
			new RSAKeyGenerator(2048)
				.keyID("1")
				.generate()
		);
		
		OIDCProviderMetadata meta = new OIDCProviderMetadata(
			issuer,
			Collections.singletonList(SubjectType.PAIRWISE),
			Collections.singletonList(ClientRegistrationType.AUTOMATIC),
			null,
			null,
			jwkSet
		);
		
		assertEquals(issuer, meta.getIssuer());
		assertEquals(Collections.singletonList(SubjectType.PAIRWISE), meta.getSubjectTypes());
		assertEquals(Collections.singletonList(ClientRegistrationType.AUTOMATIC), meta.getClientRegistrationTypes());
		assertNull(meta.getJWKSetURI());
		assertNull(meta.getSignedJWKSetURI());
		assertEquals(jwkSet, meta.getJWKSet());
		
		meta = OIDCProviderMetadata.parse(meta.toJSONObject().toJSONString());
		
		assertEquals(issuer, meta.getIssuer());
		assertEquals(Collections.singletonList(SubjectType.PAIRWISE), meta.getSubjectTypes());
		assertEquals(Collections.singletonList(ClientRegistrationType.AUTOMATIC), meta.getClientRegistrationTypes());
		assertNull(meta.getJWKSetURI());
		assertNull(meta.getSignedJWKSetURI());
		assertEquals(jwkSet.toJSONObject(), meta.getJWKSet().toJSONObject());
	}
	
	
	public void testFederationConstructor_multipleJWKSets() throws JOSEException {
		
		Issuer issuer = new Issuer("https://c2id.com");
		
		URI jwkSetURI = URI.create("https://c2id.com/jwks.json");
		
		URI signedJWKSetURI = URI.create("https://c2id.com/jwks.jwt");
		
		JWKSet jwkSet = new JWKSet(
			new RSAKeyGenerator(2048)
				.keyID("1")
				.generate());
		
		OIDCProviderMetadata metadata = new OIDCProviderMetadata(
			issuer,
			Collections.singletonList(SubjectType.PAIRWISE),
			Collections.singletonList(ClientRegistrationType.AUTOMATIC),
			jwkSetURI,
			signedJWKSetURI,
			jwkSet);
		
		assertEquals(issuer, metadata.getIssuer());
		assertEquals(Collections.singletonList(SubjectType.PAIRWISE), metadata.getSubjectTypes());
		assertEquals(Collections.singletonList(ClientRegistrationType.AUTOMATIC), metadata.getClientRegistrationTypes());
		assertEquals(jwkSetURI, metadata.getJWKSetURI());
		assertEquals(signedJWKSetURI, metadata.getSignedJWKSetURI());
		assertEquals(jwkSet, metadata.getJWKSet());
	}
	
	
	public void testFederationConstructor_nullClientRegTypes() {
		
		Issuer issuer = new Issuer("https://c2id.com");
		URI jwkSetURI = URI.create("https://c2id.com/jwks.json");
		
		try {
			new OIDCProviderMetadata(
				issuer,
				Collections.singletonList(SubjectType.PAIRWISE),
				null,
				jwkSetURI,
				null,
				null
			);
			fail();
		} catch (NullPointerException e) {
			// ok
		}
	}
	
	
	public void testFederationConstructor_emptyClientRegTypes() {
		
		Issuer issuer = new Issuer("https://c2id.com");
		URI jwkSetURI = URI.create("https://c2id.com/jwks.json");
		
		try {
			new OIDCProviderMetadata(
				issuer,
				Collections.singletonList(SubjectType.PAIRWISE),
				Collections.<ClientRegistrationType>emptyList(),
				jwkSetURI,
				null,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("At least one federation client registration type must be specified", e.getMessage());
		}
	}
	
	
	public void testFederationConstructor_noJWKSet() {
		
		Issuer issuer = new Issuer("https://c2id.com");
		
		try {
			new OIDCProviderMetadata(
				issuer,
				Collections.singletonList(SubjectType.PAIRWISE),
				Collections.singletonList(ClientRegistrationType.AUTOMATIC),
				null,
				null,
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("At least one public JWK must be specified", e.getMessage());
		}
	}
	
	
	public void testFederationParse_emptyClientRegTypes() throws JOSEException {
		
		Issuer issuer = new Issuer("https://c2id.com");
		
		JWKSet jwkSet = new JWKSet(
			new RSAKeyGenerator(2048)
				.keyID("1")
				.generate()
		);
		
		OIDCProviderMetadata meta = new OIDCProviderMetadata(
			issuer,
			Collections.singletonList(SubjectType.PAIRWISE),
			Collections.singletonList(ClientRegistrationType.AUTOMATIC),
			null,
			null,
			jwkSet
		);
		
		JSONObject jsonObject = meta.toJSONObject();
		
		jsonObject.put("client_registration_types_supported", new LinkedList<>()); // break
		
		try {
			OIDCProviderMetadata.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("At least one federation client registration type must be specified", e.getMessage());
		}
	}
	
	
	public void testIncrementalAuthz_public_confidential() throws Exception {
		
		Issuer issuer = new Issuer("https://c2id.com");
		
		List<SubjectType> subjectTypes = new LinkedList<>();
		subjectTypes.add(SubjectType.PAIRWISE);
		subjectTypes.add(SubjectType.PUBLIC);
		
		URI jwkSetURI = new URI("https://c2id.com/jwks.json");
		
		OIDCProviderMetadata meta = new OIDCProviderMetadata(issuer, subjectTypes, jwkSetURI);
		meta.applyDefaults();
		
		assertNull(meta.getIncrementalAuthorizationTypes());
		
		meta.setIncrementalAuthorizationTypes(Arrays.asList(ClientType.PUBLIC, ClientType.CONFIDENTIAL));
		
		assertEquals(Arrays.asList(ClientType.PUBLIC, ClientType.CONFIDENTIAL), meta.getIncrementalAuthorizationTypes());
		
		JSONObject jsonObject = meta.toJSONObject();
		assertEquals(Arrays.asList("public", "confidential"), jsonObject.get("incremental_authz_types_supported"));
		
		meta = OIDCProviderMetadata.parse(jsonObject.toJSONString());
		
		assertEquals(Arrays.asList(ClientType.PUBLIC, ClientType.CONFIDENTIAL), meta.getIncrementalAuthorizationTypes());
		
		assertTrue(meta.getCustomParameters().isEmpty());
	}
	
	
	public void testDPoP() throws ParseException {
		
		// init
		OIDCProviderMetadata op = new OIDCProviderMetadata(new Issuer("https://c2id.com"), Collections.singletonList(SubjectType.PUBLIC), URI.create("https://c2id.com/jwks.json"));
		
		assertNull(op.getDPoPJWSAlgs());
		
		op.applyDefaults();
		assertNull(op.getDPoPJWSAlgs());
		
		// null
		op.setDPoPJWSAlgs(null);
		assertNull(op.getDPoPJWSAlgs());
		
		op = OIDCProviderMetadata.parse(op.toJSONObject());
		assertNull(op.getDPoPJWSAlgs());
		
		// empty
		op.setDPoPJWSAlgs(Collections.<JWSAlgorithm>emptyList());
		assertEquals(Collections.emptyList(), op.getDPoPJWSAlgs());
		
		op = OIDCProviderMetadata.parse(op.toJSONObject());
		assertEquals(Collections.emptyList(), op.getDPoPJWSAlgs());
		
		// one JWS alg
		op.setDPoPJWSAlgs(Collections.singletonList(JWSAlgorithm.RS256));
		assertEquals(Collections.singletonList(JWSAlgorithm.RS256), op.getDPoPJWSAlgs());
		
		JSONObject jsonObject = op.toJSONObject();
		assertEquals(Collections.singletonList("RS256"), JSONObjectUtils.getStringList(jsonObject, "dpop_signing_alg_values_supported"));
		
		op = OIDCProviderMetadata.parse(jsonObject);
		assertEquals(Collections.singletonList(JWSAlgorithm.RS256), op.getDPoPJWSAlgs());
		
		// three JWS algs
		op.setDPoPJWSAlgs(Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512));
		
		jsonObject = op.toJSONObject();
		assertEquals(Arrays.asList("ES256", "ES384", "ES512"), JSONObjectUtils.getStringList(jsonObject, "dpop_signing_alg_values_supported"));
		
		op = OIDCProviderMetadata.parse(jsonObject);
		assertEquals(Arrays.asList(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512), op.getDPoPJWSAlgs());
	}
	
	
	public void testPromptValuesSupported() throws ParseException {
		
		OIDCProviderMetadata metadata = new OIDCProviderMetadata(new Issuer("https://c2id.com"), Collections.singletonList(SubjectType.PUBLIC), URI.create("https://c2id.com/jwks.json"));
		metadata.applyDefaults();
		
		assertNull(metadata.getPromptTypes());
		
		List<Prompt.Type> promptTypes = Arrays.asList(Prompt.Type.LOGIN, Prompt.Type.CREATE);
		
		metadata.setPromptTypes(promptTypes);
		
		assertEquals(promptTypes, metadata.getPromptTypes());
		
		JSONObject jsonObject = metadata.toJSONObject();
		
		assertEquals(Arrays.asList("login", "create"), jsonObject.get("prompt_values_supported"));
		
		metadata = OIDCProviderMetadata.parse(jsonObject.toJSONString());
		
		assertEquals(promptTypes, metadata.getPromptTypes());
	}
	
	
	public void testPromptValuesSupport_parseIllegal() {
		
		OIDCProviderMetadata metadata = new OIDCProviderMetadata(new Issuer("https://c2id.com"), Collections.singletonList(SubjectType.PUBLIC), URI.create("https://c2id.com/jwks.json"));
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
}