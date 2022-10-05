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


import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.ciba.BackChannelTokenDeliveryMode;
import com.nimbusds.oauth2.sdk.client.ClientType;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.MapUtils;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.federation.registration.ClientRegistrationType;
import com.nimbusds.openid.connect.sdk.op.EndpointName;


/**
 * OAuth 2.0 Authorisation Server (AS) metadata.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Authorization Server Metadata (RFC 8414)
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (RFC 8705)
 *     <li>OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer
 *         (DPoP) (draft-ietf-oauth-dpop-11)
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM)
 *     <li>OAuth 2.0 Authorization Server Issuer Identification (RFC 9207)
 *     <li>Financial-grade API - Part 2: Read and Write API Security Profile
 *     <li>OAuth 2.0 Pushed Authorization Requests (RFC 9126)
 *     <li>OAuth 2.0 Device Authorization Grant (RFC 8628)
 *     <li>OpenID Connect Client Initiated Backchannel Authentication Flow -
 * 	   Core 1.0
 *     <li>OAuth 2.0 Incremental Authorization
 *         (draft-ietf-oauth-incremental-authz-04)
 *     <li>Initiating User Registration via OpenID Connect (draft 04)
 * </ul>
 */
public class AuthorizationServerMetadata extends AuthorizationServerEndpointMetadata implements ReadOnlyAuthorizationServerMetadata {

	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;

	static {
		Set<String> p = new HashSet<>(AuthorizationServerEndpointMetadata.getRegisteredParameterNames());
		p.add("issuer");
		p.add("jwks_uri");
		p.add("scopes_supported");
		p.add("response_types_supported");
		p.add("response_modes_supported");
		p.add("grant_types_supported");
		p.add("code_challenge_methods_supported");
		p.add("token_endpoint_auth_methods_supported");
		p.add("token_endpoint_auth_signing_alg_values_supported");
		p.add("request_parameter_supported");
		p.add("request_uri_parameter_supported");
		p.add("require_request_uri_registration");
		p.add("request_object_signing_alg_values_supported");
		p.add("request_object_encryption_alg_values_supported");
		p.add("request_object_encryption_enc_values_supported");
		p.add("ui_locales_supported");
		p.add("service_documentation");
		p.add("op_policy_uri");
		p.add("op_tos_uri");
		p.add("introspection_endpoint_auth_methods_supported");
		p.add("introspection_endpoint_auth_signing_alg_values_supported");
		p.add("revocation_endpoint_auth_methods_supported");
		p.add("revocation_endpoint_auth_signing_alg_values_supported");
		p.add("mtls_endpoint_aliases");
		p.add("tls_client_certificate_bound_access_tokens");
		p.add("dpop_signing_alg_values_supported");
		p.add("authorization_signing_alg_values_supported");
		p.add("authorization_encryption_alg_values_supported");
		p.add("authorization_encryption_enc_values_supported");
		p.add("require_pushed_authorization_requests");
		p.add("incremental_authz_types_supported");
		p.add("authorization_response_iss_parameter_supported");
		p.add("backchannel_token_delivery_modes_supported");
		p.add("backchannel_authentication_request_signing_alg_values_supported");
		p.add("backchannel_user_code_parameter_supported");
		p.add("prompt_values_supported");
		p.add("organization_name");
		p.add("jwks");
		p.add("signed_jwks_uri");
		p.add("client_registration_types_supported");
		p.add("request_authentication_methods_supported");
		p.add("request_authentication_signing_alg_values_supported");
		p.add("federation_registration_endpoint");
		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}
	
	
	/**
	 * Gets the registered OpenID Connect provider metadata parameter
	 * names.
	 *
	 * @return The registered OpenID Connect provider metadata parameter
	 *         names, as an unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {
		
		return REGISTERED_PARAMETER_NAMES;
	}
	
	
	/**
	 * The issuer.
	 */
	private final Issuer issuer;
	
	
	/**
	 * The JWK set URI.
	 */
	private URI jwkSetURI;
	
	
	/**
	 * The supported scope values.
	 */
	private Scope scope;
	
	
	/**
	 * The supported response types.
	 */
	private List<ResponseType> rts;
	
	
	/**
	 * The supported response modes.
	 */
	private List<ResponseMode> rms;
	
	
	/**
	 * The supported grant types.
	 */
	private List<GrantType> gts;
	
	
	/**
	 * The supported code challenge methods for PKCE.
	 */
	private List<CodeChallengeMethod> codeChallengeMethods;
	
	
	/**
	 * The supported token endpoint authentication methods.
	 */
	private List<ClientAuthenticationMethod> tokenEndpointAuthMethods;
	
	
	/**
	 * The supported JWS algorithms for the {@code private_key_jwt} and
	 * {@code client_secret_jwt} token endpoint authentication methods.
	 */
	private List<JWSAlgorithm> tokenEndpointJWSAlgs;
	
	
	/**
	 * The supported introspection endpoint authentication methods.
	 */
	private List<ClientAuthenticationMethod> introspectionEndpointAuthMethods;
	
	
	/**
	 * The supported JWS algorithms for the {@code private_key_jwt} and
	 * {@code client_secret_jwt} introspection endpoint authentication
	 * methods.
	 */
	private List<JWSAlgorithm> introspectionEndpointJWSAlgs;
	
	
	/**
	 * The supported revocation endpoint authentication methods.
	 */
	private List<ClientAuthenticationMethod> revocationEndpointAuthMethods;
	
	
	/**
	 * The supported JWS algorithms for the {@code private_key_jwt} and
	 * {@code client_secret_jwt} revocation endpoint authentication
	 * methods.
	 */
	private List<JWSAlgorithm> revocationEndpointJWSAlgs;
	
	
	/**
	 * The supported JWS algorithms for request objects.
	 */
	private List<JWSAlgorithm> requestObjectJWSAlgs;
	
	
	/**
	 * The supported JWE algorithms for request objects.
	 */
	private List<JWEAlgorithm> requestObjectJWEAlgs;
	
	
	/**
	 * The supported encryption methods for request objects.
	 */
	private List<EncryptionMethod> requestObjectJWEEncs;
	
	
	/**
	 * If {@code true} the {@code request} parameter is supported, else
	 * not.
	 */
	private boolean requestParamSupported = false;
	
	
	/**
	 * If {@code true} the {@code request_uri} parameter is supported, else
	 * not.
	 */
	private boolean requestURIParamSupported = false;
	
	
	/**
	 * If {@code true} the {@code request_uri} parameters must be
	 * pre-registered with the provider, else not.
	 */
	private boolean requireRequestURIReg = false;
	
	
	/**
	 * If {@code true} the {@code iss} authorisation response is supported,
	 * else not.
	 */
	private boolean authzResponseIssParameterSupported = false;
	
	
	/**
	 * The supported UI locales.
	 */
	private List<LangTag> uiLocales;
	
	
	/**
	 * The service documentation URI.
	 */
	private URI serviceDocsURI;
	
	
	/**
	 * The provider's policy regarding relying party use of data.
	 */
	private URI policyURI;
	
	
	/**
	 * The provider's terms of service.
	 */
	private URI tosURI;
	
	
	/**
	 * Aliases for endpoints with mutial TLS authentication.
	 */
	private AuthorizationServerEndpointMetadata mtlsEndpointAliases;
	
	
	/**
	 * If {@code true} the
	 * {@code tls_client_certificate_bound_access_tokens} if set, else
	 * not.
	 */
	private boolean tlsClientCertificateBoundAccessTokens = false;
	
	
	/**
	 * The supported JWS algorithms for DPoP.
	 */
	private List<JWSAlgorithm> dPoPJWSAlgs;
	
	
	/**
	 * The supported JWS algorithms for JWT-encoded authorisation
	 * responses.
	 */
	private List<JWSAlgorithm> authzJWSAlgs;
	
	
	/**
	 * The supported JWE algorithms for JWT-encoded authorisation
	 * responses.
	 */
	private List<JWEAlgorithm> authzJWEAlgs;
	
	
	/**
	 * The supported encryption methods for JWT-encoded authorisation
	 * responses.
	 */
	private List<EncryptionMethod> authzJWEEncs;
	
	
	/**
	 * If {@code true} PAR is required, else not.
	 */
	private boolean requirePAR = false;
	
	
	/**
	 * The supported OAuth 2.0 client types for incremental authorisation.
	 */
	private List<ClientType> incrementalAuthzTypes;

	
	/**
	 * The supported CIBA token delivery modes.
	 */
	private List<BackChannelTokenDeliveryMode> backChannelTokenDeliveryModes;
	
	
	/**
	 * The supported JWS algorithms for CIBA requests. If omitted signed
	 * authentication requests are not supported.
	 */
	private List<JWSAlgorithm> backChannelAuthRequestJWSAlgs;

	
	/**
	 * If {@code true} the CIBA {@code user_code} parameter is supported,
	 * else not.
	 */
	private boolean backChannelUserCodeSupported = false;
	
	
	/**
	 * The supported prompt types.
	 */
	private List<Prompt.Type> promptTypes;
	
	
	/**
	 * The organisation name (OpenID Connect Federation 1.0).
	 */
	private String organizationName;
	
	
	/**
	 * The OP JWK set (OpenID Connect Federation 1.0).
	 */
	private JWKSet jwkSet;
	
	
	/**
	 * The signed OP JWK set (OpenID Connect Federation 1.0).
	 */
	private URI signedJWKSetURI;
	
	
	/**
	 * The supported OpenID Connect Federation 1.0 client registration
	 * types.
	 */
	private List<ClientRegistrationType> clientRegistrationTypes;
	
	
	/**
	 * The supported request authentication methods for automatic OpenID
	 * Connect Federation 1.0 client registration.
	 */
	private Map<EndpointName,List<ClientAuthenticationMethod>> clientRegistrationAuthMethods;
	
	
	/**
	 * The supported JWS algorithms for authenticating automatic OpenID
	 * Connect Federation 1.0 client registration requests.
	 */
	private List<JWSAlgorithm> clientRegistrationAuthJWSAlgs;
	
	
	/**
	 * The OpenID Connect Federation 1.0 registration endpoint.
	 */
	private URI federationRegistrationEndpoint;
	
	
	/**
	 * Custom (not-registered) parameters.
	 */
	private final JSONObject customParameters = new JSONObject();
	
	
	/**
	 * Creates a new OAuth 2.0 Authorisation Server (AS) metadata instance.
	 *
	 * @param issuer The issuer identifier. Must be an URI using the https
	 *               scheme with no query or fragment component. Must not
	 *               be {@code null}.
	 */
	public AuthorizationServerMetadata(final Issuer issuer) {
		
		URI uri;
		try {
			uri = new URI(issuer.getValue());
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException("The issuer identifier must be a URI: " + e.getMessage(), e);
		}
		
		if (uri.getRawQuery() != null)
			throw new IllegalArgumentException("The issuer URI must be without a query component");
		
		if (uri.getRawFragment() != null)
			throw new IllegalArgumentException("The issuer URI must be without a fragment component");
		
		this.issuer = issuer;
	}
	
	
	@Override
	public Issuer getIssuer() {
		return issuer;
	}
	
	
	@Override
	public URI getJWKSetURI() {
		return jwkSetURI;
	}
	
	
	/**
	 * Sets the JSON Web Key (JWT) set URI. Corresponds to the
	 * {@code jwks_uri} metadata field.
	 *
	 * @param jwkSetURI The JWK set URI, {@code null} if not specified.
	 */
	public void setJWKSetURI(final URI jwkSetURI) {
		this.jwkSetURI = jwkSetURI;
	}
	
	
	@Override
	public Scope getScopes() {
		return scope;
	}
	
	
	/**
	 * Sets the supported scope values. Corresponds to the
	 * {@code scopes_supported} metadata field.
	 *
	 * @param scope The supported scope values, {@code null} if not
	 *              specified.
	 */
	public void setScopes(final Scope scope) {
		this.scope = scope;
	}
	
	
	@Override
	public List<ResponseType> getResponseTypes() {
		return rts;
	}
	
	
	/**
	 * Sets the supported response type values. Corresponds to the
	 * {@code response_types_supported} metadata field.
	 *
	 * @param rts The supported response type values, {@code null} if not
	 *            specified.
	 */
	public void setResponseTypes(final List<ResponseType> rts) {
		this.rts = rts;
	}
	
	
	@Override
	public List<ResponseMode> getResponseModes() {
		return rms;
	}
	
	
	/**
	 * Sets the supported response mode values. Corresponds to the
	 * {@code response_modes_supported}.
	 *
	 * @param rms The supported response mode values, {@code null} if not
	 *            specified.
	 */
	public void setResponseModes(final List<ResponseMode> rms) {
		this.rms = rms;
	}
	
	
	@Override
	public List<GrantType> getGrantTypes() {
		return gts;
	}
	
	
	/**
	 * Sets the supported OAuth 2.0 grant types. Corresponds to the
	 * {@code grant_types_supported} metadata field.
	 *
	 * @param gts The supported grant types, {@code null} if not specified.
	 */
	public void setGrantTypes(final List<GrantType> gts) {
		this.gts = gts;
	}
	
	
	@Override
	public List<CodeChallengeMethod> getCodeChallengeMethods() {
		return codeChallengeMethods;
	}
	
	
	/**
	 * Gets the supported authorisation code challenge methods for PKCE.
	 * Corresponds to the {@code code_challenge_methods_supported} metadata
	 * field.
	 *
	 * @param codeChallengeMethods The supported code challenge methods,
	 *                             {@code null} if not specified.
	 */
	public void setCodeChallengeMethods(final List<CodeChallengeMethod> codeChallengeMethods) {
		this.codeChallengeMethods = codeChallengeMethods;
	}
	
	
	@Override
	public List<ClientAuthenticationMethod> getTokenEndpointAuthMethods() {
		return tokenEndpointAuthMethods;
	}
	
	
	/**
	 * Sets the supported token endpoint authentication methods.
	 * Corresponds to the {@code token_endpoint_auth_methods_supported}
	 * metadata field.
	 *
	 * @param authMethods The supported token endpoint authentication
	 *                    methods, {@code null} if not specified.
	 */
	public void setTokenEndpointAuthMethods(final List<ClientAuthenticationMethod> authMethods) {
		this.tokenEndpointAuthMethods = authMethods;
	}
	
	
	@Override
	public List<JWSAlgorithm> getTokenEndpointJWSAlgs() {
		return tokenEndpointJWSAlgs;
	}
	
	
	/**
	 * Sets the supported JWS algorithms for the {@code private_key_jwt}
	 * and {@code client_secret_jwt} token endpoint authentication methods.
	 * Corresponds to the
	 * {@code token_endpoint_auth_signing_alg_values_supported} metadata
	 * field.
	 *
	 * @param jwsAlgs The supported JWS algorithms, {@code null} if not
	 *                specified. Must not contain the {@code none}
	 *                algorithm.
	 */
	public void setTokenEndpointJWSAlgs(final List<JWSAlgorithm> jwsAlgs) {
		if (jwsAlgs != null && jwsAlgs.contains(Algorithm.NONE))
			throw new IllegalArgumentException("The \"none\" algorithm is not accepted");
		
		this.tokenEndpointJWSAlgs = jwsAlgs;
	}
	
	
	@Override
	public List<ClientAuthenticationMethod> getIntrospectionEndpointAuthMethods() {
		return introspectionEndpointAuthMethods;
	}
	
	
	/**
	 * Sets the supported introspection endpoint authentication methods.
	 * Corresponds to the
	 * {@code introspection_endpoint_auth_methods_supported} metadata
	 * field.
	 *
	 * @param authMethods The supported introspection endpoint
	 *                    authentication methods, {@code null} if not
	 *                    specified.
	 */
	public void setIntrospectionEndpointAuthMethods(final List<ClientAuthenticationMethod> authMethods) {
		this.introspectionEndpointAuthMethods = authMethods;
	}
	
	
	@Override
	public List<JWSAlgorithm> getIntrospectionEndpointJWSAlgs() {
		return introspectionEndpointJWSAlgs;
	}
	
	
	/**
	 * Sets the supported JWS algorithms for the {@code private_key_jwt}
	 * and {@code client_secret_jwt} introspection endpoint authentication
	 * methods. Corresponds to the
	 * {@code introspection_endpoint_auth_signing_alg_values_supported}
	 * metadata field.
	 *
	 * @param jwsAlgs The supported JWS algorithms, {@code null} if not
	 *                specified. Must not contain the {@code none}
	 *                algorithm.
	 */
	public void setIntrospectionEndpointJWSAlgs(final List<JWSAlgorithm> jwsAlgs) {
		
		if (jwsAlgs != null && jwsAlgs.contains(Algorithm.NONE))
			throw new IllegalArgumentException("The \"none\" algorithm is not accepted");
		
		introspectionEndpointJWSAlgs = jwsAlgs;
	}
	
	
	@Override
	public List<ClientAuthenticationMethod> getRevocationEndpointAuthMethods() {
		return revocationEndpointAuthMethods;
	}
	
	
	/**
	 * Sets the supported revocation endpoint authentication methods.
	 * Corresponds to the
	 * {@code revocation_endpoint_auth_methods_supported} metadata field.
	 *
	 * @param authMethods The supported revocation endpoint authentication
	 *                    methods, {@code null} if not specified.
	 */
	public void setRevocationEndpointAuthMethods(final List<ClientAuthenticationMethod> authMethods) {
		revocationEndpointAuthMethods = authMethods;
	}
	
	
	@Override
	public List<JWSAlgorithm> getRevocationEndpointJWSAlgs() {
		return revocationEndpointJWSAlgs;
	}
	
	
	/**
	 * Sets the supported JWS algorithms for the {@code private_key_jwt}
	 * and {@code client_secret_jwt} revocation endpoint authentication
	 * methods. Corresponds to the
	 * {@code revocation_endpoint_auth_signing_alg_values_supported}
	 * metadata field.
	 *
	 * @param jwsAlgs The supported JWS algorithms, {@code null} if not
	 *                specified. Must not contain the {@code none}
	 *                algorithm.
	 */
	public void setRevocationEndpointJWSAlgs(final List<JWSAlgorithm> jwsAlgs) {
		
		if (jwsAlgs != null && jwsAlgs.contains(Algorithm.NONE))
			throw new IllegalArgumentException("The \"none\" algorithm is not accepted");
		
		revocationEndpointJWSAlgs = jwsAlgs;
	}
	
	
	@Override
	public List<JWSAlgorithm> getRequestObjectJWSAlgs() {
		return requestObjectJWSAlgs;
	}
	
	
	/**
	 * Sets the supported JWS algorithms for request objects. Corresponds
	 * to the {@code request_object_signing_alg_values_supported} metadata
	 * field.
	 *
	 * @param requestObjectJWSAlgs The supported JWS algorithms,
	 *                             {@code null} if not specified.
	 */
	public void setRequestObjectJWSAlgs(final List<JWSAlgorithm> requestObjectJWSAlgs) {
		this.requestObjectJWSAlgs = requestObjectJWSAlgs;
	}
	
	
	@Override
	public List<JWEAlgorithm> getRequestObjectJWEAlgs() {
		return requestObjectJWEAlgs;
	}
	
	
	/**
	 * Sets the supported JWE algorithms for request objects. Corresponds
	 * to the {@code request_object_encryption_alg_values_supported}
	 * metadata field.
	 *
	 * @param requestObjectJWEAlgs The supported JWE algorithms,
	 *                            {@code null} if not specified.
	 */
	public void setRequestObjectJWEAlgs(final List<JWEAlgorithm> requestObjectJWEAlgs) {
		this.requestObjectJWEAlgs = requestObjectJWEAlgs;
	}
	
	
	@Override
	public List<EncryptionMethod> getRequestObjectJWEEncs() {
		return requestObjectJWEEncs;
	}
	
	
	/**
	 * Sets the supported encryption methods for request objects.
	 * Corresponds to the
	 * {@code request_object_encryption_enc_values_supported} metadata
	 * field.
	 *
	 * @param requestObjectJWEEncs The supported encryption methods,
	 *                             {@code null} if not specified.
	 */
	public void setRequestObjectJWEEncs(final List<EncryptionMethod> requestObjectJWEEncs) {
		this.requestObjectJWEEncs = requestObjectJWEEncs;
	}
	
	
	@Override
	public boolean supportsRequestParam() {
		return requestParamSupported;
	}
	
	
	/**
	 * Sets the support for the {@code request} authorisation request
	 * parameter. Corresponds to the {@code request_parameter_supported}
	 * metadata field.
	 *
	 * @param requestParamSupported {@code true} if the {@code reqeust}
	 *                              parameter is supported, else
	 *                              {@code false}.
	 */
	public void setSupportsRequestParam(final boolean requestParamSupported) {
		this.requestParamSupported = requestParamSupported;
	}
	
	
	@Override
	public boolean supportsRequestURIParam() {
		return requestURIParamSupported;
	}
	
	
	/**
	 * Sets the support for the {@code request_uri} authorisation request
	 * parameter. Corresponds to the
	 * {@code request_uri_parameter_supported} metadata field.
	 *
	 * @param requestURIParamSupported {@code true} if the
	 *                                 {@code request_uri} parameter is
	 *                                 supported, else {@code false}.
	 */
	public void setSupportsRequestURIParam(final boolean requestURIParamSupported) {
		this.requestURIParamSupported = requestURIParamSupported;
	}
	
	
	@Override
	public boolean requiresRequestURIRegistration() {
		return requireRequestURIReg;
	}
	
	
	/**
	 * Sets the requirement for the {@code request_uri} parameter
	 * pre-registration. Corresponds to the
	 * {@code require_request_uri_registration} metadata field.
	 *
	 * @param requireRequestURIReg {@code true} if the {@code request_uri}
	 *                             parameter values must be pre-registered,
	 *                             else {@code false}.
	 */
	public void setRequiresRequestURIRegistration(final boolean requireRequestURIReg) {
		this.requireRequestURIReg = requireRequestURIReg;
	}
	
	
	@Override
	public boolean supportsAuthorizationResponseIssuerParam() {
		return authzResponseIssParameterSupported;
	}
	
	
	/**
	 * Sets the support for the {@code iss} authorisation response
	 * parameter. Corresponds to the
	 * {@code authorization_response_iss_parameter_supported} metadata
	 * field.
	 *
	 * @param authzResponseIssParameterSupported {@code true} if the
	 *                                           {@code iss} authorisation
	 *                                           response parameter is
	 *                                           provided, else
	 *                                           {@code false}.
	 */
	public void setSupportsAuthorizationResponseIssuerParam(final boolean authzResponseIssParameterSupported) {
		this.authzResponseIssParameterSupported = authzResponseIssParameterSupported;
	}
	
	
	@Override
	public List<LangTag> getUILocales() {
		return uiLocales;
	}
	
	
	/**
	 * Sets the supported UI locales. Corresponds to the
	 * {@code ui_locales_supported} metadata field.
	 *
	 * @param uiLocales The supported UI locales, {@code null} if not
	 *                  specified.
	 */
	public void setUILocales(final List<LangTag> uiLocales) {
		this.uiLocales = uiLocales;
	}
	
	
	@Override
	public URI getServiceDocsURI() {
		return serviceDocsURI;
	}
	
	
	/**
	 * Sets the service documentation URI. Corresponds to the
	 * {@code service_documentation} metadata field.
	 *
	 * @param serviceDocsURI The service documentation URI, {@code null} if
	 *                       not specified. The URI scheme must be https or
	 *                       http.
	 */
	public void setServiceDocsURI(final URI serviceDocsURI) {
		URIUtils.ensureSchemeIsHTTPSorHTTP(serviceDocsURI);
		this.serviceDocsURI = serviceDocsURI;
	}
	
	
	@Override
	public URI getPolicyURI() {
		return policyURI;
	}
	
	
	/**
	 * Sets the provider's policy regarding relying party use of data.
	 * Corresponds to the {@code op_policy_uri} metadata field.
	 *
	 * @param policyURI The policy URI, {@code null} if not specified. The
	 *                  URI scheme must be https or http.
	 */
	public void setPolicyURI(final URI policyURI) {
		URIUtils.ensureSchemeIsHTTPSorHTTP(policyURI);
		this.policyURI = policyURI;
	}
	
	
	@Override
	public URI getTermsOfServiceURI() {
		return tosURI;
	}
	
	
	/**
	 * Sets the provider's terms of service. Corresponds to the
	 * {@code op_tos_uri} metadata field.
	 *
	 * @param tosURI The terms of service URI, {@code null} if not
	 *               specified. The URI scheme must be https or http.
	 */
	public void setTermsOfServiceURI(final URI tosURI) {
		URIUtils.ensureSchemeIsHTTPSorHTTP(tosURI);
		this.tosURI = tosURI;
	}
	
	
	@Override
	public ReadOnlyAuthorizationServerEndpointMetadata getReadOnlyMtlsEndpointAliases() {
		return getMtlsEndpointAliases();
	}
	
	
	/**
	 * Gets the aliases for communication with mutual TLS. Corresponds to
	 * the {@code mtls_endpoint_aliases} metadata field.
	 *
	 * @return The aliases for communication with mutual TLS, {@code null}
	 *         when no aliases are defined.
	 */
	public AuthorizationServerEndpointMetadata getMtlsEndpointAliases() {
		return mtlsEndpointAliases;
	}
	
	
	/**
	 * Sets the aliases for communication with mutual TLS. Corresponds to the
	 * {@code mtls_endpoint_aliases} metadata field.
	 * 
	 * @param mtlsEndpointAliases The aliases for communication with mutual
	 *                            TLS, or {@code null} when no aliases are
	 *                            defined.
	 */
	public void setMtlsEndpointAliases(AuthorizationServerEndpointMetadata mtlsEndpointAliases) {
		this.mtlsEndpointAliases = mtlsEndpointAliases;
	}
	
	
	@Override
	public boolean supportsTLSClientCertificateBoundAccessTokens() {
		return tlsClientCertificateBoundAccessTokens;
	}
	
	
	/**
	 * Sets the support for TLS client certificate bound access tokens.
	 * Corresponds to the
	 * {@code tls_client_certificate_bound_access_tokens} metadata field.
	 *
	 * @param tlsClientCertBoundTokens {@code true} if TLS client
	 *                                 certificate bound access tokens are
	 *                                 supported, else {@code false}.
	 */
	public void setSupportsTLSClientCertificateBoundAccessTokens(final boolean tlsClientCertBoundTokens) {
		tlsClientCertificateBoundAccessTokens = tlsClientCertBoundTokens;
	}
	
	
	@Override
	@Deprecated
	public boolean supportsMutualTLSSenderConstrainedAccessTokens() {
		return supportsTLSClientCertificateBoundAccessTokens();
	}
	
	
	/**
	 * Sets the support for TLS client certificate bound access tokens.
	 * Corresponds to the
	 * {@code tls_client_certificate_bound_access_tokens} metadata field.
	 *
	 * @param mutualTLSSenderConstrainedAccessTokens {@code true} if TLS
	 *                                               client certificate
	 *                                               bound access tokens
	 *                                               are supported, else
	 *                                               {@code false}.
	 */
	@Deprecated
	public void setSupportsMutualTLSSenderConstrainedAccessTokens(final boolean mutualTLSSenderConstrainedAccessTokens) {
		setSupportsTLSClientCertificateBoundAccessTokens(mutualTLSSenderConstrainedAccessTokens);
	}
	
	
	@Override
	public List<JWSAlgorithm> getDPoPJWSAlgs() {
		return dPoPJWSAlgs;
	}
	
	
	/**
	 * Sets the supported JWS algorithms for Demonstrating
	 * Proof-of-Possession at the Application Layer (DPoP). Corresponds to
	 * the "dpop_signing_alg_values_supported" metadata field.
	 *
	 * @param dPoPJWSAlgs The supported JWS algorithms for DPoP,
	 *                    {@code null} if none.
	 */
	public void setDPoPJWSAlgs(final List<JWSAlgorithm> dPoPJWSAlgs) {
		this.dPoPJWSAlgs = dPoPJWSAlgs;
	}
	
	
	@Override
	public List<JWSAlgorithm> getAuthorizationJWSAlgs() {
		return authzJWSAlgs;
	}
	
	
	/**
	 * Sets the supported JWS algorithms for JWT-encoded authorisation
	 * responses. Corresponds to the
	 * {@code authorization_signing_alg_values_supported} metadata field.
	 *
	 * @param authzJWSAlgs The supported JWS algorithms, {@code null} if
	 *                     not specified.
	 */
	public void setAuthorizationJWSAlgs(final List<JWSAlgorithm> authzJWSAlgs) {
		this.authzJWSAlgs = authzJWSAlgs;
	}
	
	
	@Override
	public List<JWEAlgorithm> getAuthorizationJWEAlgs() {
		return authzJWEAlgs;
	}
	
	
	/**
	 * Sets the supported JWE algorithms for JWT-encoded authorisation
	 * responses. Corresponds to the
	 * {@code authorization_encryption_alg_values_supported} metadata
	 * field.
	 *
	 * @param authzJWEAlgs The supported JWE algorithms, {@code null} if
	 *                     not specified.
	 */
	public void setAuthorizationJWEAlgs(final List<JWEAlgorithm> authzJWEAlgs) {
		this.authzJWEAlgs = authzJWEAlgs;
	}
	
	
	@Override
	public List<EncryptionMethod> getAuthorizationJWEEncs() {
		return authzJWEEncs;
	}
	
	
	/**
	 * Sets the supported encryption methods for JWT-encoded authorisation
	 * responses. Corresponds to the
	 * {@code authorization_encryption_enc_values_supported} metadata
	 * field.
	 *
	 * @param authzJWEEncs The supported encryption methods, {@code null}
	 *                     if not specified.
	 */
	public void setAuthorizationJWEEncs(final List<EncryptionMethod> authzJWEEncs) {
		this.authzJWEEncs = authzJWEEncs;
	}
	
	
	@Override
	public boolean requiresPushedAuthorizationRequests() {
		return requirePAR;
	}
	
	
	/**
	 * Sets the requirement for pushed authorisation requests (PAR).
	 * Corresponds to the {@code pushed_authorization_request_endpoint}
	 * metadata field.
	 *
	 * @param requirePAR {@code true} if PAR is required, else
	 *                   {@code false}.
	 */
	public void requiresPushedAuthorizationRequests(final boolean requirePAR) {
		this.requirePAR = requirePAR;
	}
	
	
	@Override
	public List<ClientType> getIncrementalAuthorizationTypes() {
		return incrementalAuthzTypes;
	}
	
	
	/**
	 * Sets the supported OAuth 2.0 client types for incremental
	 * authorisation. Corresponds to the
	 * {@code incremental_authz_types_supported} metadata field.
	 *
	 * @param incrementalAuthzTypes The supported client types for
	 *                              incremental authorisation, {@code null}
	 *                              if not specified.
	 */
	public void setIncrementalAuthorizationTypes(final List<ClientType> incrementalAuthzTypes) {
		this.incrementalAuthzTypes = incrementalAuthzTypes;
	}
	
	
	@Override
	public List<BackChannelTokenDeliveryMode> getBackChannelTokenDeliveryModes() {
		return backChannelTokenDeliveryModes;
	}
	
	
	/**
	 * Sets the supported CIBA token delivery modes. Corresponds to the
	 * {@code backchannel_token_delivery_modes_supported} metadata field.
	 *
	 * @param backChannelTokenDeliveryModes The CIBA token delivery modes,
	 *                                      {@code null} if not specified.
	 */
	public void setBackChannelTokenDeliveryModes(final List<BackChannelTokenDeliveryMode> backChannelTokenDeliveryModes) {
		this.backChannelTokenDeliveryModes = backChannelTokenDeliveryModes;
	}
	
	@Override
	public List<JWSAlgorithm> getBackChannelAuthenticationRequestJWSAlgs() {
		return backChannelAuthRequestJWSAlgs;
	}
	
	/**
	 * Gets the supported JWS algorithms for CIBA requests. Corresponds to
	 * the {@code backchannel_authentication_request_signing_alg_values_supported}
	 * metadata field.
	 *
	 * @param backChannelAuthRequestJWSAlgs The supported JWS algorithms,
	 *                                      {@code null} if not specified.
	 */
	public void setBackChannelAuthenticationRequestJWSAlgs(final List<JWSAlgorithm> backChannelAuthRequestJWSAlgs) {
		this.backChannelAuthRequestJWSAlgs = backChannelAuthRequestJWSAlgs;
	}
	
	
	@Override
	public boolean supportsBackChannelUserCodeParam() {
		return backChannelUserCodeSupported;
	}
	
	
	/**
	 * Sets the support for the {@code user_code} CIBA request parameter.
	 * Corresponds to the {@code backchannel_user_code_parameter_supported}
	 * metadata field.
	 *
	 * @param backChannelUserCodeSupported {@code true} if the
	 *                                     {@code user_code} parameter is
	 *                                     supported, else {@code false}.
	 */
	public void setSupportsBackChannelUserCodeParam(final boolean backChannelUserCodeSupported) {
		this.backChannelUserCodeSupported = backChannelUserCodeSupported;
	}
	
	
	@Override
	public List<Prompt.Type> getPromptTypes() {
		return promptTypes;
	}
	
	
	/**
	 * Sets the supported {@link Prompt.Type prompt types}. Corresponds to
	 * the {@code prompt_values_supported} metadata field.
	 *
	 * @param promptTypes The supported prompt types, {@code null} if not
	 *                    specified.
	 */
	public void setPromptTypes(final List<Prompt.Type> promptTypes) {
		this.promptTypes = promptTypes;
	}
	
	
	@Override
	public String getOrganizationName() {
		return organizationName;
	}
	
	
	/**
	 * Sets the organisation name (in federation). Corresponds to the
	 * {@code organization_name} metadata field.
	 *
	 * @param organizationName The organisation name, {@code null} if not
	 *                         specified.
	 */
	public void setOrganizationName(final String organizationName) {
		this.organizationName = organizationName;
	}
	
	
	@Override
	public JWKSet getJWKSet() {
		return jwkSet;
	}
	
	
	/**
	 * Sets the JWK set (OpenID Connect Federation 1.0). Corresponds to the
	 * {@code jwks} metadata field.
	 *
	 * @param jwkSet The JWK set, {@code null} if not specified.
	 */
	public void setJWKSet(final JWKSet jwkSet) {
		this.jwkSet = jwkSet;
	}
	
	
	@Override
	public URI getSignedJWKSetURI() {
		return signedJWKSetURI;
	}
	
	
	/**
	 * Sets the signed JWK set URI (OpenID Connect Federation 1.0).
	 * Corresponds to the {@code signed_jwks_uri} metadata field.
	 *
	 * @param signedJWKSetURI The signed JWK set URI, {@code null} if not
	 *                        specified.
	 */
	public void setSignedJWKSetURI(final URI signedJWKSetURI) {
		this.signedJWKSetURI = signedJWKSetURI;
	}
	
	
	@Override
	public List<ClientRegistrationType> getClientRegistrationTypes() {
		return clientRegistrationTypes;
	}
	
	
	/**
	 * Sets the supported federation client registration types. Corresponds
	 * to the {@code client_registration_types_supported} metadata field.
	 *
	 * @param clientRegistrationTypes The supported client registration
	 *                                types, {@code null} if not specified.
	 */
	public void setClientRegistrationTypes(final List<ClientRegistrationType> clientRegistrationTypes) {
		this.clientRegistrationTypes = clientRegistrationTypes;
	}
	
	
	@Override
	public Map<EndpointName, List<ClientAuthenticationMethod>> getClientRegistrationAuthnMethods() {
		return clientRegistrationAuthMethods;
	}
	
	
	/**
	 * Sets the supported request authentication methods for automatic
	 * OpenID Connect Federation 1.0 client registration. Corresponds to
	 * the {@code request_authentication_methods_supported} field.
	 *
	 * @param methods The supported request authentication methods for
	 *                automatic federation client registration,
	 *                {@code null} if not specified.
	 */
	public void setClientRegistrationAuthnMethods(final Map<EndpointName,List<ClientAuthenticationMethod>> methods) {
		clientRegistrationAuthMethods = methods;
	}
	
	
	@Override
	public List<JWSAlgorithm> getClientRegistrationAuthnJWSAlgs() {
		return clientRegistrationAuthJWSAlgs;
	}
	
	
	/**
	 * Sets the supported JWS algorithms for authenticating automatic
	 * OpenID Connect Federation 1.0 client registration requests.
	 * Corresponds to the
	 * {@code request_authentication_signing_alg_values_supported}.
	 *
	 * @param jwsAlgs The supported JWS algorithms, {@code null} if
	 *                       not specified.
	 */
	public void setClientRegistrationAuthnJWSAlgs(final List<JWSAlgorithm> jwsAlgs) {
		clientRegistrationAuthJWSAlgs = jwsAlgs;
	}
	
	
	@Override
	public URI getFederationRegistrationEndpointURI() {
		return federationRegistrationEndpoint;
	}
	
	
	/**
	 * Sets the federation registration endpoint URI. Corresponds to the
	 * {@code federation_registration_endpoint} metadata field.
	 *
	 * @param federationRegistrationEndpoint The federation registration
	 *                                       endpoint URI, {@code null} if
	 *                                       not specified.
	 */
	public void setFederationRegistrationEndpointURI(final URI federationRegistrationEndpoint) {
		this.federationRegistrationEndpoint = federationRegistrationEndpoint;
	}
	
	
	@Override
	public Object getCustomParameter(final String name) {
		
		return customParameters.get(name);
	}
	
	
	@Override
	public URI getCustomURIParameter(final String name) {
		
		try {
			return JSONObjectUtils.getURI(customParameters, name, null);
		} catch (ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Sets the specified custom (not registered) parameter.
	 *
	 * @param name  The parameter name. Must not be {@code null}.
	 * @param value The parameter value, {@code null} if not specified.
	 */
	public void setCustomParameter(final String name, final Object value) {
		
		if (REGISTERED_PARAMETER_NAMES.contains(name)) {
			throw new IllegalArgumentException("The " + name + " parameter is registered");
		}
		
		customParameters.put(name, value);
	}
	
	
	@Override
	public JSONObject getCustomParameters() {
		
		return customParameters;
	}
	
	
	/**
	 * Applies the OAuth 2.0 Authorisation Server metadata defaults where
	 * no values have been specified.
	 *
	 * <ul>
	 *     <li>The response modes default to {@code ["query", "fragment"]}.
	 *     <li>The grant types default to {@code ["authorization_code",
	 *         "implicit"]}.
	 *     <li>The token endpoint authentication methods default to
	 *         {@code ["client_secret_basic"]}.
	 * </ul>
	 */
	public void applyDefaults() {
		
		if (rms == null) {
			rms = new ArrayList<>(2);
			rms.add(ResponseMode.QUERY);
			rms.add(ResponseMode.FRAGMENT);
		}
		
		if (gts == null) {
			gts = new ArrayList<>(2);
			gts.add(GrantType.AUTHORIZATION_CODE);
			gts.add(GrantType.IMPLICIT);
		}
		
		if (tokenEndpointAuthMethods == null) {
			tokenEndpointAuthMethods = new ArrayList<>();
			tokenEndpointAuthMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		}
	}
	
	
	@Override
	public JSONObject toJSONObject() {
		JSONObject o = super.toJSONObject();
		
		// Mandatory fields
		o.put("issuer", issuer.getValue());
		
		
		// Optional fields
		if (jwkSetURI != null)
			o.put("jwks_uri", jwkSetURI.toString());
		
		if (scope != null)
			o.put("scopes_supported", scope.toStringList());
		
		List<String> stringList;
		
		if (rts != null) {
			
			stringList = new ArrayList<>(rts.size());
			
			for (ResponseType rt: rts)
				stringList.add(rt.toString());
			
			o.put("response_types_supported", stringList);
		}
		
		if (rms != null) {
			
			stringList = new ArrayList<>(rms.size());
			
			for (ResponseMode rm: rms)
				stringList.add(rm.getValue());
			
			o.put("response_modes_supported", stringList);
		}
		
		if (gts != null) {
			
			stringList = new ArrayList<>(gts.size());
			
			for (GrantType gt: gts)
				stringList.add(gt.toString());
			
			o.put("grant_types_supported", stringList);
		}
		
		if (codeChallengeMethods != null) {
			
			stringList = new ArrayList<>(codeChallengeMethods.size());
			
			for (CodeChallengeMethod m: codeChallengeMethods)
				stringList.add(m.getValue());
			
			o.put("code_challenge_methods_supported", stringList);
		}
		
		
		if (tokenEndpointAuthMethods != null) {
			
			stringList = new ArrayList<>(tokenEndpointAuthMethods.size());
			
			for (ClientAuthenticationMethod m: tokenEndpointAuthMethods)
				stringList.add(m.getValue());
			
			o.put("token_endpoint_auth_methods_supported", stringList);
		}
		
		if (tokenEndpointJWSAlgs != null) {
			
			stringList = new ArrayList<>(tokenEndpointJWSAlgs.size());
			
			for (JWSAlgorithm alg: tokenEndpointJWSAlgs)
				stringList.add(alg.getName());
			
			o.put("token_endpoint_auth_signing_alg_values_supported", stringList);
		}
		
		if (introspectionEndpointAuthMethods != null) {
			
			stringList = new ArrayList<>(introspectionEndpointAuthMethods.size());
			
			for (ClientAuthenticationMethod m: introspectionEndpointAuthMethods)
				stringList.add(m.getValue());
			
			o.put("introspection_endpoint_auth_methods_supported", stringList);
		}
		
		if (introspectionEndpointJWSAlgs != null) {
			
			stringList = new ArrayList<>(introspectionEndpointJWSAlgs.size());
			
			for (JWSAlgorithm alg: introspectionEndpointJWSAlgs)
				stringList.add(alg.getName());
			
			o.put("introspection_endpoint_auth_signing_alg_values_supported", stringList);
		}
		
		if (revocationEndpointAuthMethods != null) {
			
			stringList = new ArrayList<>(revocationEndpointAuthMethods.size());
			
			for (ClientAuthenticationMethod m: revocationEndpointAuthMethods)
				stringList.add(m.getValue());
			
			o.put("revocation_endpoint_auth_methods_supported", stringList);
		}
		
		if (revocationEndpointJWSAlgs != null) {
			
			stringList = new ArrayList<>(revocationEndpointJWSAlgs.size());
			
			for (JWSAlgorithm alg: revocationEndpointJWSAlgs)
				stringList.add(alg.getName());
			
			o.put("revocation_endpoint_auth_signing_alg_values_supported", stringList);
		}
		
		if (requestObjectJWSAlgs != null) {
			
			stringList = new ArrayList<>(requestObjectJWSAlgs.size());
			
			for (JWSAlgorithm alg: requestObjectJWSAlgs)
				stringList.add(alg.getName());
			
			o.put("request_object_signing_alg_values_supported", stringList);
		}
		
		if (requestObjectJWEAlgs != null) {
			
			stringList = new ArrayList<>(requestObjectJWEAlgs.size());
			
			for (JWEAlgorithm alg: requestObjectJWEAlgs)
				stringList.add(alg.getName());
			
			o.put("request_object_encryption_alg_values_supported", stringList);
		}
		
		if (requestObjectJWEEncs != null) {
			
			stringList = new ArrayList<>(requestObjectJWEEncs.size());
			
			for (EncryptionMethod m: requestObjectJWEEncs)
				stringList.add(m.getName());
			
			o.put("request_object_encryption_enc_values_supported", stringList);
		}
		
		if (uiLocales != null) {
			
			stringList = new ArrayList<>(uiLocales.size());
			
			for (LangTag l: uiLocales)
				stringList.add(l.toString());
			
			o.put("ui_locales_supported", stringList);
		}
		
		if (serviceDocsURI != null)
			o.put("service_documentation", serviceDocsURI.toString());
		
		if (policyURI != null)
			o.put("op_policy_uri", policyURI.toString());
		
		if (tosURI != null)
			o.put("op_tos_uri", tosURI.toString());
		
		if (requestParamSupported) {
			o.put("request_parameter_supported", true);
		}
		
		if (requestURIParamSupported) {
			o.put("request_uri_parameter_supported", true);
		}
		
		if (requireRequestURIReg) {
			o.put("require_request_uri_registration", true);
		}
		
		if (authzResponseIssParameterSupported) {
			o.put("authorization_response_iss_parameter_supported", true);
		}
		
		if (mtlsEndpointAliases != null)
			o.put("mtls_endpoint_aliases", mtlsEndpointAliases.toJSONObject());
		
		if (tlsClientCertificateBoundAccessTokens) {
			o.put("tls_client_certificate_bound_access_tokens", true);
		}
		
		// DPoP
		if (dPoPJWSAlgs != null) {
			
			stringList = new ArrayList<>(dPoPJWSAlgs.size());
			
			for (JWSAlgorithm alg: dPoPJWSAlgs)
				stringList.add(alg.getName());
			
			o.put("dpop_signing_alg_values_supported", stringList);
		}
		
		// JARM
		if (authzJWSAlgs != null) {
			
			stringList = new ArrayList<>(authzJWSAlgs.size());
			
			for (JWSAlgorithm alg: authzJWSAlgs)
				stringList.add(alg.getName());
			
			o.put("authorization_signing_alg_values_supported", stringList);
		}
		
		if (authzJWEAlgs != null) {
			
			stringList = new ArrayList<>(authzJWEAlgs.size());
			
			for (JWEAlgorithm alg: authzJWEAlgs)
				stringList.add(alg.getName());
			
			o.put("authorization_encryption_alg_values_supported", stringList);
		}
		
		if (authzJWEEncs != null) {
			
			stringList = new ArrayList<>(authzJWEEncs.size());
			
			for (EncryptionMethod m: authzJWEEncs)
				stringList.add(m.getName());
			
			o.put("authorization_encryption_enc_values_supported", stringList);
		}
		
		// PAR
		if (requirePAR) {
			o.put("require_pushed_authorization_requests", true);
		}
		
		// Incremental authz
		if (CollectionUtils.isNotEmpty(incrementalAuthzTypes)) {
			stringList = new ArrayList<>(incrementalAuthzTypes.size());
			for (ClientType clientType: incrementalAuthzTypes) {
				if (clientType != null) {
					stringList.add(clientType.name().toLowerCase());
				}
			}
			o.put("incremental_authz_types_supported", stringList);
		}
		
		// CIBA
		if (backChannelTokenDeliveryModes != null) {
			
			stringList = new ArrayList<>(backChannelTokenDeliveryModes.size());
			
			for (BackChannelTokenDeliveryMode mode: backChannelTokenDeliveryModes) {
				if (mode != null) {
					stringList.add(mode.getValue());
				}
			}
			
			o.put("backchannel_token_delivery_modes_supported", stringList);
		}
		
		if (backChannelAuthRequestJWSAlgs != null) {
			
			stringList = new ArrayList<>(backChannelAuthRequestJWSAlgs.size());
			
			for (JWSAlgorithm alg : backChannelAuthRequestJWSAlgs) {
				if (alg != null) {
					stringList.add(alg.getName());
				}
			}
			
			o.put("backchannel_authentication_request_signing_alg_values_supported", stringList);
		}
		
		if (backChannelUserCodeSupported) {
			o.put("backchannel_user_code_parameter_supported", true);
		}
		
		
		// Prompt=create
		if (promptTypes != null) {
			stringList = new ArrayList<>(promptTypes.size());
			for (Prompt.Type type: promptTypes) {
				stringList.add(type.toString());
			}
			o.put("prompt_values_supported", stringList);
		}
		
		// OIDC Federation 1.0
		
		if (organizationName != null) {
			o.put("organization_name", organizationName);
		}
		
		if (CollectionUtils.isNotEmpty(clientRegistrationTypes)) {
			
			o.put("client_registration_types_supported", Identifier.toStringList(clientRegistrationTypes));
			
			if (jwkSet != null) {
				o.put("jwks", JSONObjectUtils.toJSONObject(jwkSet.toPublicJWKSet())); // prevent private keys from leaking
			} else if (signedJWKSetURI != null) {
				o.put("signed_jwks_uri", signedJWKSetURI.toString());
			}
			
			if (clientRegistrationTypes.contains(ClientRegistrationType.AUTOMATIC) && MapUtils.isNotEmpty(clientRegistrationAuthMethods)) {
				JSONObject map = new JSONObject();
				for (Map.Entry<EndpointName,List<ClientAuthenticationMethod>> en: getClientRegistrationAuthnMethods().entrySet()) {
					List<String> methodNames = new LinkedList<>();
					for (ClientAuthenticationMethod method: en.getValue()) {
						methodNames.add(method.getValue());
					}
					map.put(en.getKey().getValue(), methodNames);
				}
				o.put("request_authentication_methods_supported", map);
			}
			
			if (clientRegistrationTypes.contains(ClientRegistrationType.AUTOMATIC) && CollectionUtils.isNotEmpty(clientRegistrationAuthJWSAlgs)) {
				
				stringList = new ArrayList<>(clientRegistrationAuthJWSAlgs.size());
				
				for (JWSAlgorithm alg: clientRegistrationAuthJWSAlgs)
					stringList.add(alg.getName());
				
				o.put("request_authentication_signing_alg_values_supported", stringList);
			}
			
			if (clientRegistrationTypes.contains(ClientRegistrationType.EXPLICIT) && federationRegistrationEndpoint != null) {
				o.put("federation_registration_endpoint", federationRegistrationEndpoint.toString());
			} else {
				o.remove("federation_registration_endpoint");
			}
		}

		// Append any custom (not registered) parameters
		o.putAll(customParameters);
		
		return o;
	}
	
	
	/**
	 * Parses an OAuth 2.0 Authorisation Server metadata from the specified
	 * JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The OAuth 2.0 Authorisation Server metadata.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OAuth 2.0 Authorisation Server metadata.
	 */
	public static AuthorizationServerMetadata parse(final JSONObject jsonObject)
		throws ParseException {
		
		// Parse issuer and subject_types_supported first
		
		Issuer issuer = new Issuer(JSONObjectUtils.getURI(jsonObject, "issuer").toString());

		AuthorizationServerEndpointMetadata asEndpoints = AuthorizationServerEndpointMetadata.parse(jsonObject);
		
		AuthorizationServerMetadata as;
		
		try {
			as = new AuthorizationServerMetadata(issuer); // validates issuer syntax
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage(), e);
		}
		
		// Endpoints
		as.setAuthorizationEndpointURI(asEndpoints.getAuthorizationEndpointURI());
		as.setTokenEndpointURI(asEndpoints.getTokenEndpointURI());
		as.setRegistrationEndpointURI(asEndpoints.getRegistrationEndpointURI());
		as.setIntrospectionEndpointURI(asEndpoints.getIntrospectionEndpointURI());
		as.setRevocationEndpointURI(asEndpoints.getRevocationEndpointURI());
		as.setRequestObjectEndpoint(asEndpoints.getRequestObjectEndpoint());
		as.setPushedAuthorizationRequestEndpointURI(asEndpoints.getPushedAuthorizationRequestEndpointURI());
		as.setDeviceAuthorizationEndpointURI(asEndpoints.getDeviceAuthorizationEndpointURI());
		as.setBackChannelAuthenticationEndpointURI(asEndpoints.getBackChannelAuthenticationEndpointURI());
		as.jwkSetURI = JSONObjectUtils.getURI(jsonObject, "jwks_uri", null);
		
		// AS capabilities
		if (jsonObject.get("scopes_supported") != null) {
			
			as.scope = new Scope();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "scopes_supported")) {
				
				if (v != null)
					as.scope.add(new Scope.Value(v));
			}
		}
		
		if (jsonObject.get("response_types_supported") != null) {
			
			as.rts = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "response_types_supported")) {
				
				if (v != null)
					as.rts.add(ResponseType.parse(v));
			}
		}
		
		if (jsonObject.get("response_modes_supported") != null) {
			
			as.rms = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "response_modes_supported")) {
				
				if (v != null)
					as.rms.add(new ResponseMode(v));
			}
		}
		
		if (jsonObject.get("grant_types_supported") != null) {
			
			as.gts = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "grant_types_supported")) {
				
				if (v != null)
					as.gts.add(GrantType.parse(v));
			}
		}
		
		if (jsonObject.get("code_challenge_methods_supported") != null) {
			
			as.codeChallengeMethods = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "code_challenge_methods_supported")) {
				
				if (v != null)
					as.codeChallengeMethods.add(CodeChallengeMethod.parse(v));
			}
		}
		
		if (jsonObject.get("token_endpoint_auth_methods_supported") != null) {
			
			as.tokenEndpointAuthMethods = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "token_endpoint_auth_methods_supported")) {
				
				if (v != null)
					as.tokenEndpointAuthMethods.add(ClientAuthenticationMethod.parse(v));
			}
		}
		
		if (jsonObject.get("token_endpoint_auth_signing_alg_values_supported") != null) {
			
			as.tokenEndpointJWSAlgs = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "token_endpoint_auth_signing_alg_values_supported")) {
				
				if (v != null && v.equals(Algorithm.NONE.getName()))
					throw new ParseException("The none algorithm is not accepted");
				
				if (v != null)
					as.tokenEndpointJWSAlgs.add(JWSAlgorithm.parse(v));
			}
		}
		
		if (jsonObject.get("introspection_endpoint_auth_methods_supported") != null) {
			
			as.introspectionEndpointAuthMethods = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "introspection_endpoint_auth_methods_supported")) {
				
				if (v != null)
					as.introspectionEndpointAuthMethods.add(ClientAuthenticationMethod.parse(v));
			}
		}
		
		if (jsonObject.get("introspection_endpoint_auth_signing_alg_values_supported") != null) {
			
			as.introspectionEndpointJWSAlgs = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "introspection_endpoint_auth_signing_alg_values_supported")) {
				
				if (v != null && v.equals(Algorithm.NONE.getName()))
					throw new ParseException("The none algorithm is not accepted");
				
				if (v != null)
					as.introspectionEndpointJWSAlgs.add(JWSAlgorithm.parse(v));
			}
		}
		
		if (jsonObject.get("revocation_endpoint_auth_methods_supported") != null) {
			
			as.revocationEndpointAuthMethods = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "revocation_endpoint_auth_methods_supported")) {
				
				if (v != null)
					as.revocationEndpointAuthMethods.add(ClientAuthenticationMethod.parse(v));
			}
		}
		
		if (jsonObject.get("revocation_endpoint_auth_signing_alg_values_supported") != null) {
			
			as.revocationEndpointJWSAlgs = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "revocation_endpoint_auth_signing_alg_values_supported")) {
				
				if (v != null && v.equals(Algorithm.NONE.getName()))
					throw new ParseException("The none algorithm is not accepted");
				
				if (v != null)
					as.revocationEndpointJWSAlgs.add(JWSAlgorithm.parse(v));
			}
		}
		
		
		// Request object
		if (jsonObject.get("request_object_signing_alg_values_supported") != null) {
			
			as.requestObjectJWSAlgs = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "request_object_signing_alg_values_supported")) {
				
				if (v != null)
					as.requestObjectJWSAlgs.add(JWSAlgorithm.parse(v));
			}
		}
		
		
		if (jsonObject.get("request_object_encryption_alg_values_supported") != null) {
			
			as.requestObjectJWEAlgs = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "request_object_encryption_alg_values_supported")) {
				
				if (v != null)
					as.requestObjectJWEAlgs.add(JWEAlgorithm.parse(v));
			}
		}
		
		
		if (jsonObject.get("request_object_encryption_enc_values_supported") != null) {
			
			as.requestObjectJWEEncs = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "request_object_encryption_enc_values_supported")) {
				
				if (v != null)
					as.requestObjectJWEEncs.add(EncryptionMethod.parse(v));
			}
		}
		
		
		// Misc
		
		if (jsonObject.get("ui_locales_supported") != null) {
			
			as.uiLocales = new ArrayList<>();
			
			for (String v : JSONObjectUtils.getStringArray(jsonObject, "ui_locales_supported")) {
				
				if (v != null) {
					
					try {
						as.uiLocales.add(LangTag.parse(v));
						
					} catch (LangTagException e) {
						
						throw new ParseException("Invalid ui_locales_supported field: " + e.getMessage(), e);
					}
				}
			}
		}
		
		if (jsonObject.get("service_documentation") != null) {
			try {
				as.setServiceDocsURI(JSONObjectUtils.getURI(jsonObject, "service_documentation"));
			} catch (IllegalArgumentException e) {
				throw new ParseException("Illegal service_documentation parameter: " + e.getMessage());
			}
		}
		
		if (jsonObject.get("op_policy_uri") != null) {
			try {
				as.setPolicyURI(JSONObjectUtils.getURI(jsonObject, "op_policy_uri"));
			} catch (IllegalArgumentException e) {
				throw new ParseException("Illegal op_policy_uri parameter: " + e.getMessage());
			}
		}
		
		if (jsonObject.get("op_tos_uri") != null) {
			try {
				as.setTermsOfServiceURI(JSONObjectUtils.getURI(jsonObject, "op_tos_uri"));
			} catch (IllegalArgumentException e) {
				throw new ParseException("Illegal op_tos_uri parameter: " + e.getMessage());
			}
		}
		
		if (jsonObject.get("request_parameter_supported") != null)
			as.requestParamSupported = JSONObjectUtils.getBoolean(jsonObject, "request_parameter_supported");
		
		if (jsonObject.get("request_uri_parameter_supported") != null)
			as.requestURIParamSupported = JSONObjectUtils.getBoolean(jsonObject, "request_uri_parameter_supported");
		
		if (jsonObject.get("require_request_uri_registration") != null)
			as.requireRequestURIReg = JSONObjectUtils.getBoolean(jsonObject, "require_request_uri_registration");
		
		if (jsonObject.get("authorization_response_iss_parameter_supported") != null)
			as.authzResponseIssParameterSupported = JSONObjectUtils.getBoolean(jsonObject, "authorization_response_iss_parameter_supported");
		
		if (jsonObject.get("mtls_endpoint_aliases") != null)
			as.mtlsEndpointAliases = AuthorizationServerEndpointMetadata.parse(JSONObjectUtils.getJSONObject(jsonObject, "mtls_endpoint_aliases"));
		
		if (jsonObject.get("tls_client_certificate_bound_access_tokens") != null)
			as.tlsClientCertificateBoundAccessTokens = JSONObjectUtils.getBoolean(jsonObject, "tls_client_certificate_bound_access_tokens");
		
		// DPoP
		if (jsonObject.get("dpop_signing_alg_values_supported") != null)  {
			
			as.dPoPJWSAlgs = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "dpop_signing_alg_values_supported")) {
				
				if (v != null)
					as.dPoPJWSAlgs.add(JWSAlgorithm.parse(v));
			}
		}
		
		// JARM
		if (jsonObject.get("authorization_signing_alg_values_supported") != null) {
			
			as.authzJWSAlgs = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "authorization_signing_alg_values_supported")) {
				
				if (v != null)
					as.authzJWSAlgs.add(JWSAlgorithm.parse(v));
			}
		}
		
		
		if (jsonObject.get("authorization_encryption_alg_values_supported") != null) {
			
			as.authzJWEAlgs = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "authorization_encryption_alg_values_supported")) {
				
				if (v != null)
					as.authzJWEAlgs.add(JWEAlgorithm.parse(v));
			}
		}
		
		
		if (jsonObject.get("authorization_encryption_enc_values_supported") != null) {
			
			as.authzJWEEncs = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "authorization_encryption_enc_values_supported")) {
				
				if (v != null)
					as.authzJWEEncs.add(EncryptionMethod.parse(v));
			}
		}
		
		// PAR
		if (jsonObject.get("require_pushed_authorization_requests") != null) {
			as.requiresPushedAuthorizationRequests(JSONObjectUtils.getBoolean(jsonObject, "require_pushed_authorization_requests"));
		}
		
		// Incremental authz
		if (jsonObject.get("incremental_authz_types_supported") != null) {
			
			as.incrementalAuthzTypes = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "incremental_authz_types_supported")) {
				
				if (v != null) {
					ClientType clientType;
					try {
						clientType = ClientType.valueOf(v.toUpperCase());
					} catch (IllegalArgumentException e) {
						throw new ParseException("Illegal client type in incremental_authz_types_supported field: " + v);
					}
					as.incrementalAuthzTypes.add(clientType);
				}
			}
		}
		
		// CIBA
		if (jsonObject.get("backchannel_token_delivery_modes_supported") != null) {
			
			as.backChannelTokenDeliveryModes = new ArrayList<>();

			for (String v : JSONObjectUtils.getStringArray(jsonObject, "backchannel_token_delivery_modes_supported")) {

				if (v != null)
					as.backChannelTokenDeliveryModes.add(BackChannelTokenDeliveryMode.parse(v));
			}
		}

		if (jsonObject.get("backchannel_authentication_request_signing_alg_values_supported") != null) {
			
			as.backChannelAuthRequestJWSAlgs = new ArrayList<>();

			for (String v : JSONObjectUtils.getStringArray(jsonObject, "backchannel_authentication_request_signing_alg_values_supported")) {

				if (v != null)
					as.backChannelAuthRequestJWSAlgs.add(JWSAlgorithm.parse(v));
			}
		}
		
		if (jsonObject.get("backchannel_user_code_parameter_supported") != null) {
			as.backChannelUserCodeSupported = JSONObjectUtils.getBoolean(jsonObject, "backchannel_user_code_parameter_supported");
		}
		
		// prompt=create
		if (jsonObject.get("prompt_values_supported") != null) {
			
			as.promptTypes = new ArrayList<>();
			for (String v: JSONObjectUtils.getStringList(jsonObject, "prompt_values_supported")) {
				
				if (v != null)
					as.promptTypes.add(Prompt.Type.parse(v));
			}
		}
		
		// OIDC Federation 1.0
		if (jsonObject.get("client_registration_types_supported") != null) {
			
			as.clientRegistrationTypes = new LinkedList<>();
			for (String v : JSONObjectUtils.getStringList(jsonObject, "client_registration_types_supported")) {
				as.clientRegistrationTypes.add(new ClientRegistrationType(v));
			}
			
			if (jsonObject.get("jwks") != null) {
				try {
					as.jwkSet = JWKSet.parse(JSONObjectUtils.getJSONObject(jsonObject, "jwks"));
				} catch (java.text.ParseException e) {
					throw new ParseException(e.getMessage(), e);
				}
			}
			
			as.signedJWKSetURI = JSONObjectUtils.getURI(jsonObject, "signed_jwks_uri", null);
			
			if (jsonObject.get("request_authentication_methods_supported") != null) {
				Map<EndpointName, List<ClientAuthenticationMethod>> requestAuthMethods = new HashMap<>();
				JSONObject spec = JSONObjectUtils.getJSONObject(jsonObject, "request_authentication_methods_supported");
				// authorization_endpoint or RAR
				for (String endpointName : spec.keySet()) {
					List<String> methodNames = JSONObjectUtils.getStringList(spec, endpointName, Collections.<String>emptyList());
					List<ClientAuthenticationMethod> authMethods = new LinkedList<>();
					for (String name : methodNames) {
						authMethods.add(ClientAuthenticationMethod.parse(name));
					}
					requestAuthMethods.put(new EndpointName(endpointName), authMethods);
				}
				as.setClientRegistrationAuthnMethods(requestAuthMethods);
			}
			
			if (jsonObject.get("request_authentication_signing_alg_values_supported") != null) {
				as.clientRegistrationAuthJWSAlgs = new ArrayList<>();
				
				for (String v : JSONObjectUtils.getStringArray(jsonObject, "request_authentication_signing_alg_values_supported")) {
					
					if (v != null)
						as.clientRegistrationAuthJWSAlgs.add(JWSAlgorithm.parse(v));
				}
			}
			
			as.federationRegistrationEndpoint = JSONObjectUtils.getURI(jsonObject, "federation_registration_endpoint", null);
		}
		
		as.organizationName = JSONObjectUtils.getString(jsonObject, "organization_name", null);
		
		// Parse custom (not registered) parameters
		JSONObject customParams = new JSONObject(jsonObject);
		customParams.keySet().removeAll(REGISTERED_PARAMETER_NAMES);
		for (Map.Entry<String,Object> customEntry: customParams.entrySet()) {
			as.setCustomParameter(customEntry.getKey(), customEntry.getValue());
		}
		
		return as;
	}
	
	
	/**
	 * Parses an OAuth 2.0 Authorisation Server metadata from the specified
	 * JSON object string.
	 *
	 * @param s The JSON object sting to parse. Must not be {@code null}.
	 *
	 * @return The OAuth 2.0 Authorisation Server metadata.
	 *
	 * @throws ParseException If the JSON object string couldn't be parsed
	 *                        to an OAuth 2.0 Authorisation Server
	 *                        metadata.
	 */
	public static AuthorizationServerMetadata parse(final String s)
		throws ParseException {
		
		return parse(JSONObjectUtils.parse(s));
	}
	
	
	/**
	 * Resolves OAuth 2.0 authorisation server metadata URL from the
	 * specified issuer identifier.
	 *
	 * @param issuer The issuer identifier. Must represent a valid HTTPS or
	 *               HTTP URL. Must not be {@code null}.
	 *
	 * @return The OAuth 2.0 authorisation server metadata URL.
	 *
	 * @throws GeneralException If the issuer identifier is invalid.
	 */
	public static URL resolveURL(final Issuer issuer)
		throws GeneralException {
		
		try {
			URL issuerURL = new URL(issuer.getValue());
			
			// Validate but don't insist on HTTPS
			if (issuerURL.getQuery() != null && ! issuerURL.getQuery().trim().isEmpty()) {
				throw new GeneralException("The issuer identifier must not contain a query component");
			}
			
			if (issuerURL.getPath() != null && issuerURL.getPath().endsWith("/")) {
				return new URL(issuerURL + ".well-known/oauth-authorization-server");
			} else {
				return new URL(issuerURL + "/.well-known/oauth-authorization-server");
			}
			
		} catch (MalformedURLException e) {
			throw new GeneralException("The issuer identifier doesn't represent a valid URL: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Resolves OAuth 2.0 authorisation server metadata from the specified
	 * issuer identifier. The metadata is downloaded by HTTP GET from
	 * {@code [issuer-url]/.well-known/oauth-authorization-server}.
	 *
	 * @param issuer The issuer identifier. Must represent a valid HTTPS or
	 *               HTTP URL. Must not be {@code null}.
	 *
	 * @return The OAuth 2.0 authorisation server metadata.
	 *
	 * @throws GeneralException If the issuer identifier or the downloaded
	 *                          metadata are invalid.
	 * @throws IOException      On a HTTP exception.
	 */
	public static AuthorizationServerMetadata resolve(final Issuer issuer)
		throws GeneralException, IOException {
		
		return resolve(issuer, 0, 0);
	}
	
	
	/**
	 * Resolves OAuth 2.0 authorisation server metadata from the specified
	 * issuer identifier. The metadata is downloaded by HTTP GET from
	 * {@code [issuer-url]/.well-known/oauth-authorization-server}.
	 *
	 * @param issuer         The issuer identifier. Must represent a valid
	 *                       HTTPS or HTTP URL. Must not be {@code null}.
	 * @param connectTimeout The HTTP connect timeout, in milliseconds.
	 *                       Zero implies no timeout. Must not be negative.
	 * @param readTimeout    The HTTP response read timeout, in
	 *                       milliseconds. Zero implies no timeout. Must
	 *                       not be negative.
	 *
	 * @return The OAuth 2.0 authorisation server metadata.
	 *
	 * @throws GeneralException If the issuer identifier or the downloaded
	 *                          metadata are invalid.
	 * @throws IOException      On a HTTP exception.
	 */
	public static AuthorizationServerMetadata resolve(final Issuer issuer,
							  final int connectTimeout,
							  final int readTimeout)
		throws GeneralException, IOException {
		
		URL configURL = resolveURL(issuer);
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, configURL);
		httpRequest.setConnectTimeout(connectTimeout);
		httpRequest.setReadTimeout(readTimeout);
		
		HTTPResponse httpResponse = httpRequest.send();
		
		if (httpResponse.getStatusCode() != 200) {
			throw new IOException("Couldn't download OAuth 2.0 Authorization Server metadata from " + configURL +
				": Status code " + httpResponse.getStatusCode());
		}
		
		JSONObject jsonObject = httpResponse.getContentAsJSONObject();
		
		AuthorizationServerMetadata as = AuthorizationServerMetadata.parse(jsonObject);
		
		if (! issuer.equals(as.issuer)) {
			throw new GeneralException("The returned issuer doesn't match the expected: " + as.getIssuer());
		}
		
		return as;
	}
}
