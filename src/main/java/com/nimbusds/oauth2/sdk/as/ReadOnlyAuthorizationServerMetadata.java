/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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
import java.util.List;
import java.util.Map;

import com.nimbusds.oauth2.sdk.rar.AuthorizationType;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.ciba.BackChannelTokenDeliveryMode;
import com.nimbusds.oauth2.sdk.client.ClientType;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.federation.registration.ClientRegistrationType;
import com.nimbusds.openid.connect.sdk.op.EndpointName;


/**
 * Read-only OAuth 2.0 Authorisation Server (AS) metadata.
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
 *     <li>OAuth 2.0 Rich Authorization Requests (RFC 9396)
 *     <li>OAuth 2.0 Device Authorization Grant (RFC 8628)
 *     <li>OpenID Connect Client Initiated Backchannel Authentication Flow -
 * 	   Core 1.0
 *     <li>OAuth 2.0 Incremental Authorization
 *         (draft-ietf-oauth-incremental-authz-04)
 *     <li>Initiating User Registration via OpenID Connect 1.0
 *     <li>OpenID Connect Federation 1.0 (draft 22)
 * </ul>
 */
public interface ReadOnlyAuthorizationServerMetadata extends ReadOnlyAuthorizationServerEndpointMetadata {
	
	
	/**
	 * Gets the issuer identifier. Corresponds to the {@code issuer}
	 * metadata field.
	 *
	 * @return The issuer identifier.
	 */
	Issuer getIssuer();
	
	
	/**
	 * Gets the JSON Web Key (JWK) set URI. Corresponds to the
	 * {@code jwks_uri} metadata field.
	 *
	 * @return The JWK set URI, {@code null} if not specified.
	 */
	URI getJWKSetURI();
	
	
	/**
	 * Gets the supported scope values. Corresponds to the
	 * {@code scopes_supported} metadata field.
	 *
	 * @return The supported scope values, {@code null} if not specified.
	 */
	Scope getScopes();
	
	
	/**
	 * Gets the supported response type values. Corresponds to the
	 * {@code response_types_supported} metadata field.
	 *
	 * @return The supported response type values, {@code null} if not
	 * specified.
	 */
	List<ResponseType> getResponseTypes();
	
	
	/**
	 * Gets the supported response mode values. Corresponds to the
	 * {@code response_modes_supported}.
	 *
	 * @return The supported response mode values, {@code null} if not
	 * specified.
	 */
	List<ResponseMode> getResponseModes();
	
	
	/**
	 * Gets the supported OAuth 2.0 grant types. Corresponds to the
	 * {@code grant_types_supported} metadata field.
	 *
	 * @return The supported grant types, {@code null} if not specified.
	 */
	List<GrantType> getGrantTypes();
	
	
	/**
	 * Gets the supported authorisation code challenge methods for PKCE.
	 * Corresponds to the {@code code_challenge_methods_supported} metadata
	 * field.
	 *
	 * @return The supported code challenge methods, {@code null} if not
	 * specified.
	 */
	List<CodeChallengeMethod> getCodeChallengeMethods();
	
	
	/**
	 * Gets the supported token endpoint authentication methods.
	 * Corresponds to the {@code token_endpoint_auth_methods_supported}
	 * metadata field.
	 *
	 * @return The supported token endpoint authentication methods,
	 * {@code null} if not specified.
	 */
	List<ClientAuthenticationMethod> getTokenEndpointAuthMethods();
	
	
	/**
	 * Gets the supported JWS algorithms for the {@code private_key_jwt}
	 * and {@code client_secret_jwt} token endpoint authentication methods.
	 * Corresponds to the
	 * {@code token_endpoint_auth_signing_alg_values_supported} metadata
	 * field.
	 *
	 * @return The supported JWS algorithms, {@code null} if not specified.
	 */
	List<JWSAlgorithm> getTokenEndpointJWSAlgs();
	
	
	/**
	 * Gets the supported introspection endpoint authentication methods.
	 * Corresponds to the
	 * {@code introspection_endpoint_auth_methods_supported} metadata
	 * field.
	 *
	 * @return The supported introspection endpoint authentication methods,
	 * {@code null} if not specified.
	 */
	List<ClientAuthenticationMethod> getIntrospectionEndpointAuthMethods();
	
	
	/**
	 * Gets the supported JWS algorithms for the {@code private_key_jwt}
	 * and {@code client_secret_jwt} introspection endpoint authentication
	 * methods. Corresponds to the
	 * {@code introspection_endpoint_auth_signing_alg_values_supported}
	 * metadata field.
	 *
	 * @return The supported JWS algorithms, {@code null} if not specified.
	 */
	List<JWSAlgorithm> getIntrospectionEndpointJWSAlgs();
	
	
	/**
	 * Gets the supported revocation endpoint authentication methods.
	 * Corresponds to the
	 * {@code revocation_endpoint_auth_methods_supported} metadata field.
	 *
	 * @return The supported revocation endpoint authentication methods,
	 * {@code null} if not specified.
	 */
	List<ClientAuthenticationMethod> getRevocationEndpointAuthMethods();
	
	
	/**
	 * Gets the supported JWS algorithms for the {@code private_key_jwt}
	 * and {@code client_secret_jwt} revocation endpoint authentication
	 * methods. Corresponds to the
	 * {@code revocation_endpoint_auth_signing_alg_values_supported}
	 * metadata field.
	 *
	 * @return The supported JWS algorithms, {@code null} if not specified.
	 */
	List<JWSAlgorithm> getRevocationEndpointJWSAlgs();
	
	
	/**
	 * Gets the supported JWS algorithms for request objects. Corresponds
	 * to the {@code request_object_signing_alg_values_supported} metadata
	 * field.
	 *
	 * @return The supported JWS algorithms, {@code null} if not specified.
	 */
	List<JWSAlgorithm> getRequestObjectJWSAlgs();
	
	
	/**
	 * Gets the supported JWE algorithms for request objects. Corresponds
	 * to the {@code request_object_encryption_alg_values_supported}
	 * metadata field.
	 *
	 * @return The supported JWE algorithms, {@code null} if not specified.
	 */
	List<JWEAlgorithm> getRequestObjectJWEAlgs();
	
	
	/**
	 * Gets the supported encryption methods for request objects.
	 * Corresponds to the
	 * {@code request_object_encryption_enc_values_supported} metadata
	 * field.
	 *
	 * @return The supported encryption methods, {@code null} if not
	 * specified.
	 */
	List<EncryptionMethod> getRequestObjectJWEEncs();
	
	
	/**
	 * Gets the support for the {@code request} authorisation request
	 * parameter. Corresponds to the {@code request_parameter_supported}
	 * metadata field.
	 *
	 * @return {@code true} if the {@code reqeust} parameter is supported,
	 * else {@code false}.
	 */
	boolean supportsRequestParam();
	
	
	/**
	 * Gets the support for the {@code request_uri} authorisation request
	 * parameter. Corresponds to the
	 * {@code request_uri_parameter_supported} metadata field.
	 *
	 * @return {@code true} if the {@code request_uri} parameter is
	 * supported, else {@code false}.
	 */
	boolean supportsRequestURIParam();
	
	
	/**
	 * Gets the requirement for the {@code request_uri} parameter
	 * pre-registration. Corresponds to the
	 * {@code require_request_uri_registration} metadata field.
	 *
	 * @return {@code true} if the {@code request_uri} parameter values
	 * must be pre-registered, else {@code false}.
	 */
	boolean requiresRequestURIRegistration();
	
	
	/**
	 * Gets the support for the {@code iss} authorisation response
	 * parameter. Corresponds to the
	 * {@code authorization_response_iss_parameter_supported} metadata
	 * field.
	 *
	 * @return {@code true} if the {@code iss} authorisation response
	 * parameter is provided, else {@code false}.
	 */
	boolean supportsAuthorizationResponseIssuerParam();
	
	
	/**
	 * Gets the supported UI locales. Corresponds to the
	 * {@code ui_locales_supported} metadata field.
	 *
	 * @return The supported UI locales, {@code null} if not specified.
	 */
	List<LangTag> getUILocales();
	
	
	/**
	 * Gets the service documentation URI. Corresponds to the
	 * {@code service_documentation} metadata field.
	 *
	 * @return The service documentation URI, {@code null} if not
	 * specified.
	 */
	URI getServiceDocsURI();
	
	
	/**
	 * Gets the provider's policy regarding relying party use of data.
	 * Corresponds to the {@code op_policy_uri} metadata field.
	 *
	 * @return The policy URI, {@code null} if not specified.
	 */
	URI getPolicyURI();
	
	
	/**
	 * Gets the provider's terms of service. Corresponds to the
	 * {@code op_tos_uri} metadata field.
	 *
	 * @return The terms of service URI, {@code null} if not specified.
	 */
	URI getTermsOfServiceURI();
	
	
	/**
	 * Gets the aliases for communication with mutual TLS. Corresponds to
	 * the {@code mtls_endpoint_aliases} metadata field.
	 *
	 * @return The aliases for communication with mutual TLS, {@code null}
	 *         when no aliases are defined.
	 */
	ReadOnlyAuthorizationServerEndpointMetadata getReadOnlyMtlsEndpointAliases();
	
	
	/**
	 * Gets the support for TLS client certificate bound access tokens.
	 * Corresponds to the
	 * {@code tls_client_certificate_bound_access_tokens} metadata field.
	 *
	 * @return {@code true} if TLS client certificate bound access tokens
	 * are supported, else {@code false}.
	 */
	boolean supportsTLSClientCertificateBoundAccessTokens();
	
	
	/**
	 * Gets the support for TLS client certificate bound access tokens.
	 * Corresponds to the
	 * {@code tls_client_certificate_bound_access_tokens} metadata field.
	 *
	 * @return {@code true} if TLS client certificate bound access tokens
	 * are supported, else {@code false}.
	 */
	@Deprecated
	boolean supportsMutualTLSSenderConstrainedAccessTokens();
	
	
	/**
	 * Gets the supported JWS algorithms for Demonstrating
	 * Proof-of-Possession at the Application Layer (DPoP). Corresponds to
	 * the "dpop_signing_alg_values_supported" metadata field.
	 *
	 * @return The supported JWS algorithms for DPoP, {@code null} if none.
	 */
	List<JWSAlgorithm> getDPoPJWSAlgs();
	
	
	/**
	 * Gets the supported JWS algorithms for JWT-encoded authorisation
	 * responses. Corresponds to the
	 * {@code authorization_signing_alg_values_supported} metadata field.
	 *
	 * @return The supported JWS algorithms, {@code null} if not specified.
	 */
	List<JWSAlgorithm> getAuthorizationJWSAlgs();
	
	
	/**
	 * Gets the supported JWE algorithms for JWT-encoded authorisation
	 * responses. Corresponds to the
	 * {@code authorization_encryption_alg_values_supported} metadata
	 * field.
	 *
	 * @return The supported JWE algorithms, {@code null} if not specified.
	 */
	List<JWEAlgorithm> getAuthorizationJWEAlgs();
	
	
	/**
	 * Gets the supported encryption methods for JWT-encoded authorisation
	 * responses. Corresponds to the
	 * {@code authorization_encryption_enc_values_supported} metadata
	 * field.
	 *
	 * @return The supported encryption methods, {@code null} if not
	 * specified.
	 */
	List<EncryptionMethod> getAuthorizationJWEEncs();
	
	
	/**
	 * Gets the requirement for pushed authorisation requests (PAR).
	 * Corresponds to the {@code pushed_authorization_request_endpoint}
	 * metadata field.
	 *
	 * @return {@code true} if PAR is required, else {@code false}.
	 */
	boolean requiresPushedAuthorizationRequests();


	/**
	 * Gets the supported authorisation details types for Rich
	 * Authorisation Requests (RAR). Corresponds to the
	 * {@code authorization_details_types_supported} metadata field.
	 *
	 * @return The supported authorisation types, {@code null} if not
	 *         specified.
	 */
	List<AuthorizationType> getAuthorizationDetailsTypes();
	
	
	/**
	 * Gets the supported OAuth 2.0 client types for incremental
	 * authorisation. Corresponds to the
	 * {@code incremental_authz_types_supported} metadata field.
	 *
	 * @return The supported client types for incremental authorisation,
	 * {@code null} if not specified.
	 */
	List<ClientType> getIncrementalAuthorizationTypes();
	
	
	/**
	 * Gets the supported CIBA token delivery modes. Corresponds to the
	 * {@code backchannel_token_delivery_modes_supported} metadata field.
	 *
	 * @return The CIBA token delivery modes, {@code null} if not
	 * specified.
	 */
	List<BackChannelTokenDeliveryMode> getBackChannelTokenDeliveryModes();
	
	
	/**
	 * Gets the supported JWS algorithms for CIBA requests. Corresponds to
	 * the {@code backchannel_authentication_request_signing_alg_values_supported}
	 * metadata field.
	 *
	 * @return The supported JWS algorithms, {@code null} if not specified.
	 */
	List<JWSAlgorithm> getBackChannelAuthenticationRequestJWSAlgs();
	
	
	/**
	 * Gets the support for the {@code user_code} CIBA request parameter.
	 * Corresponds to the {@code backchannel_user_code_parameter_supported}
	 * metadata field.
	 *
	 * @return {@code true} if the {@code user_code} parameter is
	 * supported, else {@code false}.
	 */
	boolean supportsBackChannelUserCodeParam();
	
	
	/**
	 * Gets the supported {@link Prompt.Type prompt types}. Corresponds to
	 * the {@code prompt_values_supported} metadata field.
	 *
	 * @return The supported prompt types, {@code null} if not specified.
	 */
	List<Prompt.Type> getPromptTypes();
	
	
	
	
	
	/**
	 * Gets the organisation name (OpenID Connect Federation 1.0).
	 * Corresponds to the {@code organization_name} metadata field.
	 *
	 * @return The organisation name, {@code null} if not specified.
	 */
	String getOrganizationName();
	
	
	/**
	 * Gets the JWK set (OpenID Connect Federation 1.0). Corresponds to the
	 * {@code jwks} metadata field.
	 *
	 * @return The JWK set, {@code null} if not specified.
	 */
	JWKSet getJWKSet();
	
	
	/**
	 * Gets the signed JWK set URI (OpenID Connect Federation 1.0).
	 * Corresponds to the {@code signed_jwks_uri} metadata field.
	 *
	 * @return The signed JWK set URI, {@code null} if not specified.
	 */
	URI getSignedJWKSetURI();
	
	
	/**
	 * Gets the supported OpenID Connect Federation 1.0 client registration
	 * types. Corresponds to the
	 * {@code client_registration_types_supported} metadata field.
	 *
	 * @return The supported client registration types, {@code null} if not
	 * specified.
	 */
	List<ClientRegistrationType> getClientRegistrationTypes();
	
	
	/**
	 * Gets the supported request authentication methods for automatic
	 * OpenID Connect Federation 1.0 client registration. Corresponds to
	 * the {@code request_authentication_methods_supported} field.
	 *
	 * @return The supported request authentication methods for automatic
	 * federation client registration, {@code null} if not specified.
	 */
	Map<EndpointName, List<ClientAuthenticationMethod>> getClientRegistrationAuthnMethods();
	
	
	/**
	 * Gets the supported JWS algorithms for authenticating automatic
	 * OpenID Connect Federation 1.0 client registration requests.
	 * Corresponds to the
	 * {@code request_authentication_signing_alg_values_supported}.
	 *
	 * @return The supported JWS algorithms, {@code null} if not specified.
	 */
	List<JWSAlgorithm> getClientRegistrationAuthnJWSAlgs();
	
	
	/**
	 * Gets the specified custom (not registered) parameter.
	 *
	 * @param name The parameter name. Must not be {@code null}.
	 * @return The parameter value, {@code null} if not specified.
	 */
	Object getCustomParameter(String name);
	
	
	/**
	 * Gets the specified custom (not registered) URI parameter.
	 *
	 * @param name The parameter name. Must not be {@code null}.
	 * @return The parameter URI value, {@code null} if not specified.
	 */
	URI getCustomURIParameter(String name);
	
	
	/**
	 * Gets the custom (not registered) parameters.
	 *
	 * @return The custom parameters, empty JSON object if none.
	 */
	JSONObject getCustomParameters();
	
	
	/**
	 * Returns the JSON object representation of the metadata.
	 *
	 * @return The JSON object representation.
	 */
	JSONObject toJSONObject();
}
