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

import net.minidev.json.JSONObject;


/**
 * Read-only OAuth 2.0 Authorisation Server (AS) endpoint metadata.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Authorization Server Metadata (RFC 8414)
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (RFC 8705)
 *     <li>OAuth 2.0 Pushed Authorization Requests (RFC 9126)
 *     <li>OAuth 2.0 Device Authorization Grant (RFC 8628)
 *     <li>OpenID Connect Client Initiated Backchannel Authentication Flow -
 * 	   Core 1.0
 *     <li>OpenID Connect Federation 1.0 (draft 22).
 * </ul>
 */
public interface ReadOnlyAuthorizationServerEndpointMetadata {
	
	
	/**
	 * Gets the authorisation endpoint URI. Corresponds the
	 * {@code authorization_endpoint} metadata field.
	 *
	 * @return The authorisation endpoint URI, {@code null} if not
	 *         specified.
	 */
	URI getAuthorizationEndpointURI();
	
	
	/**
	 * Gets the token endpoint URI. Corresponds the {@code token_endpoint}
	 * metadata field.
	 *
	 * @return The token endpoint URI, {@code null} if not specified.
	 */
	URI getTokenEndpointURI();
	
	
	/**
	 * Gets the client registration endpoint URI. Corresponds to the
	 * {@code registration_endpoint} metadata field.
	 *
	 * @return The client registration endpoint URI, {@code null} if not
	 *         specified.
	 */
	URI getRegistrationEndpointURI();
	
	
	/**
	 * Gets the token introspection endpoint URI. Corresponds to the
	 * {@code introspection_endpoint} metadata field.
	 *
	 * @return The token introspection endpoint URI, {@code null} if not
	 *         specified.
	 */
	URI getIntrospectionEndpointURI();
	
	
	/**
	 * Gets the token revocation endpoint URI. Corresponds to the
	 * {@code revocation_endpoint} metadata field.
	 *
	 * @return The token revocation endpoint URI, {@code null} if not
	 *         specified.
	 */
	URI getRevocationEndpointURI();
	
	
	/**
	 * Gets the request object endpoint. Corresponds to the
	 * {@code request_object_endpoint} metadata field.
	 *
	 * @return The request object endpoint, {@code null} if not specified.
	 */
	@Deprecated
	URI getRequestObjectEndpoint();
	
	
	/**
	 * Gets the pushed authorisation request endpoint. Corresponds to the
	 * {@code pushed_authorization_request_endpoint} metadata field.
	 *
	 * @return The pushed authorisation request endpoint, {@code null} if
	 *         not specified.
	 */
	URI getPushedAuthorizationRequestEndpointURI();
	
	
	/**
	 * Gets the device authorization endpoint URI. Corresponds the
	 * {@code device_authorization_endpoint} metadata field.
	 *
	 * @return The device authorization endpoint URI, {@code null} if not
	 *         specified.
	 */
	URI getDeviceAuthorizationEndpointURI();
	
	
	/**
	 * Gets the back-channel authentication endpoint URI. Corresponds the
	 * {@code backchannel_authentication_endpoint} metadata field.
	 *
	 * @return The back-channel authentication endpoint URI, {@code null}
	 *         if not specified.
	 */
	URI getBackChannelAuthenticationEndpointURI();
	
	
	/**
	 * Gets the back-channel authentication endpoint URI. Corresponds the
	 * {@code backchannel_authentication_endpoint} metadata field.
	 *
	 * @deprecated Use {@link #getBackChannelAuthenticationEndpointURI}
	 * instead.
	 *
	 * @return The back-channel authentication endpoint URI, {@code null}
	 *         if not specified.
	 */
	@Deprecated
	URI getBackChannelAuthenticationEndpoint();
	
	
	/**
	 * Gets the federation registration endpoint URI. Corresponds to the
	 * {@code federation_registration_endpoint} metadata field.
	 *
	 * @return The federation registration endpoint URI, {@code null} if
	 * not specified.
	 */
	URI getFederationRegistrationEndpointURI();
	
	
	/**
	 * Returns the JSON object representation of the metadata.
	 *
	 * @return The JSON object.
	 */
	JSONObject toJSONObject();
}
