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

package com.nimbusds.openid.connect.sdk.op;


import java.net.URI;

import com.nimbusds.oauth2.sdk.as.ReadOnlyAuthorizationServerEndpointMetadata;


/**
 * Read-only OpenID Provider (OP) endpoint metadata.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Authorization Server Metadata (RFC 8414)
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (RFC 8705)
 *     <li>OAuth 2.0 Device Flow for Browserless and Input Constrained Devices
 *         (draft-ietf-oauth-device-flow-14)
 *     <li>OpenID Connect Discovery 1.0, section 3.
 *     <li>OpenID Connect Session Management 1.0, section 2.1 (draft 28).
 *     <li>OpenID Connect Front-Channel Logout 1.0, section 3 (draft 02).
 *     <li>OpenID Connect Back-Channel Logout 1.0, section 2.1 (draft 04).
 *     <li>OpenID Connect Federation 1.0 (draft 10).
 * </ul>
 */
public interface ReadOnlyOIDCProviderEndpointMetadata extends ReadOnlyAuthorizationServerEndpointMetadata {
	
	
	/**
	 * Gets the UserInfo endpoint URI. Corresponds the
	 * {@code userinfo_endpoint} metadata field.
	 *
	 * @return The UserInfo endpoint URI, {@code null} if not specified.
	 */
	URI getUserInfoEndpointURI();
	
	
	/**
	 * Gets the cross-origin check session iframe URI. Corresponds to the
	 * {@code check_session_iframe} metadata field.
	 *
	 * @return The check session iframe URI, {@code null} if not specified.
	 */
	URI getCheckSessionIframeURI();
	
	
	/**
	 * Gets the logout endpoint URI. Corresponds to the
	 * {@code end_session_endpoint} metadata field.
	 *
	 * @return The logoout endpoint URI, {@code null} if not specified.
	 */
	URI getEndSessionEndpointURI();
	
	
	/**
	 * Gets the federation registration endpoint URI. Corresponds to the
	 * {@code federation_registration_endpoint} metadata field.
	 *
	 * @return The federation registration endpoint URI, {@code null} if
	 * not specified.
	 */
	URI getFederationRegistrationEndpointURI();
}
