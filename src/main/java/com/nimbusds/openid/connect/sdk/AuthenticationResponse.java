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

package com.nimbusds.openid.connect.sdk;


import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;

import java.net.URI;


/**
 * OpenID Connect authentication response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 * </ul>
 */
public interface AuthenticationResponse extends Response {


	/**
	 * Returns the base redirection URI.
	 *
	 * @return The base redirection URI.
	 */
	URI getRedirectionURI();


	/**
	 * Returns the optional state.
	 *
	 * @return The state, {@code null} if not requested or if the response
	 *         is JWT-secured in which case the state parameter may be
	 *         included as a JWT claim.
	 */
	State getState();


	/**
	 * Returns the optional issuer.
	 *
	 * @return The issuer, {@code null} if not specified.
	 */
	Issuer getIssuer();


	/**
	 * Returns the JSON Web Token (JWT) secured response.
	 *
	 * @return The JWT-secured response, {@code null} for a regular
	 *         authorisation response.
	 */
	JWT getJWTResponse();


	/**
	 * Returns the optional explicit response mode.
	 *
	 * @return The response mode, {@code null} if not specified.
	 */
	ResponseMode getResponseMode();


	/**
	 * Determines the implied response mode.
	 *
	 * @return The implied response mode.
	 */
	ResponseMode impliedResponseMode();
	
	
	/**
	 * Casts this response to an authentication success response.
	 *
	 * @return The authentication success response.
	 */
	AuthenticationSuccessResponse toSuccessResponse();
	
	
	/**
	 * Casts this response to an authentication error response.
	 *
	 * @return The authentication error response.
	 */
	AuthenticationErrorResponse toErrorResponse();
}
