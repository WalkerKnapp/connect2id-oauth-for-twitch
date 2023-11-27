/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2023, Connect2id Ltd and contributors.
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

package com.nimbusds.oauth2.sdk;


import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import net.jcip.annotations.Immutable;

import java.util.*;


/**
 * Authorisation grant type.
 */
@Immutable
public final class GrantType extends Identifier {

	
	/**
	 * Authorisation code, as specified in RFC 6749.
	 */
	public static final GrantType AUTHORIZATION_CODE = new GrantType("authorization_code", false, true, ParameterRequirement.NOT_ALLOWED, new HashSet<>(Arrays.asList("code", "redirect_uri", "code_verifier")));


	/**
	 * Implicit, as specified in RFC 6749.
	 */
	public static final GrantType IMPLICIT = new GrantType("implicit", false, true, ParameterRequirement.NOT_ALLOWED, Collections.<String>emptySet());
	
	
	/**
	 * Refresh token, as specified in RFC 6749.
	 */
	public static final GrantType REFRESH_TOKEN = new GrantType("refresh_token", false, false, ParameterRequirement.OPTIONAL, Collections.singleton("refresh_token"));


	/**
	 * Password, as specified in RFC 6749.
	 */
	public static final GrantType PASSWORD = new GrantType("password", false, false, ParameterRequirement.OPTIONAL, new HashSet<>(Arrays.asList("username", "password")));


	/**
	 * Client credentials, as specified in RFC 6749.
	 */
	public static final GrantType CLIENT_CREDENTIALS = new GrantType("client_credentials", true, true, ParameterRequirement.OPTIONAL, Collections.<String>emptySet());


	/**
	 * JWT bearer, as specified in RFC 7523.
	 */
	public static final GrantType JWT_BEARER = new GrantType("urn:ietf:params:oauth:grant-type:jwt-bearer", false, false, ParameterRequirement.OPTIONAL, Collections.singleton("assertion"));


	/**
	 * SAML 2.0 bearer, as specified in RFC 7522.
	 */
	public static final GrantType SAML2_BEARER = new GrantType("urn:ietf:params:oauth:grant-type:saml2-bearer", false, false, ParameterRequirement.OPTIONAL, Collections.singleton("assertion"));


	/**
	 * Device authorisation grant, as specified in RFC 8628.
	 */
	public static final GrantType DEVICE_CODE = new GrantType("urn:ietf:params:oauth:grant-type:device_code", false, true, ParameterRequirement.NOT_ALLOWED, Collections.singleton("device_code"));


	/**
	 * Client Initiated Back-channel Authentication (CIBA), as specified in
	 * OpenID Connect Client Initiated Backchannel Authentication Flow -
	 * Core 1.0.
	 */
	public static final GrantType CIBA = new GrantType("urn:openid:params:grant-type:ciba", true, true, ParameterRequirement.NOT_ALLOWED, Collections.singleton("auth_req_id"));

	
	/**
	 * Token exchange, as specified in RFC 8693.
	 */
	public static final GrantType TOKEN_EXCHANGE = new GrantType("urn:ietf:params:oauth:grant-type:token-exchange",
			false, false,  ParameterRequirement.OPTIONAL,
			new HashSet<>(Arrays.asList(
					"audience", "requested_token_type", "subject_token", "subject_token_type", "actor_token", "actor_token_type"
			)));
	
	
	private static final long serialVersionUID = -5367937758427680765L;
	
	
	/**
	 * The client authentication requirement.
	 */
	private final boolean requiresClientAuth;


	/**
	 * The client identifier requirement.
	 */
	private final boolean requiresClientID;


	/**
	 * The scope parameter requirement in token requests.
	 */
	private final ParameterRequirement scopeRequirementInTokenRequest;


	/**
	 * The names of the token request parameters specific to this grant
	 * type.
	 */
	private final Set<String> requestParamNames;


	/**
	 * Creates a new OAuth 2.0 authorisation grant type with the specified
	 * value. The client authentication and identifier requirements are set
	 * to {@code false}. The scope parameter in token requests is not
	 * allowed.
	 *
	 * @param value The authorisation grant type value. Must not be
	 *              {@code null} or empty string.
	 */
	public GrantType(final String value) {

		this(value, false, false, ParameterRequirement.NOT_ALLOWED, Collections.<String>emptySet());
	}


	/**
	 * Creates a new OAuth 2.0 authorisation grant type with the specified
	 * value.
	 *
	 * @param value                          The authorisation grant type
	 *                                       value. Must not be
	 *                                       {@code null} or empty string.
	 * @param requiresClientAuth             The client authentication
	 *                                       requirement.
	 * @param requiresClientID               The client identifier
	 *                                       requirement.
	 * @param scopeRequirementInTokenRequest The scope parameter
	 *                                       requirement in token requests.
	 *                                       Must not be {@code null}.
	 * @param requestParamNames              The names of the token request
	 *                                       parameters specific to this
	 *                                       grant type, empty set or
	 *                                       {@code null} if none.
	 */
	private GrantType(final String value,
			  final boolean requiresClientAuth,
			  final boolean requiresClientID,
			  final ParameterRequirement scopeRequirementInTokenRequest,
			  final Set<String> requestParamNames) {

		super(value);

		this.requiresClientAuth = requiresClientAuth;

		this.requiresClientID = requiresClientID;

		Objects.requireNonNull(scopeRequirementInTokenRequest);
		this.scopeRequirementInTokenRequest = scopeRequirementInTokenRequest;

		this.requestParamNames = requestParamNames == null ? Collections.<String>emptySet() : Collections.unmodifiableSet(requestParamNames);
	}


	/**
	 * Gets the client authentication requirement.
	 *
	 * @return {@code true} if explicit client authentication is always
	 *         required for this grant type, else {@code false}.
	 */
	public boolean requiresClientAuthentication() {

		return requiresClientAuth;
	}


	/**
	 * Gets the client identifier requirement.
	 *
	 * @return {@code true} if a client identifier must always be
	 *         communicated for this grant type (either as part of the
	 *         client authentication, or as a parameter in the token
	 *         request), else {@code false}.
	 */
	public boolean requiresClientID() {

		return requiresClientID;
	}

	/**
	 * Gets the scope parameter requirement in token requests.
	 *
	 * @return The scope parameter requirement.
	 */
	public ParameterRequirement getScopeRequirementInTokenRequest() {

		return scopeRequirementInTokenRequest;
	}


	/**
	 * Gets the names of the token request parameters specific to this
	 * grant type.
	 *
	 * @return The parameter names, empty set if none.
	 */
	public Set<String> getRequestParameterNames() {

		return requestParamNames;
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof GrantType && this.toString().equals(object.toString());
	}


	/**
	 * Parses a grant type from the specified string.
	 *
	 * @param value The string to parse.
	 *
	 * @return The grant type.
	 *
	 * @throws ParseException If string is {@code null}, blank or empty.
	 */
	public static GrantType parse(final String value)
		throws ParseException {

		GrantType grantType;

		try {
			grantType = new GrantType(value);

		} catch (IllegalArgumentException e) {

			throw new ParseException(e.getMessage());
		}

		if (grantType.equals(GrantType.AUTHORIZATION_CODE)) {

			return GrantType.AUTHORIZATION_CODE;

		} else if (grantType.equals(GrantType.IMPLICIT)) {

			return GrantType.IMPLICIT;

		} else if (grantType.equals(GrantType.REFRESH_TOKEN)) {

			return GrantType.REFRESH_TOKEN;

		} else if (grantType.equals(GrantType.PASSWORD)) {

			return GrantType.PASSWORD;

		} else if (grantType.equals(GrantType.CLIENT_CREDENTIALS)) {

			return GrantType.CLIENT_CREDENTIALS;

		} else if (grantType.equals(GrantType.JWT_BEARER)) {

			return GrantType.JWT_BEARER;

		} else if (grantType.equals(GrantType.SAML2_BEARER)) {

			return GrantType.SAML2_BEARER;

		} else if (grantType.equals(GrantType.DEVICE_CODE)) {

			return GrantType.DEVICE_CODE;

		} else if (grantType.equals(GrantType.CIBA)) {

			return GrantType.CIBA;

		} else if (grantType.equals(GrantType.TOKEN_EXCHANGE)) {

			return GrantType.TOKEN_EXCHANGE;

		} else {

			return grantType;
		}
	}
	
	
	/**
	 * Ensures the specified grant type is set in a list of parameters.
	 *
	 * @param grantType The grant type. Must not be {@code null}.
	 * @param params    The parameters. Must not be {@code null}.
	 *
	 * @throws ParseException If the grant type is not set.
	 */
	public static void ensure(final GrantType grantType, final Map<String, List<String>> params)
		throws ParseException {
		
		// Parse grant type
		String grantTypeString = MultivaluedMapUtils.getFirstValue(params, "grant_type");
		
		if (grantTypeString == null) {
			String msg = "Missing grant_type parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
		}
		
		if (! GrantType.parse(grantTypeString).equals(grantType)) {
			String msg = "The grant_type must be " + grantType + "";
			throw new ParseException(msg, OAuth2Error.UNSUPPORTED_GRANT_TYPE.appendDescription(": " + msg));
		}
	}
}
