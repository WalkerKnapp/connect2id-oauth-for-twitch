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

package com.nimbusds.oauth2.sdk.token;


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import java.util.List;
import java.util.Map;


/**
 * Access token utilities.
 */
class AccessTokenUtils {
	
	
	/**
	 * Parses a {@code token_type} parameter.
	 *
	 * @param params The parameters. Must not be {@code null}.
	 * @param type   The expected token type. Must not be {@code null}.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static void parseAndEnsureType(final JSONObject params, final AccessTokenType type)
		throws ParseException {
		
		if (! new AccessTokenType(JSONObjectUtils.getString(params, "token_type")).equals(type)) {
			throw new ParseException("Token type must be " + type);
		}
	}
	
	
	/**
	 * Parses a {code access_token} parameter.
	 *
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The token value.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static String parseValue(final JSONObject params)
		throws ParseException {
		
		return JSONObjectUtils.getString(params, "access_token");
	}
	
	
	/**
	 * Parses a {@code expires_in} parameter.
	 *
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The lifetime, in seconds, zero if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static long parseLifetime(final JSONObject params)
		throws ParseException {
		
		if (params.containsKey("expires_in")) {
			
			// Lifetime can be a JSON number or string
			if (params.get("expires_in") instanceof Number) {
				return JSONObjectUtils.getLong(params, "expires_in");
			} else {
				String lifetimeStr = JSONObjectUtils.getString(params, "expires_in");
				try {
					return Long.parseLong(lifetimeStr);
				} catch (NumberFormatException e) {
					throw new ParseException("Invalid expires_in parameter, must be integer");
				}
			}
		}
		
		return 0L;
	}
	
	
	/**
	 * Parses a {@code scope} parameter.
	 *
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The scope, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static Scope parseScope(final JSONObject params)
		throws ParseException {
		
		return Scope.parse(JSONObjectUtils.getString(params, "scope", null));
	}


	/**
	 * Parses an {@code authorization_details} parameter.
	 *
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The authorisation details, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static List<AuthorizationDetail> parseAuthorizationDetails(final JSONObject params)
		throws ParseException {

		JSONArray jsonArray = JSONObjectUtils.getJSONArray(params, "authorization_details", null);

		if (jsonArray == null) {
			return null;
		}

		return AuthorizationDetail.parseList(JSONArrayUtils.toJSONObjectList(jsonArray));
	}

	
	/**
	 * Parses a {@code issued_token_type} parameter.
	 *
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The issued token type, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static TokenTypeURI parseIssuedTokenType(final JSONObject params)
		throws ParseException {
		
		String issuedTokenTypeString = JSONObjectUtils.getString(params, "issued_token_type", null);
		if (issuedTokenTypeString == null) {
			return null;
		}
		try {
			return TokenTypeURI.parse(issuedTokenTypeString);
		} catch (ParseException e) {
			throw new ParseException("Invalid issued_token_type parameter: " + e.getMessage());
		}
	}
	
	
	private static void ensureSupported(final AccessTokenType type) {
		
		if (! AccessTokenType.BEARER.equals(type) && ! AccessTokenType.DPOP.equals(type)) {
			throw new IllegalArgumentException("Unsupported access token type, must be Bearer or DPoP: " + type);
		}
	}
	
	
	/**
	 * Parses an access token value from an {@code Authorization} HTTP
	 * request header.
	 *
	 * @param header The {@code Authorization} header value, {@code null}
	 *               if not specified.
	 * @param type   The expected access token type. Must be
	 *               {@link AccessTokenType#BEARER} or
	 *               {@link AccessTokenType#DPOP} and not {@code null}.
	 *
	 * @return The access token value.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static String parseValueFromHeader(final String header, final AccessTokenType type)
		throws ParseException {
		
		ensureSupported(type);
		
		if (StringUtils.isBlank(header)) {
			TokenSchemeError schemeError = BearerTokenError.MISSING_TOKEN;
			if (AccessTokenType.DPOP.equals(type)) {
				schemeError = DPoPTokenError.MISSING_TOKEN;
			}
			throw new ParseException("Missing HTTP Authorization header", schemeError);
		}
		
		String[] parts = header.split("\\s", 2);
		
		if (parts.length != 2) {
			TokenSchemeError schemeError = BearerTokenError.INVALID_REQUEST;
			if (AccessTokenType.DPOP.equals(type)) {
				schemeError = DPoPTokenError.INVALID_REQUEST;
			}
			throw new ParseException("Invalid HTTP Authorization header value", schemeError);
		}
		
		if (! parts[0].equals(type.getValue())) {
			TokenSchemeError schemeError = BearerTokenError.INVALID_REQUEST;
			if (AccessTokenType.DPOP.equals(type)) {
				schemeError = DPoPTokenError.INVALID_TOKEN;
			}
			throw new ParseException("Token type must be Bearer", schemeError);
		}
		
		if (StringUtils.isBlank(parts[1])) {
			TokenSchemeError schemeError = BearerTokenError.INVALID_REQUEST;
			if (AccessTokenType.DPOP.equals(type)) {
				schemeError = DPoPTokenError.INVALID_REQUEST;
			}
			throw new ParseException("The token value must not be null or empty string", schemeError);
		}
		
		return parts[1];
	}
	
	
	/**
	 * Parses a query or form parameters map for an access token value.
	 *
	 * @param parameters The query parameters. Must not be {@code null}.
	 * @param type       The expected access token type. Must be
	 *                   {@link AccessTokenType#BEARER} or
	 *                   {@link AccessTokenType#DPOP} and not {@code null}.
	 *
	 * @return The access token value.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static String parseValueFromQueryParameters(final Map<String, List<String>> parameters,
						    final AccessTokenType type)
		throws ParseException {
		
		ensureSupported(type);
		
		if (! parameters.containsKey("access_token")) {
			TokenSchemeError schemeError = BearerTokenError.MISSING_TOKEN;
			if (AccessTokenType.DPOP.equals(type)) {
				schemeError = DPoPTokenError.MISSING_TOKEN;
			}
			throw new ParseException("Missing access token parameter", schemeError);
		}
		
		String accessTokenValue = MultivaluedMapUtils.getFirstValue(parameters, "access_token");
		
		if (StringUtils.isBlank(accessTokenValue)) {
			TokenSchemeError schemeError = BearerTokenError.INVALID_REQUEST;
			if (AccessTokenType.DPOP.equals(type)) {
				schemeError = DPoPTokenError.INVALID_REQUEST;
			}
			throw new ParseException("Blank / empty access token", schemeError);
		}
		
		return accessTokenValue;
	}
	
	
	/**
	 * Parses a query or form parameters map for an access token value.
	 *
	 * @param parameters The query parameters. Must not be {@code null}.
	 *
	 * @return The access token value.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static String parseValueFromQueryParameters(final Map<String, List<String>> parameters)
		throws ParseException {
		
		if (! parameters.containsKey("access_token")) {
			throw new ParseException("Missing access token parameter");
		}
		
		String accessTokenValue = MultivaluedMapUtils.getFirstValue(parameters, "access_token");
		
		if (StringUtils.isBlank(accessTokenValue)) {
			throw new ParseException("Blank / empty access token");
		}
		
		return accessTokenValue;
	}
	
	
	/**
	 * Determines the access token type from an {@code Authorization} HTTP
	 * request header.
	 *
	 * @param header The {@code Authorization} header value, {@code null}
	 *               if not specified.
	 *
	 * @return A {@link AccessTokenType#BEARER} or
	 *         {@link AccessTokenType#DPOP} access token type.
	 *
	 * @throws ParseException If the access token type couldn't be
	 *                        determined.
	 */
	static AccessTokenType determineAccessTokenTypeFromAuthorizationHeader(final String header)
		throws ParseException {
		
		if (StringUtils.isNotBlank(header)) {
			
			if (header.toLowerCase().startsWith(AccessTokenType.BEARER.getValue().toLowerCase() + " ")) {
				return AccessTokenType.BEARER;
			}
			
			if (header.toLowerCase().startsWith(AccessTokenType.DPOP.getValue().toLowerCase() + " ")) {
				return AccessTokenType.DPOP;
			}
		}
		
		throw new ParseException("Couldn't determine access token type from Authorization header");
	}
	
	
	private AccessTokenUtils() {}
}
