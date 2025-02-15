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

package com.nimbusds.oauth2.sdk.token;


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import java.util.List;
import java.util.Map;


/**
 * Bearer access token.
 *
 * <p>Example bearer access token serialised to JSON:
 *
 * <pre>
 * {
 *   "access_token" : "2YotnFZFEjr1zCsicMWpAA",
 *   "token_type"   : "bearer",
 *   "expires_in"   : 3600,
 *   "scope"        : "read write"
 * }
 * </pre>
 *
 * <p>The above example token serialised to an HTTP Authorization header:
 *
 * <pre>
 * Authorization: Bearer 2YotnFZFEjr1zCsicMWpAA
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749)
 *     <li>OAuth 2.0 Bearer Token Usage (RFC 6750)
 *     <li>OAuth 2.0 Rich Authorization Requests (RFC 9396)
 *     <li>OAuth 2.0 Token Exchange (RFC 8693)
 * </ul>
 */
@Immutable
public class BearerAccessToken extends AccessToken {
	
	
	private static final long serialVersionUID = 2387121016151061194L;
	
	
	/**
	 * Creates a new minimal bearer access token with a randomly generated 
	 * 256-bit (32-byte) value, Base64URL-encoded. The optional lifetime,
	 * scope and token type URI are left unspecified.
	 */
	public BearerAccessToken() {
	
		this(32);
	}	


	/**
	 * Creates a new minimal bearer access token with a randomly generated 
	 * value of the specified byte length, Base64URL-encoded. The optional 
	 * lifetime, scope and token type URI are left unspecified.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	public BearerAccessToken(final int byteLength) {
	
		this(byteLength, 0L, null);
	}


	/**
	 * Creates a new bearer access token with a randomly generated 256-bit 
	 * (32-byte) value, Base64URL-encoded. The optional token type URI is
	 * left unspecified.
	 *
	 * @param lifetime The lifetime in seconds, 0 if not specified.
	 * @param scope    The scope, {@code null} if not specified.
	 */
	public BearerAccessToken(final long lifetime, final Scope scope) {
	
		this(32, lifetime, scope);
	}


	/**
	 * Creates a new bearer access token with a randomly generated value of 
	 * the specified byte length, Base64URL-encoded. The optional token
	 * type URI is left unspecified.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 * @param lifetime   The lifetime in seconds, 0 if not specified.
	 * @param scope      The scope, {@code null} if not specified.
	 */
	public BearerAccessToken(final int byteLength, final long lifetime, final Scope scope) {
	
		super(AccessTokenType.BEARER, byteLength, lifetime, scope);
	}
	
	
	/**
	 * Creates a new minimal bearer access token with the specified value.
	 * The optional lifetime, scope and token type URI are left
	 * unspecified.
	 *
	 * @param value The access token value. Must not be {@code null} or
	 *              empty string.
	 */
	public BearerAccessToken(final String value) {
	
		this(value, 0L, null, null);
	}

	
	/**
	 * Creates a new bearer access token with the specified value. The
	 * token type URI is left unspecified.
	 *
	 * @param value    The access token value. Must not be {@code null} or
	 *                 empty string.
	 * @param lifetime The lifetime in seconds, 0 if not specified.
	 * @param scope    The scope, {@code null} if not specified.
	 */
	public BearerAccessToken(final String value, final long lifetime, final Scope scope) {

		this(value, lifetime, scope, null);
	}
	
	
	/**
	 * Creates a new bearer access token with the specified value.
	 *
	 * @param value           The access token value. Must not be
	 *                        {@code null} or empty string.
	 * @param lifetime        The lifetime in seconds, 0 if not specified.
	 * @param scope           The scope, {@code null} if not specified.
	 * @param issuedTokenType The token type URI, {@code null} if not
	 *                        specified.
	 */
	public BearerAccessToken(final String value,
				 final long lifetime,
				 final Scope scope,
				 final TokenTypeURI issuedTokenType) {
	
		super(AccessTokenType.BEARER, value, lifetime, scope, null, issuedTokenType);
	}


	/**
	 * Creates a new bearer access token with the specified value.
	 *
	 * @param value                The access token value. Must not be
	 *                             {@code null} or empty string.
	 * @param lifetime             The lifetime in seconds, 0 if not
	 *                             specified.
	 * @param scope                The scope, {@code null} if not
	 *                             specified.
	 * @param authorizationDetails The authorisation details, {@code null}
	 *                             if not specified.
	 * @param issuedTokenType      The token type URI, {@code null} if not
	 *                             specified.
	 */
	public BearerAccessToken(final String value,
				 final long lifetime,
				 final Scope scope,
				 final List<AuthorizationDetail> authorizationDetails,
				 final TokenTypeURI issuedTokenType) {

		super(AccessTokenType.BEARER, value, lifetime, scope, authorizationDetails, issuedTokenType);
	}
	
	
	/**
	 * Returns the HTTP Authorization header value for this bearer access 
	 * token.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * Authorization: Bearer eyJhbGciOiJIUzI1NiJ9
	 * </pre>
	 *
	 * @return The HTTP Authorization header.
	 */
	@Override
	public String toAuthorizationHeader(){
	
		return "Bearer " + getValue();
	}
	
	
	@Override
	public boolean equals(final Object object) {
	
		return object instanceof BearerAccessToken &&
		       this.toString().equals(object.toString());
	}


	/**
	 * Parses a bearer access token from a JSON object access token 
	 * response.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The bearer access token.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        bearer access token.
	 */
	public static BearerAccessToken parse(final JSONObject jsonObject)
		throws ParseException {
		
		AccessTokenUtils.parseAndEnsureType(jsonObject, AccessTokenType.BEARER);
		String accessTokenValue = AccessTokenUtils.parseValue(jsonObject);
		long lifetime = AccessTokenUtils.parseLifetime(jsonObject);
		Scope scope = AccessTokenUtils.parseScope(jsonObject);
		List<AuthorizationDetail> authorizationDetails = AccessTokenUtils.parseAuthorizationDetails(jsonObject);
		TokenTypeURI issuedTokenType = AccessTokenUtils.parseIssuedTokenType(jsonObject);
		return new BearerAccessToken(accessTokenValue, lifetime, scope, authorizationDetails, issuedTokenType);
	}
	
	
	/**
	 * Parses an HTTP Authorization header for a bearer access token.
	 *
	 * @param header The HTTP Authorization header value to parse. May be
	 *               {@code null} if the header is missing, in which case
	 *               an exception will be thrown.
	 *
	 * @return The bearer access token.
	 *
	 * @throws ParseException If the HTTP Authorization header value 
	 *                        couldn't be parsed to a bearer access token.
	 */
	public static BearerAccessToken parse(final String header)
		throws ParseException {
		
		return new BearerAccessToken(AccessTokenUtils.parseValueFromHeader(header, AccessTokenType.BEARER));
	}
	
	
	/**
	 * Parses a query or form parameters map for a bearer access token.
	 *
	 * @param parameters The query parameters. Must not be {@code null}.
	 *
	 * @return The bearer access token.
	 *
	 * @throws ParseException If a bearer access token wasn't found in the
	 *                        parameters.
	 */
	public static BearerAccessToken parse(final Map<String,List<String>> parameters)
		throws ParseException {
		
		return new BearerAccessToken(AccessTokenUtils.parseValueFromQueryParameters(parameters, AccessTokenType.BEARER));
	}
	
	
	
	/**
	 * Parses an HTTP request for a bearer access token.
	 * 
	 * @param request The HTTP request to parse. Must not be {@code null}.
	 * 
	 * @return The bearer access token.
	 * 
	 * @throws ParseException If a bearer access token wasn't found in the
	 *                        HTTP request.
	 */
	public static BearerAccessToken parse(final HTTPRequest request)
		throws ParseException {

		// See http://tools.ietf.org/html/rfc6750#section-2
		String authzHeader = request.getAuthorization();

		if (authzHeader != null) {
			return parse(authzHeader);
		}

		// Try alternative token locations, form and query string are
		// parameters are not differentiated here
		Map<String,List<String>> params = request.getQueryParameters();
		return parse(params);
	}
}
