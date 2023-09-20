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
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.minidev.json.JSONObject;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;


/**
 * The base abstract class for access tokens. Concrete extending classes should
 * be immutable.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 1.4 and 5.1.
 *     <li>OAuth 2.0 Rich Authorization Requests (RFC 9396), section 7.
 *     <li>OAuth 2.0 Token Exchange (RFC 8693), section 3.
 * </ul>
 */
public abstract class AccessToken extends Token {
	
	
	private static final long serialVersionUID = 2947643641344083799L;
	
	
	/**
	 * The access token type.
	 */
	private final AccessTokenType type;
	
	
	/**
	 * Optional lifetime, in seconds.
	 */
	private final long lifetime;
	
	
	/**
	 * Optional scope.
	 */
	private final Scope scope;


	/**
	 * Optional authorisation details.
	 */
	private final List<AuthorizationDetail> authorizationDetails;


	/**
	 * Optional identifier URI for the token type, as defined in OAuth 2.0
	 * Token Exchange (RFC 8693).
	 */
	private final TokenTypeURI issuedTokenType;


	/**
	 * Creates a new minimal access token with a randomly generated 256-bit 
	 * (32-byte) value, Base64URL-encoded. The optional lifetime, scope and
	 * token type URI are left unspecified.
	 *
	 * @param type The access token type. Must not be {@code null}.
	 */
	public AccessToken(final AccessTokenType type) {
	
		this(type, 32);
	}


	/**
	 * Creates a new minimal access token with a randomly generated value 
	 * of the specified byte length, Base64URL-encoded. The optional 
	 * lifetime, scope and token type URI are left unspecified.
	 *
	 * @param type       The access token type. Must not be {@code null}.
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	public AccessToken(final AccessTokenType type, final int byteLength) {
	
		this(type, byteLength, 0L, null);
	}


	/**
	 * Creates a new access token with a randomly generated 256-bit 
	 * (32-byte) value, Base64URL-encoded. The optional token type URI is
	 * left unspecified.
	 *
	 * @param type     The access token type. Must not be {@code null}.
	 * @param lifetime The lifetime in seconds, 0 if not specified.
	 * @param scope    The scope, {@code null} if not specified.
	 */
	public AccessToken(final AccessTokenType type,
		           final long lifetime, 
		           final Scope scope) {
	
		this(type, 32, lifetime, scope);
	}


	/**
	 * Creates a new access token with a randomly generated value 
	 * of the specified byte length, Base64URL-encoded. The optional token
	 * type URI is left unspecified.
	 *
	 * @param type       The access token type. Must not be {@code null}.
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 * @param lifetime   The lifetime in seconds, 0 if not specified.
	 * @param scope      The scope, {@code null} if not specified.
	 */
	public AccessToken(final AccessTokenType type, 
		           final int byteLength, 
		           final long lifetime, 
		           final Scope scope) {
	
		this(type, byteLength, lifetime, scope, null);
	}

	
	/**
	 * Creates a new access token with a randomly generated value
	 * of the specified byte length, Base64URL-encoded.
	 *
	 * @param type            The access token type. Must not be
	 *                        {@code null}.
	 * @param byteLength      The byte length of the value to generate.
	 *                        Must be greater than one.
	 * @param lifetime        The lifetime in seconds, 0 if not specified.
	 * @param scope           The scope, {@code null} if not specified.
	 * @param issuedTokenType The token type URI, {@code null} if not
	 *                        specified.
	 */
	public AccessToken(final AccessTokenType type,
			   final int byteLength,
			   final long lifetime,
			   final Scope scope,
			   final TokenTypeURI issuedTokenType) {

		this(type, byteLength, lifetime, scope, null, issuedTokenType);
	}


	/**
	 * Creates a new access token with a randomly generated value
	 * of the specified byte length, Base64URL-encoded.
	 *
	 * @param type                 The access token type. Must not be
	 *                             {@code null}.
	 * @param byteLength           The byte length of the value to
	 *                             generate. Must be greater than one.
	 * @param lifetime             The lifetime in seconds, 0 if not
	 *                             specified.
	 * @param scope                The scope, {@code null} if not
	 *                             specified.
	 * @param authorizationDetails The authorisation details, {@code null}
	 *                             if not specified.
	 * @param issuedTokenType      The token type URI, {@code null} if not
	 *                             specified.
	 */
	public AccessToken(final AccessTokenType type,
			   final int byteLength,
			   final long lifetime,
			   final Scope scope,
			   final List<AuthorizationDetail> authorizationDetails,
			   final TokenTypeURI issuedTokenType) {

		super(byteLength);

		if (type == null)
			throw new IllegalArgumentException("The access token type must not be null");

		this.type = type;

		this.lifetime = lifetime;
		this.scope = scope;
		this.authorizationDetails = authorizationDetails;
		this.issuedTokenType = issuedTokenType;
	}
	
	
	/**
	 * Creates a new minimal access token with the specified value. The 
	 * optional lifetime, scope and token type URI are left unspecified.
	 *
	 * @param type  The access token type. Must not be {@code null}.
	 * @param value The access token value. Must not be {@code null} or
	 *              empty string.
	 */
	public AccessToken(final AccessTokenType type, final String value) {
	
		this(type, value, 0L, null);
	}
	
	
	/**
	 * Creates a new access token with the specified value. The optional
	 * token type URI is left unspecified.
	 *
	 * @param type     The access token type. Must not be {@code null}.
	 * @param value    The access token value. Must not be {@code null} or
	 *                 empty string.
	 * @param lifetime The lifetime in seconds, 0 if not specified.
	 * @param scope    The scope, {@code null} if not specified.
	 */
	public AccessToken(final AccessTokenType type, 
		           final String value, 
		           final long lifetime, 
		           final Scope scope) {
		this(type, value, lifetime, scope, null);
	}

	
	/**
	 * Creates a new access token with the specified value.
	 *
	 * @param type            The access token type. Must not be
	 *                        {@code null}.
	 * @param value           The access token value. Must not be
	 *                        {@code null} or empty string.
	 * @param lifetime        The lifetime in seconds, 0 if not specified.
	 * @param scope           The scope, {@code null} if not specified.
	 * @param issuedTokenType The token type URI, {@code null} if not
	 *                        specified.
	 */
	public AccessToken(final AccessTokenType type,
			   final String value,
			   final long lifetime,
			   final Scope scope,
			   final TokenTypeURI issuedTokenType) {
		
		this(type, value, lifetime, scope, null, issuedTokenType);
	}


	/**
	 * Creates a new access token with the specified value.
	 *
	 * @param type            The access token type. Must not be
	 *                        {@code null}.
	 * @param value           The access token value. Must not be
	 *                        {@code null} or empty string.
	 * @param lifetime        The lifetime in seconds, 0 if not specified.
	 * @param scope           The scope, {@code null} if not specified.
	 * @param issuedTokenType The token type URI, {@code null} if not
	 *                        specified.
	 */
	public AccessToken(final AccessTokenType type,
			   final String value,
			   final long lifetime,
			   final Scope scope,
			   final List<AuthorizationDetail> authorizationDetails,
			   final TokenTypeURI issuedTokenType) {

		super(value);

		if (type == null)
			throw new IllegalArgumentException("The access token type must not be null");

		this.type = type;

		this.lifetime = lifetime;
		this.scope = scope;
		this.authorizationDetails = authorizationDetails;
		this.issuedTokenType = issuedTokenType;
	}


	/**
	 * Returns the access token type.
	 *
	 * @return The access token type.
	 */
	public AccessTokenType getType() {

		return type;
	}

	
	/**
	 * Returns the lifetime of this access token.
	 *
	 * @return The lifetime in seconds, 0 if not specified.
	 */
	public long getLifetime() {
	
		return lifetime;
	}
	
	
	/**
	 * Returns the scope of this access token.
	 *
	 * @return The scope, {@code null} if not specified.
	 */
	public Scope getScope() {
	
		return scope;
	}


	/**
	 * Returns the authorisation details for this access token.
	 *
	 * @return The authorisation details, {@code null} if not specified.
	 */
	public List<AuthorizationDetail> getAuthorizationDetails() {

		return authorizationDetails;
	}

	
	/**
	 * Returns the identifier URI for the type of this access token. Used
	 * in OAuth 2.0 Token Exchange (RFC 8693).
	 *
	 * @return The token type URI, {@code null} if not specified.
	 */
	public TokenTypeURI getIssuedTokenType() {
		
		return issuedTokenType;
	}

	
	@Override
	public Set<String> getParameterNames() {

		Set<String> paramNames = new HashSet<>();
		paramNames.add("access_token");
		paramNames.add("token_type");

		if (getLifetime() > 0)
			paramNames.add("expires_in");

		if (getScope() != null)
			paramNames.add("scope");

		if (getAuthorizationDetails() != null)
			paramNames.add("authorization_details");

		if (getIssuedTokenType() != null) {
			paramNames.add("issued_token_type");
		}

		return paramNames;
	}


	@Override
	public JSONObject toJSONObject() {

		JSONObject o = new JSONObject();

		o.put("access_token", getValue());
		o.put("token_type", type.toString());
		
		if (getLifetime() > 0)
			o.put("expires_in", lifetime);

		if (getScope() != null)
			o.put("scope", scope.toString());

		if (getAuthorizationDetails() != null)
			o.put("authorization_details", AuthorizationDetail.toJSONArray(getAuthorizationDetails()));

		if (getIssuedTokenType() != null) {
			o.put("issued_token_type", getIssuedTokenType().getURI().toString());
		}
		
		return o;
	}


	@Override
	public String toJSONString() {

		return toJSONObject().toString();
	}
	
	
	/**
	 * Returns the {@code Authorization} HTTP request header value for this
	 * access token.
	 *
	 * @return The {@code Authorization} header value.
	 */
	public abstract String toAuthorizationHeader();


	/**
	 * Parses an access token from a JSON object access token response.
	 * Only bearer and DPoP access tokens are supported.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The access token.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        access token.
	 */
	public static AccessToken parse(final JSONObject jsonObject)
		throws ParseException {

		AccessTokenType tokenType = new AccessTokenType(JSONObjectUtils.getString(jsonObject, "token_type"));
		
		if (AccessTokenType.BEARER.equals(tokenType)) {
			return BearerAccessToken.parse(jsonObject);
		} else if (AccessTokenType.DPOP.equals(tokenType)) {
			return DPoPAccessToken.parse(jsonObject);
		} else if (AccessTokenType.N_A.equals(tokenType)) {
			return NAAccessToken.parse(jsonObject);
		} else {
			throw new ParseException("Unsupported token_type: " + tokenType);
		}
	}
	
	
	/**
	 * Parses an {@code Authorization} HTTP request header value for an 
	 * access token. Only bearer access token are supported.
	 *
	 * @param header The {@code Authorization} header value to parse. Must 
	 *               not be {@code null}.
	 *
	 * @return The access token.
	 *
	 * @throws ParseException If the {@code Authorization} header value 
	 *                        couldn't be parsed to an access token.
	 *
	 * @see #parse(String, AccessTokenType)
	 */
	@Deprecated
	public static AccessToken parse(final String header)
		throws ParseException {
	
		return BearerAccessToken.parse(header);
	}
	
	
	/**
	 * Parses an {@code Authorization} HTTP request header value for an
	 * access token. Only bearer and DPoP access token are supported.
	 *
	 * @param header        The {@code Authorization} header value to
	 *                      parse. Must not be {@code null}.
	 * @param preferredType The preferred (primary) access token type.
	 *                      Must be either {@link AccessTokenType#BEARER}
	 *                      or {@link AccessTokenType#DPOP} and not
	 *                      {@code null}.
	 *
	 * @return The access token.
	 *
	 * @throws ParseException If the {@code Authorization} header value
	 *                        couldn't be parsed to an access token.
	 */
	public static AccessToken parse(final String header,
					final AccessTokenType preferredType)
		throws ParseException {
	
		if (! AccessTokenType.BEARER.equals(preferredType) && ! AccessTokenType.DPOP.equals(preferredType)) {
			throw new IllegalArgumentException("Unsupported Authorization scheme: " + preferredType);
		}
		
		if (header != null && header.startsWith(AccessTokenType.BEARER.getValue()) || AccessTokenType.BEARER.equals(preferredType)) {
			return BearerAccessToken.parse(header);
		} else {
			return DPoPAccessToken.parse(header);
		}
	}
	
	
	/**
	 * Parses an HTTP request header value for an access token.
	 *
	 * @param request The HTTP request to parse. Must not be {@code null}.
	 *
	 * @return The access token.
	 *
	 * @throws ParseException If an access token wasn't found in the HTTP
	 *                        request.
	 */
	public static AccessToken parse(final HTTPRequest request)
		throws ParseException {
		
		if (request.getAuthorization() != null) {
			
			AccessTokenType tokenType = AccessTokenUtils.determineAccessTokenTypeFromAuthorizationHeader(request.getAuthorization());
			
			if (AccessTokenType.BEARER.equals(tokenType)) {
				return BearerAccessToken.parse(request.getAuthorization());
			}
			
			if (AccessTokenType.DPOP.equals(tokenType)) {
				return DPoPAccessToken.parse(request.getAuthorization());
			}
			
			throw new ParseException("Couldn't determine access token type from Authorization header");
		}
		
		// Try alternative token locations, form and query string are
		// parameters are not differentiated here
		Map<String, List<String>> params = request.getQueryParameters(); // TODO switch to non-deprecated method
		return new TypelessAccessToken(AccessTokenUtils.parseValueFromQueryParameters(params));
	}
}
