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


import java.util.List;
import java.util.Map;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;


/**
 * DPoP access token.
 *
 * <p>Example DPoP access token serialised to JSON:
 *
 * <pre>
 * {
 *   "access_token" : "aeniniu3oogh2quoot7Aipie9IeGh3te",
 *   "token_type"   : "DPoP",
 *   "expires_in"   : 3600,
 *   "scope"        : "read write"
 * }
 * </pre>
 *
 * <p>The above example token serialised to a HTTP Authorization header:
 *
 * <pre>
 * Authorization: DPoP aeniniu3oogh2quoot7Aipie9IeGh3te
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer
 *         (DPoP) (draft-ietf-oauth-dpop-03)
 * </ul>
 */
@Immutable
public class DPoPAccessToken extends AccessToken {
	
	
	private static final long serialVersionUID = 7745184045632691024L;
	
	
	/**
	 * Creates a new minimal DPoP access token with the specified value.
	 * The optional lifetime and scope are left undefined.
	 *
	 * @param value The access token value. Must not be {@code null} or
	 *              empty string.
	 */
	public DPoPAccessToken(final String value) {
	
		this(value, 0L, null);
	}
	
	
	/**
	 * Creates a new DPoP access token with the specified value and
	 * optional lifetime and scope.
	 *
	 * @param value    The access token value. Must not be {@code null} or
	 *                 empty string.
	 * @param lifetime The lifetime in seconds, 0 if not specified.
	 * @param scope    The scope, {@code null} if not specified.
	 */
	public DPoPAccessToken(final String value, final long lifetime, final Scope scope) {
	
		this(value, lifetime, scope, null);
	}

	/**
	 * Creates a new DPoP access token with the specified value and
	 * optional lifetime and scope.
	 *
	 * @param value           The access token value. Must not be {@code null} or empty string.
	 * @param lifetime        The lifetime in seconds, 0 if not specified.
	 * @param scope           The scope, {@code null} if not specified.
	 * @param issuedTokenType The issuedTokenType, {@code null} if not specified.
	 */
	public DPoPAccessToken(final String value, final long lifetime, final Scope scope,
			final TokenTypeURI issuedTokenType) {

		super(AccessTokenType.DPOP, value, lifetime, scope, issuedTokenType);
	}
	
	
	/**
	 * Returns the HTTP Authorization header value for this DPoP access
	 * token.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * Authorization: DPoP aeniniu3oogh2quoot7Aipie9IeGh3te
	 * </pre>
	 *
	 * @return The HTTP Authorization header.
	 */
	@Override
	public String toAuthorizationHeader(){
	
		return "DPoP " + getValue();
	}
	
	
	@Override
	public boolean equals(final Object object) {
	
		return object instanceof DPoPAccessToken &&
		       this.toString().equals(object.toString());
	}


	/**
	 * Parses a DPoP access token from a JSON object access token
	 * response.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The DPoP access token.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        DPoP access token.
	 */
	public static DPoPAccessToken parse(final JSONObject jsonObject)
		throws ParseException {

		AccessTokenUtils.parseAndEnsureType(jsonObject, AccessTokenType.DPOP);
		String accessTokenValue = AccessTokenUtils.parseValue(jsonObject);
		long lifetime = AccessTokenUtils.parseLifetime(jsonObject);
		Scope scope = AccessTokenUtils.parseScope(jsonObject);
		TokenTypeURI issuedTokenType = AccessTokenUtils.parseIssuedTokenType(jsonObject);
		return new DPoPAccessToken(accessTokenValue, lifetime, scope, issuedTokenType);
	}
	
	
	/**
	 * Parses an HTTP Authorization header for a DPoP access token.
	 *
	 * @param header The HTTP Authorization header value to parse. May be
	 *               {@code null} if the header is missing, in which case
	 *               an exception will be thrown.
	 *
	 * @return The DPoP access token.
	 *
	 * @throws ParseException If the HTTP Authorization header value 
	 *                        couldn't be parsed to a DPoP access token.
	 */
	public static DPoPAccessToken parse(final String header)
		throws ParseException {
		
		return new DPoPAccessToken(AccessTokenUtils.parseValueFromHeader(header, AccessTokenType.DPOP));
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
	public static DPoPAccessToken parse(final Map<String,List<String>> parameters)
		throws ParseException {
		
		return new DPoPAccessToken(AccessTokenUtils.parseValueFromQueryParameters(parameters, AccessTokenType.DPOP));
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
	public static DPoPAccessToken parse(final HTTPRequest request)
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
