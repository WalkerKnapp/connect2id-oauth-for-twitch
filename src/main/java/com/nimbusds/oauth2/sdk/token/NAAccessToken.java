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


import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;


/**
 * Access token of type not applicable (N/A), intended for use in OAuth 2.0
 * token exchange scenarios.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Token Exchange (RFC 8693)
 * </ul>
 */
@Immutable
public class NAAccessToken extends AccessToken {
	
	
	private static final long serialVersionUID = 268047904352224888L;
	
	
	/**
	 * Creates a new N/A access token with the specified value.
	 *
	 * @param value           The access token value. Must not be
	 *                        {@code null} or empty string.
	 * @param lifetime        The lifetime in seconds, 0 if not specified.
	 * @param scope           The scope, {@code null} if not specified.
	 * @param issuedTokenType The token type URI, {@code null} if not
	 *                        specified.
	 */
	public NAAccessToken(final String value, final long lifetime, final Scope scope, final TokenTypeURI issuedTokenType) {
		
		super(AccessTokenType.N_A, value, lifetime, scope, issuedTokenType);
	}
	
	
	@Override
	public String toAuthorizationHeader() {
		throw new UnsupportedOperationException();
	}
	
	
	/**
	 * Parses a N/A access token from a JSON object access token response.
	 *
	 * @param jsonObject The JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The N/A access token.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        N/A access token.
	 */
	public static NAAccessToken parse(final JSONObject jsonObject)
		throws ParseException {
		
		AccessTokenUtils.parseAndEnsureType(jsonObject, AccessTokenType.N_A);
		String accessTokenValue = AccessTokenUtils.parseValue(jsonObject);
		long lifetime = AccessTokenUtils.parseLifetime(jsonObject);
		Scope scope = AccessTokenUtils.parseScope(jsonObject);
		TokenTypeURI issuedTokenType = AccessTokenUtils.parseIssuedTokenType(jsonObject);
		return new NAAccessToken(accessTokenValue, lifetime, scope, issuedTokenType);
	}
}
