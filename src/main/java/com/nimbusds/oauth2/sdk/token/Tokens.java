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
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.minidev.json.JSONObject;

import java.util.*;


/**
 * Access and optional refresh token.
 */
public class Tokens {


	/**
	 * Access token.
	 */
	private final AccessToken accessToken;


	/**
	 * Refresh token, {@code null} if not specified.
	 */
	private final RefreshToken refreshToken;
	
	
	/**
	 * Optional token metadata, intended for server environments.
	 */

	private final Map<String,Object> metadata = new HashMap<>();


	/**
	 * Creates a new tokens instance.
	 *
	 * @param accessToken  The access token. Must not be {@code null}.
	 * @param refreshToken The refresh token. If none {@code null}.
	 */
	public Tokens(final AccessToken accessToken, final RefreshToken refreshToken) {

		this.accessToken = Objects.requireNonNull(accessToken);
		this.refreshToken = refreshToken;
	}
	

	/**
	 * Returns the access token.
	 *
	 * @return The access token.
	 */
	public AccessToken getAccessToken() {

		return accessToken;
	}


	/**
	 * Returns the access token as type bearer.
	 *
	 * @return The bearer access token, {@code null} if the type is
	 *         different.
	 */
	public BearerAccessToken getBearerAccessToken() {

		if (accessToken instanceof BearerAccessToken) {
			return (BearerAccessToken) accessToken;
		}
		
		if (AccessTokenType.BEARER.equals(accessToken.getType())) {
			// Create from AccessToken with Bearer access token type
			return new BearerAccessToken(
				accessToken.getValue(),
				accessToken.getLifetime(),
				accessToken.getScope(),
				accessToken.getAuthorizationDetails(),
				accessToken.getIssuedTokenType()
			);
		}

		return null;
	}
	
	
	/**
	 * Returns the access token as type DPoP.
	 *
	 * @return The DPoP access token, {@code null} if the type is
	 *         different.
	 */
	public DPoPAccessToken getDPoPAccessToken() {
		
		if (accessToken instanceof DPoPAccessToken) {
			// Cast
			return (DPoPAccessToken) accessToken;
		}
		
		if (AccessTokenType.DPOP.equals(accessToken.getType())) {
			// Create from AccessToken with DPoP access token type
			return new DPoPAccessToken(
				accessToken.getValue(),
				accessToken.getLifetime(),
				accessToken.getScope(),
				accessToken.getAuthorizationDetails(),
				accessToken.getIssuedTokenType()
			);
		}
		
		return null;
	}


	/**
	 * Returns the optional refresh token.
	 *
	 * @return The refresh token, {@code null} if none.
	 */
	public RefreshToken getRefreshToken() {

		return refreshToken;
	}


	/**
	 * Returns the token parameter names for the included tokens.
	 *
	 * @return The token parameter names.
	 */
	public Set<String> getParameterNames() {

		// Get the std param names for the access + refresh token
		Set<String> paramNames = accessToken.getParameterNames();

		if (refreshToken != null)
			paramNames.addAll(refreshToken.getParameterNames());

		return Collections.unmodifiableSet(paramNames);
	}
	
	
	/**
	 * Returns the optional modifiable token metadata. Intended for server
	 * environments.
	 *
	 * @return The token metadata.
	 */
	public Map<String, Object> getMetadata() {

		return metadata;
	}


	/**
	 * Returns the JSON object representation of this token pair.
	 *
	 * <p>Example JSON object:
	 *
	 * <pre>
	 * {
	 *   "access_token"  : "dZdt8BlltORMTz5U",
	 *   "refresh_token" : "E87zjAoeNXaSoF1U"
	 * }
	 * </pre>
	 *
	 * @return The JSON object representation.
	 */
	public JSONObject toJSONObject() {

		JSONObject o = accessToken.toJSONObject();

		if (refreshToken != null)
			o.putAll(refreshToken.toJSONObject());

		return o;
	}
	
	
	/**
	 * Casts to OpenID Connect tokens.
	 *
	 * @return The OpenID Connect tokens (including an ID token).
	 */
	public OIDCTokens toOIDCTokens() {
		
		return (OIDCTokens)this;
	}


	@Override
	public String toString() {

		return toJSONObject().toJSONString();
	}


	/**
	 * Parses an access and optional refresh token from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The tokens.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        tokens instance.
	 */
	public static Tokens parse(final JSONObject jsonObject)
		throws ParseException {

		return new Tokens(AccessToken.parse(jsonObject), RefreshToken.parse(jsonObject));
	}
}
