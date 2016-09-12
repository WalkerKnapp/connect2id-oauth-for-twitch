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

package com.nimbusds.oauth2.sdk;


import java.util.LinkedHashMap;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.token.RefreshToken;


/**
 * Refresh token grant. Used in refresh token requests.
 *
 * <p>Note that the optional scope parameter is not supported.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 6.
 * </ul>
 */
@Immutable
public class RefreshTokenGrant extends AuthorizationGrant {


	/**
	 * The grant type.
	 */
	public static final GrantType GRANT_TYPE = GrantType.REFRESH_TOKEN;


	/**
	 * The refresh token.
	 */
	private final RefreshToken refreshToken;


	/**
	 * Creates a new refresh token grant.
	 *
	 * @param refreshToken The refresh token. Must not be {@code null}.
	 */
	public RefreshTokenGrant(final RefreshToken refreshToken) {


		super(GRANT_TYPE);

		if (refreshToken == null)
			throw new IllegalArgumentException("The refresh token must not be null");

		this.refreshToken = refreshToken;
	}


	/**
	 * Gets the refresh token.
	 *
	 * @return The refresh token.
	 */
	public RefreshToken getRefreshToken() {

		return refreshToken;
	}


	@Override
	public Map<String,String> toParameters() {

		Map<String,String> params = new LinkedHashMap<>();
		params.put("grant_type", GRANT_TYPE.getValue());
		params.put("refresh_token", refreshToken.getValue());
		return params;
	}


	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		RefreshTokenGrant grant = (RefreshTokenGrant) o;

		return refreshToken.equals(grant.refreshToken);

	}


	@Override
	public int hashCode() {
		return refreshToken.hashCode();
	}


	/**
	 * Parses a refresh token grant from the specified parameters.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * grant_type=refresh_token
	 * refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
	 * </pre>
	 *
	 * @param params The parameters.
	 *
	 * @return The refresh token grant.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static RefreshTokenGrant parse(final Map<String,String> params)
		throws ParseException {

		// Parse grant type
		String grantTypeString = params.get("grant_type");

		if (grantTypeString == null)
			throw new ParseException("Missing \"grant_type\" parameter", OAuth2Error.INVALID_REQUEST);

		if (! GrantType.parse(grantTypeString).equals(GRANT_TYPE))
			throw new ParseException("The \"grant_type\" must be " + GRANT_TYPE, OAuth2Error.UNSUPPORTED_GRANT_TYPE);

		// Parse refresh token
		String refreshTokenString = params.get("refresh_token");

		if (refreshTokenString == null || refreshTokenString.trim().isEmpty())
			throw new ParseException("Missing or empty \"refresh_token\" parameter", OAuth2Error.INVALID_REQUEST);

		RefreshToken refreshToken = new RefreshToken(refreshTokenString);

		return new RefreshTokenGrant(refreshToken);
	}
}
