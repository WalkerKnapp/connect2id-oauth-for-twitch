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

package com.nimbusds.openid.connect.sdk.claims;


import net.jcip.annotations.Immutable;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.token.AccessToken;


/**
 * Access token hash ({@code at_hash}).
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 * </ul>
 */
@Immutable
public final class AccessTokenHash extends HashClaim {
	
	
	private static final long serialVersionUID = -2260085393906006318L;
	
	
	/**
	 * Checks if an access token hash claim must be included in ID tokens
	 * for the specified response type.
	 *
	 * @param responseType The OpenID Connect response type. Must not be
	 *                     {@code null}.
	 *
	 * @return {@code true} if the access token hash is required, else
	 *         {@code false}.
	 */
	public static boolean isRequiredInIDTokenClaims(final ResponseType responseType) {

		// Only required in implicit flow for 'token id_token' and
		// hybrid flow for 'code id_token token'
		// Disregard authz / token endpoint!
		return ResponseType.IDTOKEN_TOKEN.equals(responseType) || ResponseType.CODE_IDTOKEN_TOKEN.equals(responseType);

	}


	/**
	 * Creates a new access token hash with the specified value.
	 *
	 * @param value The access token hash value. Must not be {@code null}.
	 */
	public AccessTokenHash(final String value) {
	
		super(value);
	}


	/**
	 * Computes the hash for the specified access token and reference JSON
	 * Web Signature (JWS) algorithm.
	 *
	 * @param accessToken The access token. Must not be {@code null}.
	 * @param alg         The reference JWS algorithm. Must not be
	 *                    {@code null}.
	 *
	 * @return The access token hash, or {@code null} if the JWS algorithm
	 *         is not supported.
	 *
	 * @deprecated Use {@link #compute(AccessToken, JWSAlgorithm, Curve)}
	 * instead.
	 */
	@Deprecated
	public static AccessTokenHash compute(final AccessToken accessToken, final JWSAlgorithm alg) {

		String value = computeValue(accessToken, alg);

		if (value == null)
			return null;

		return new AccessTokenHash(value);
	}


	/**
	 * Computes the hash for the specified access token and reference JSON
	 * Web Signature (JWS) algorithm.
	 *
	 * @param accessToken The access token. Must not be {@code null}.
	 * @param alg         The reference JWS algorithm. Must not be
	 *                    {@code null}.
	 * @param crv         The JWK curve used with the JWS algorithm,
	 *                    {@code null} if not applicable.
	 *
	 * @return The access token hash, or {@code null} if the JWS algorithm
	 *         is not supported.
	 */
	public static AccessTokenHash compute(final AccessToken accessToken,
					      final JWSAlgorithm alg,
					      final Curve crv) {

		String value = computeValue(accessToken, alg, crv);

		if (value == null)
			return null;

		return new AccessTokenHash(value);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof AccessTokenHash &&
		       this.toString().equals(object.toString());
	}
}
