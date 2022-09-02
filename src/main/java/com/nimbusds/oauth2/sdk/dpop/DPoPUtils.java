/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.oauth2.sdk.dpop;


import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.openid.connect.sdk.Nonce;


/**
 * DPoP utilities.
 */
public final class DPoPUtils {
	
	
	/**
	 * Creates a new DPoP JWT claims set.
	 *
	 * @param jti         The JWT ID. Must not be {@code null}.
	 * @param htm         The HTTP request method. Must not be
	 *                    {@code null}.
	 * @param htu         The HTTP URI, without a query or fragment. Must
	 *                    not be {@code null}.
	 * @param iat         The issue time. Must not be {@code null}.
	 * @param accessToken The access token for the access token hash
	 *                    ("ath") claim computation, {@code null} if not
	 *                    specified.
	 *
	 * @return The JWT claims set.
	 *
	 * @throws JOSEException If a cryptographic exception was encountered.
	 */
	@Deprecated
	public static JWTClaimsSet createJWTClaimsSet(final JWTID jti,
					              final String htm,
					              final URI htu,
					              final Date iat,
					              final AccessToken accessToken)
		throws JOSEException {
		
		return createJWTClaimsSet(jti, htm, htu, iat, accessToken, null);
	}
	
	
	/**
	 * Creates a new DPoP JWT claims set.
	 *
	 * @param jti         The JWT ID. Must not be {@code null}.
	 * @param htm         The HTTP request method. Must not be
	 *                    {@code null}.
	 * @param htu         The HTTP URI, without a query or fragment. Must
	 *                    not be {@code null}.
	 * @param iat         The issue time. Must not be {@code null}.
	 * @param accessToken The access token for the access token hash
	 *                    ("ath") claim computation, {@code null} if not
	 *                    specified.
	 * @param nonce       The nonce, {@code null} if not specified.
	 *
	 * @return The JWT claims set.
	 *
	 * @throws JOSEException If a cryptographic exception was encountered.
	 */
	public static JWTClaimsSet createJWTClaimsSet(final JWTID jti,
						      final String htm,
						      final URI htu,
						      final Date iat,
						      final AccessToken accessToken,
						      final Nonce nonce)
		throws JOSEException {
		
		if (StringUtils.isBlank(htm)) {
			throw new IllegalArgumentException("The HTTP method (htu) is required");
		}
		
		if (htu.getQuery() != null) {
			throw new IllegalArgumentException("The HTTP URI (htu) must not have a query");
		}
		
		if (htu.getFragment() != null) {
			throw new IllegalArgumentException("The HTTP URI (htu) must not have a fragment");
		}
		
		if (iat == null) {
			throw new IllegalArgumentException("The issue time (iat) is required");
		}
		
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
			.jwtID(jti.getValue())
			.claim("htm", htm)
			.claim("htu", htu.toString())
			.issueTime(iat);
		
		if (accessToken != null) {
			builder = builder.claim("ath", computeSHA256(accessToken).toString());
		}
		
		if (nonce != null) {
			builder = builder.claim("nonce", nonce.getValue());
		}
		
		return builder.build();
	}
	
	
	/**
	 * Computes a SHA-256 hash for the specified access token.
	 *
	 * @param accessToken The access token. Must not be {@code null}.
	 *
	 * @return The hash, BASE64 URL encoded.
	 *
	 * @throws JOSEException If hashing failed.
	 */
	public static Base64URL computeSHA256(final AccessToken accessToken)
		throws JOSEException {
		
		byte[] hash;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			hash = md.digest(accessToken.getValue().getBytes(StandardCharsets.UTF_8));
		} catch (NoSuchAlgorithmException e) {
			throw new JOSEException(e.getMessage(), e);
		}
		
		return Base64URL.encode(hash);
	}
	
	
      /**
       *Prevents public instantiation.
       */
      private DPoPUtils() {}
}
