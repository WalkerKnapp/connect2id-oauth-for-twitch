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
import java.util.Date;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;


/**
 * DPoP proof JWT factory.
 */
public interface DPoPProofFactory {
	
	
	/**
	 * The DPoP JWT (typ) type.
	 */
	JOSEObjectType TYPE = new JOSEObjectType("dpop+jwt");
	
	
	/**
	 * The minimal required JWT ID (jti) length, 12 bytes (96 bits).
	 */
	int MINIMAL_JTI_BYTE_LENGTH = 96 / 8;
	
	
	/**
	 * Creates a new DPoP proof.
	 *
	 * @param htm The HTTP request method. Must not be {@code null}.
	 * @param htu The HTTP URI, without a query or fragment. Must not be
	 *            {@code null}.
	 *
	 * @return The signed DPoP JWT.
	 *
	 * @throws JOSEException If signing failed.
	 */
	SignedJWT createDPoPJWT(final String htm,
				final URI htu)
		throws JOSEException;
	
	
	/**
	 * Creates a new DPoP proof.
	 *
	 * @param htm The HTTP request method. Must not be {@code null}.
	 * @param htu The HTTP URI, without a query or fragment. Must not be
	 *            {@code null}.
	 * @param nonce The nonce, {@code null} if not specified.
	 *
	 * @return The signed DPoP JWT.
	 *
	 * @throws JOSEException If signing failed.
	 */
	SignedJWT createDPoPJWT(final String htm,
				final URI htu,
				final Nonce nonce)
		throws JOSEException;
	
	
	/**
	 * Creates a new DPoP proof.
	 *
	 * @param htm         The HTTP request method. Must not be
	 *                    {@code null}.
	 * @param htu         The HTTP URI, without a query or fragment. Must
	 *                    not be {@code null}.
	 * @param accessToken The access token for the access token hash
	 *                    ("ath") claim computation, {@code null} if not
	 *                    specified.
	 *
	 * @return The signed DPoP JWT.
	 *
	 * @throws JOSEException If signing failed.
	 */
	SignedJWT createDPoPJWT(final String htm,
				final URI htu,
				final AccessToken accessToken)
		throws JOSEException;
	
	
	/**
	 * Creates a new DPoP proof.
	 *
	 * @param htm         The HTTP request method. Must not be
	 *                    {@code null}.
	 * @param htu         The HTTP URI, without a query or fragment. Must
	 *                    not be {@code null}.
	 * @param accessToken The access token for the access token hash
	 *                    ("ath") claim computation, {@code null} if not
	 *                    specified.
	 * @param nonce       The nonce, {@code null} if not specified.
	 *
	 * @return The signed DPoP JWT.
	 *
	 * @throws JOSEException If signing failed.
	 */
	SignedJWT createDPoPJWT(final String htm,
				final URI htu,
				final AccessToken accessToken,
				final Nonce nonce)
		throws JOSEException;
	
	
	/**
	 * Creates a new DPoP proof.
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
	 * @return The signed DPoP JWT.
	 *
	 * @throws JOSEException If signing failed.
	 */
	@Deprecated
	SignedJWT createDPoPJWT(final JWTID jti,
				final String htm,
				final URI htu,
				final Date iat,
				final AccessToken accessToken)
		throws JOSEException;
	
	
	/**
	 * Creates a new DPoP proof.
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
	 * @return The signed DPoP JWT.
	 *
	 * @throws JOSEException If signing failed.
	 */
	SignedJWT createDPoPJWT(final JWTID jti,
				final String htm,
				final URI htu,
				final Date iat,
				final AccessToken accessToken,
				final Nonce nonce)
		throws JOSEException;
}
