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

package com.nimbusds.oauth2.sdk.dpop.verifiers;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.util.singleuse.SingleUseChecker;
import com.nimbusds.openid.connect.sdk.Nonce;
import net.jcip.annotations.ThreadSafe;

import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Set;


/**
 * DPoP proof JWT verifier for the OAuth 2.0 token endpoint of an authorisation
 * server.
 */
@ThreadSafe
public class DPoPTokenRequestVerifier extends DPoPCommonVerifier {
	
	
	/**
	 * The token endpoint URI.
	 */
	private final URI endpointURI;
	
	
	/**
	 * Creates a new DPoP proof JWT verifier for the OAuth 2.0 token
	 * endpoint.
	 *
	 * @param acceptedJWSAlgs     The accepted JWS algorithms. Must be
	 *                            supported and not {@code null}.
	 * @param endpointURI         The token endpoint URI. Any query or
	 *                            fragment component will be stripped from
	 *                            it before performing the comparison. Must
	 *                            not be {@code null}.
	 * @param maxClockSkewSeconds The max acceptable clock skew for the
	 *                            "iat" (issued-at) claim checks, in
	 *                            seconds. Should be in the order of a few
	 *                            seconds.
	 * @param singleUseChecker    The single use checker for the DPoP proof
	 *                            "jti" (JWT ID) claims, {@code null} if
	 *                            not specified.
	 */
	public DPoPTokenRequestVerifier(final Set<JWSAlgorithm> acceptedJWSAlgs,
					final URI endpointURI,
					final long maxClockSkewSeconds,
					final SingleUseChecker<Map.Entry<DPoPIssuer, JWTID>> singleUseChecker) {
		
		super(acceptedJWSAlgs, maxClockSkewSeconds, singleUseChecker);
		this.endpointURI = Objects.requireNonNull(endpointURI);
	}
	
	
	/**
	 * Verifies the specified DPoP proof and returns the DPoP JWK SHA-256
	 * thumbprint confirmation.
	 *
	 * @param issuer Unique identifier for the DPoP proof issuer, typically
	 *               as its client ID. Must not be {@code null}.
	 * @param proof  The DPoP proof JWT. Must not be {@code null}.
	 *
	 * @return The DPoP JWK SHA-256 thumbprint confirmation.
	 *
	 * @throws InvalidDPoPProofException If the DPoP proof is invalid.
	 * @throws JOSEException             If an internal JOSE exception is
	 *                                   encountered.
	 */
	@Deprecated
	public JWKThumbprintConfirmation verify(final DPoPIssuer issuer, final SignedJWT proof)
		throws InvalidDPoPProofException, JOSEException {
		
		return verify(issuer, proof, null);
	}
	
	
	/**
	 * Verifies the specified DPoP proof and returns the DPoP JWK SHA-256
	 * thumbprint confirmation.
	 *
	 * @param issuer Unique identifier for the DPoP proof issuer, typically
	 *               as its client ID. Must not be {@code null}.
	 * @param proof  The DPoP proof JWT. Must not be {@code null}.
	 * @param nonce  The expected DPoP proof JWT nonce, {@code null} if
	 *               none.
	 *
	 * @return The DPoP JWK SHA-256 thumbprint confirmation.
	 *
	 * @throws InvalidDPoPProofException If the DPoP proof is invalid.
	 * @throws JOSEException             If an internal JOSE exception is
	 *                                   encountered.
	 */
	public JWKThumbprintConfirmation verify(final DPoPIssuer issuer, final SignedJWT proof, final Nonce nonce)
		throws InvalidDPoPProofException, JOSEException {
		
		try {
			super.verify("POST", endpointURI, issuer, proof, null, null, nonce);
		} catch (AccessTokenValidationException e) {
			throw new RuntimeException("Unexpected exception", e);
		}
		
		return new JWKThumbprintConfirmation(proof.getHeader().getJWK().computeThumbprint());
	}
}
