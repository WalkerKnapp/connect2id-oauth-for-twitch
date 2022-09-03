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


import java.net.URI;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DPoPUtils;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import com.nimbusds.oauth2.sdk.util.singleuse.SingleUseChecker;
import com.nimbusds.openid.connect.sdk.Nonce;


/**
 * DPoP proof JWT and access token binding verifier.
 */
@ThreadSafe
class DPoPCommonVerifier {
	
	
	/**
	 * The supported JWS algorithms for the DPoP proof JWTs.
	 */
	public static final Set<JWSAlgorithm> SUPPORTED_JWS_ALGORITHMS;
	
	static {
		Set<JWSAlgorithm> supported = new HashSet<>();
		supported.addAll(JWSAlgorithm.Family.EC);
		supported.addAll(JWSAlgorithm.Family.RSA);
		SUPPORTED_JWS_ALGORITHMS = Collections.unmodifiableSet(supported);
	}
	
	private final Set<JWSAlgorithm> acceptedJWSAlgs;
	
	private final long maxClockSkewSeconds;
	
	private final SingleUseChecker<Map.Entry<DPoPIssuer, JWTID>> singleUseChecker;
	
	
	/**
	 * Creates a new DPoP proof JWT verifier.
	 *
	 * @param acceptedJWSAlgs     The accepted JWS algorithms. Must be
	 *                            supported and not {@code null}.
	 * @param maxClockSkewSeconds The max acceptable clock skew for the
	 *                            "iat" (issued-at) claim checks, in
	 *                            seconds. Should be in the order of a few
	 *                            seconds.
	 * @param singleUseChecker    The single use checker for the DPoP proof
	 *                            "jti" (JWT ID) claims, {@code null} if
	 *                            not specified.
	 */
	DPoPCommonVerifier(final Set<JWSAlgorithm> acceptedJWSAlgs,
			   final long maxClockSkewSeconds,
			   final SingleUseChecker<Map.Entry<DPoPIssuer, JWTID>> singleUseChecker) {
		
		if (! SUPPORTED_JWS_ALGORITHMS.containsAll(acceptedJWSAlgs)) {
			throw new IllegalArgumentException("Unsupported JWS algorithms: " + acceptedJWSAlgs.retainAll(SUPPORTED_JWS_ALGORITHMS));
		}
		this.acceptedJWSAlgs = acceptedJWSAlgs;
		
		this.maxClockSkewSeconds = maxClockSkewSeconds;
		
		this.singleUseChecker = singleUseChecker;
	}
	
	
	/**
	 * Verifies the specified DPoP proof for a token or protected resource
	 * request.
	 *
	 * @param method      The HTTP request method (case-insensitive). Must
	 *                    not be {@code null}.
	 * @param uri         The HTTP URI. Any query or fragment component
	 *                    will be stripped from it before DPoP validation.
	 *                    Must not be {@code null}.
	 * @param issuer      Unique identifier for the DPoP proof issuer,
	 *                    such as its client ID. Must not be {@code null}.
	 * @param proof       The DPoP proof JWT. Must not be {@code null}.
	 * @param accessToken The received and successfully validated DPoP
	 *                    access token for a protected resource request,
	 *                    {@code null} if not applicable.
	 * @param cnf         The JWK SHA-256 thumbprint confirmation for the
	 *                    DPoP access token, {@code null} if none.
	 * @param nonce       The expected DPoP proof JWT nonce, {@code null}
	 *                    if none.
	 *
	 * @throws InvalidDPoPProofException      If the DPoP proof is invalid.
	 * @throws AccessTokenValidationException If an access token is
	 *                                        expected and its validation
	 *                                        failed.
	 * @throws JOSEException                  If an internal JOSE exception
	 *                                        is encountered.
	 */
	void verify(final String method,
		    final URI uri,
		    final DPoPIssuer issuer,
		    final SignedJWT proof,
		    final DPoPAccessToken accessToken,
		    final JWKThumbprintConfirmation cnf,
		    final Nonce nonce)
		throws
		InvalidDPoPProofException,
		AccessTokenValidationException,
		JOSEException {
		
		if (StringUtils.isBlank(method)) {
			throw new IllegalArgumentException("The HTTP request method must not be null or blank");
		}
		
		if (uri == null) {
			throw new IllegalArgumentException("The HTTP URI must not be null");
		}
		
		DefaultJWTProcessor<DPoPProofContext> proc = new DefaultJWTProcessor<>();
		
		// Check JWS header "typ"
		proc.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<DPoPProofContext>(DPoPProofFactory.TYPE));
		
		// Use the JWK embedded into the header to validate the JWT signature
		proc.setJWSKeySelector(new DPoPKeySelector(acceptedJWSAlgs));
		
		// Validate the JWT claims
		proc.setJWTClaimsSetVerifier(new DPoPProofClaimsSetVerifier(
			URIUtils.getBaseURI(uri), method,
			nonce,
			maxClockSkewSeconds,
			accessToken != null,
			singleUseChecker
		));
		
		DPoPProofContext context = new DPoPProofContext(issuer);
		try {
			proc.process(proof, context);
		} catch (BadJOSEException | KeySourceException e) {
			throw new InvalidDPoPProofException("Invalid DPoP proof: " + e.getMessage(), e);
		}
		
		if (accessToken != null) {
			
			// Protected resource request
			
			Base64URL accessTokenHash = DPoPUtils.computeSHA256(accessToken);
			
			// Check the DPoP proof - access token binding
			if (! context.getAccessTokenHash().equals(accessTokenHash)) {
				throw new AccessTokenValidationException("The access token hash doesn't match the JWT ath claim");
			}
			
			// Check the DPoP proof - access token cnf.jkt binding
			if (! proof.getHeader().getJWK().computeThumbprint().equals(cnf.getValue())) {
				throw new AccessTokenValidationException("The DPoP proof JWK doesn't match the JWK SHA-256 thumbprint confirmation");
			}
		}
	}
}
