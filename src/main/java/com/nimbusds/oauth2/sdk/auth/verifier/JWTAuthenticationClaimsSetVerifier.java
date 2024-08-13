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

package com.nimbusds.oauth2.sdk.auth.verifier;


import java.util.Set;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionDetailsVerifier;
import com.nimbusds.oauth2.sdk.id.Audience;


/**
 * JWT client authentication claims set verifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523).
 * </ul>
 */
@Immutable
class JWTAuthenticationClaimsSetVerifier extends JWTAssertionDetailsVerifier {

	// Cache JWT exceptions for quick processing of bad claims

	/**
	 * Missing or invalid JWT claim exception.
	 */
	private static final BadJWTException ISS_SUB_MISMATCH_EXCEPTION =
		new BadJWTException("Issuer and subject JWT claims don't match");


	/**
	 * Creates a new JWT client authentication claims set verifier.
	 *
	 * @param expectedAudience The permitted audience (aud) claim values.
	 *                         Must not be empty or {@code null}. Should
	 *                         typically contain the token endpoint URI and
	 *                         for OpenID provider it may also include the
	 *                         issuer URI.
	 */
	public JWTAuthenticationClaimsSetVerifier(final Set<Audience> expectedAudience) {
		this(expectedAudience, -1L);
	}


	/**
	 * Creates a new JWT client authentication claims set verifier.
	 *
	 * @param expectedAudience The permitted audience (aud) claim values.
	 *                         Must not be empty or {@code null}. Should
	 *                         typically contain the token endpoint URI and
	 *                         for OpenID provider it may also include the
	 *                         issuer URI.
	 * @param expMaxAhead      The maximum number of seconds the expiration
	 *                         time (exp) claim can be ahead of the current
	 *                         time, if zero or negative this check is
	 *                         disabled.
	 */
	public JWTAuthenticationClaimsSetVerifier(final Set<Audience> expectedAudience,
						  final long expMaxAhead) {
		super(expectedAudience, expMaxAhead);
	}


	@Override
	public void verify(final JWTClaimsSet claimsSet, final SecurityContext securityContext)
		throws BadJWTException {

		super.verify(claimsSet, securityContext);

		// iss == sub
		if (! claimsSet.getIssuer().equals(claimsSet.getSubject())) {
			throw ISS_SUB_MISMATCH_EXCEPTION;
		}
	}
}
