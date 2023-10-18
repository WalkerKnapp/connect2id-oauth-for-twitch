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

package com.nimbusds.oauth2.sdk.assertions.jwt;


import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import net.jcip.annotations.Immutable;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;


/**
 * JSON Web Token (JWT) bearer assertion details (claims set) verifier for
 * OAuth 2.0 client authentication and authorisation grants. Intended for
 * initial validation of JWT assertions:
 *
 * <ul>
 *     <li>Audience check
 *     <li>Expiration time check
 *     <li>Not-before time check (is set)
 *     <li>Subject and issuer presence check
 * </ul>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523).
 * </ul>
 */
@Immutable
public class JWTAssertionDetailsVerifier extends DefaultJWTClaimsVerifier {


	/**
	 * The expected audience.
	 */
	private final Set<Audience> expectedAudience;


	/**
	 * Creates a new JWT bearer assertion details (claims set) verifier.
	 *
	 * @param expectedAudience The expected audience (aud) claim values.
	 *                         Must not be empty or {@code null}. Should
	 *                         typically contain the token endpoint URI and
	 *                         for OpenID provider it may also include the
	 *                         issuer URI.
	 */
	public JWTAssertionDetailsVerifier(final Set<Audience> expectedAudience) {

		super(
                        new HashSet<>(Identifier.toStringList(expectedAudience)),
			null,
                        new HashSet<>(Arrays.asList("aud", "exp", "sub", "iss")),
			null);

		if (CollectionUtils.isEmpty(expectedAudience)) {
			throw new IllegalArgumentException("The expected audience set must not be null or empty");
		}

		this.expectedAudience = expectedAudience;
	}


	/**
	 * Returns the expected audience values.
	 *
	 * @return The expected audience (aud) claim values.
	 */
	public Set<Audience> getExpectedAudience() {

		return expectedAudience;
	}
}
