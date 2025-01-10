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


import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import net.jcip.annotations.Immutable;

import java.util.Arrays;
import java.util.Date;
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
 *     <li>Expiration time too far ahead check (optional)
 *     <li>Not-before time check (if set)
 *     <li>Subject and issuer presence check
 * </ul>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523)
 * </ul>
 */
@Immutable
public class JWTAssertionDetailsVerifier extends DefaultJWTClaimsVerifier {


	/**
	 * The expected audience.
	 */
	private final Set<Audience> expectedAudience;


	/**
	 * The maximum number of seconds the expiration time can be ahead of
	 * the current time.
	 */
	private final long expMaxAhead;


	/**
	 * Creates a new JWT bearer assertion details (claims set) verifier.
	 *
	 * @param aud The permitted audience (aud) claim. Must not be empty or
	 *            {@code null}. Should be the identity of the recipient,
	 *            such as the issuer URI for an OpenID provider.
	 */
	public JWTAssertionDetailsVerifier(final Set<Audience> aud) {

		this(aud, -1L);
	}


	/**
	 * Creates a new JWT bearer assertion details (claims set) verifier.
	 *
	 * @param aud         The permitted audience (aud) claim. Must not be
	 *                    empty or {@code null}. Should be the identity of
	 *                    the recipient, such as the issuer URI for an
	 *                    OpenID provider.
	 * @param expMaxAhead The maximum number of seconds the expiration time
	 *                    (exp) claim can be ahead of the current time, if
	 *                    zero or negative this check is disabled.
	 */
	public JWTAssertionDetailsVerifier(final Set<Audience> aud,
					   final long expMaxAhead) {

		super(
                        new HashSet<>(Identifier.toStringList(aud)),
			null,
                        new HashSet<>(Arrays.asList("aud", "exp", "sub", "iss")),
			null);

		if (CollectionUtils.isEmpty(aud)) {
			throw new IllegalArgumentException("The expected audience set must not be null or empty");
		}

		this.expectedAudience = aud;

		this.expMaxAhead = expMaxAhead;
	}


	/**
	 * Returns the expected audience values.
	 *
	 * @return The expected audience (aud) claim values.
	 */
	@Deprecated
	public Set<Audience> getExpectedAudience() {

		return expectedAudience;
	}


	/**
	 * Returns the maximum number of seconds the expiration time (exp)
	 * claim can be ahead of the current time.
	 *
	 * @return The maximum number of seconds, if zero or negative this
	 *         check is disabled.
	 */
	public long getExpirationTimeMaxAhead() {

		return expMaxAhead;
	}


	@Override
	public void verify(final JWTClaimsSet claimsSet, final SecurityContext context)
		throws BadJWTException {

		super.verify(claimsSet, context);

		if (expMaxAhead > 0) {
			long now = DateUtils.toSecondsSinceEpoch(new Date());
			long exp = DateUtils.toSecondsSinceEpoch(claimsSet.getExpirationTime());
			if (now + expMaxAhead < exp) {
				throw new BadJWTException("JWT expiration too far ahead");
			}
		}
	}
}
