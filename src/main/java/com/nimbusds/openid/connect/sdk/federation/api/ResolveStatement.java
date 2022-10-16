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

package com.nimbusds.openid.connect.sdk.federation.api;


import net.jcip.annotations.Immutable;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.federation.utils.JWTUtils;


/**
 * Resolve statement.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 7.2.2.
 * </ul>
 */
@Immutable
public final class ResolveStatement {
	
	
	/**
	 * The resolve statement JOSE object type
	 * ({@code resolve-response+jwt}).
	 */
	public static final JOSEObjectType JOSE_OBJECT_TYPE = new JOSEObjectType("resolve-response+jwt");
	
	
	/**
	 * The resolve response content type
	 * ({@code application/resolve-response+jwt}).
	 */
	public static final ContentType CONTENT_TYPE = new ContentType("application", JOSE_OBJECT_TYPE.getType());
	
	
	/**
	 * The signed statement as signed JWT.
	 */
	private final SignedJWT statementJWT;
	
	
	/**
	 * The statement claims.
	 */
	private final ResolveClaimsSet claimsSet;
	
	
	/**
	 * Creates a new resolve statement.
	 *
	 * @param statementJWT The signed statement as signed JWT. Must not be
	 *                     {@code null}.
	 * @param claimsSet    The statement claims. Must not be {@code null}.
	 */
	private ResolveStatement(final SignedJWT statementJWT,
				 final ResolveClaimsSet claimsSet) {
		
		if (statementJWT == null) {
			throw new IllegalArgumentException("The entity statement must not be null");
		}
		if (JWSObject.State.UNSIGNED.equals(statementJWT.getState())) {
			throw new IllegalArgumentException("The statement is not signed");
		}
		this.statementJWT = statementJWT;
		
		if (claimsSet == null) {
			throw new IllegalArgumentException("The entity statement claims set must not be null");
		}
		this.claimsSet = claimsSet;
	}
	
	
	/**
	 * Returns the signed statement.
	 *
	 * @return The signed statement as signed JWT.
	 */
	public SignedJWT getSignedStatement() {
		return statementJWT;
	}
	
	
	/**
	 * Returns the statement claims.
	 *
	 * @return The statement claims.
	 */
	public ResolveClaimsSet getClaimsSet() {
		return claimsSet;
	}
	
	
	/**
	 * Verifies the signature and checks the statement type, issue and
	 * expiration times.
	 *
	 * @param jwkSet The JWK set to use for the signature verification.
	 *               Must not be {@code null}.
	 *
	 * @return The SHA-256 thumbprint of the key used to successfully
	 *         verify the signature.
	 *
	 * @throws BadJOSEException If the signature is invalid or the
	 *                          statement is expired or before the issue
	 *                          time.
	 * @throws JOSEException    On an internal JOSE exception.
	 */
	public Base64URL verifySignature(final JWKSet jwkSet)
		throws BadJOSEException, JOSEException {
		
		return JWTUtils.verifySignature(
			statementJWT,
			JOSE_OBJECT_TYPE,
			new ResolveClaimsVerifier(),
			jwkSet);
	}
	
	
	/**
	 * Signs the specified resolve claims set.
	 *
	 * @param claimsSet  The claims set. Must not be {@code null}.
	 * @param signingJWK The private signing JWK. Must be contained in the
	 *                   entity JWK set and not {@code null}.
	 *
	 * @return The signed resolve statement.
	 *
	 * @throws JOSEException On a internal signing exception.
	 */
	public static ResolveStatement sign(final ResolveClaimsSet claimsSet,
					    final JWK signingJWK)
		throws JOSEException {
		
		return sign(claimsSet, signingJWK, JWTUtils.resolveSigningAlgorithm(signingJWK));
	}
	
	
	/**
	 * Signs the specified resolve claims set.
	 *
	 * @param claimsSet  The claims set. Must not be {@code null}.
	 * @param signingJWK The private signing JWK. Must be contained in the
	 *                   entity JWK set and not {@code null}.
	 * @param jwsAlg     The signing algorithm. Must be supported by the
	 *                   JWK and not {@code null}.
	 *
	 * @return The signed resolve statement.
	 *
	 * @throws JOSEException On an internal signing exception.
	 */
	public static ResolveStatement sign(final ResolveClaimsSet claimsSet,
					    final JWK signingJWK,
					    final JWSAlgorithm jwsAlg)
		throws JOSEException {
		
		try {
			return new ResolveStatement(
				JWTUtils.sign(
					signingJWK,
					jwsAlg,
					JOSE_OBJECT_TYPE,
					claimsSet.toJWTClaimsSet()),
				claimsSet);
		} catch (ParseException e) {
			throw new JOSEException(e.getMessage(), e);
		}
	}
	
	
	/**
	 * Parses a resolve statement.
	 *
	 * @param signedStmt The signed statement as a signed JWT. Must not be
	 *                   {@code null}.
	 *
	 * @return The resolve statement.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ResolveStatement parse(final SignedJWT signedStmt)
		throws ParseException {
		
		return new ResolveStatement(signedStmt, new ResolveClaimsSet(JWTUtils.parseSignedJWTClaimsSet(signedStmt)));
	}
	
	
	/**
	 * Parses a resolve statement.
	 *
	 * @param signedStmtString The signed statement as a signed JWT string.
	 *                         Must not be {@code null}.
	 *
	 * @return The resolve statement.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ResolveStatement parse(final String signedStmtString)
		throws ParseException {
		
		try {
			return parse(SignedJWT.parse(signedStmtString));
		} catch (java.text.ParseException e) {
			throw new ParseException("Invalid resolve statement: " + e.getMessage(), e);
		}
	}
}
