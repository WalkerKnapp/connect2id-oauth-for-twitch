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

package com.nimbusds.openid.connect.sdk.federation.entities;


import java.security.PublicKey;
import java.util.List;

import net.jcip.annotations.Immutable;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerifierFactory;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;


/**
 * Federation entity statement.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 3.1.
 * </ul>
 */
@Immutable
public final class EntityStatement {
	
	
	/**
	 * The federation entity statement JOSE object type
	 * ({@code entity-statement+jwt}).
	 */
	public static final JOSEObjectType JOSE_OBJECT_TYPE = new JOSEObjectType("entity-statement+jwt");
	
	
	/**
	 * The federation entity statement content type
	 * ({@code application/entity-statement+jwt}).
	 */
	public static final ContentType CONTENT_TYPE = new ContentType("application", JOSE_OBJECT_TYPE.getType());
	
	
	/**
	 * The signed statement as signed JWT.
	 */
	private final SignedJWT statementJWT;
	
	
	/**
	 * The statement claims.
	 */
	private final EntityStatementClaimsSet statementClaimsSet;
	
	
	/**
	 * Creates a new federation entity statement.
	 *
	 * @param statementJWT       The signed statement as signed JWT. Must
	 *                           not be {@code null}.
	 * @param statementClaimsSet The statement claims. Must not be
	 *                           {@code null}.
	 */
	private EntityStatement(final SignedJWT statementJWT,
				final EntityStatementClaimsSet statementClaimsSet) {
		
		if (statementJWT == null) {
			throw new IllegalArgumentException("The entity statement must not be null");
		}
		if (JWSObject.State.UNSIGNED.equals(statementJWT.getState())) {
			throw new IllegalArgumentException("The statement is not signed");
		}
		this.statementJWT = statementJWT;
		
		if (statementClaimsSet == null) {
			throw new IllegalArgumentException("The entity statement claims set must not be null");
		}
		this.statementClaimsSet = statementClaimsSet;
	}
	
	
	/**
	 * Returns the entity ID.
	 *
	 * @return The entity ID.
	 */
	public EntityID getEntityID() {
		return getClaimsSet().getSubjectEntityID();
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
	public EntityStatementClaimsSet getClaimsSet() {
		return statementClaimsSet;
	}
	
	
	/**
	 * Returns {@code true} if this entity statement is for a
	 * {@link EntityRole#TRUST_ANCHOR trust anchor}.
	 *
	 * @return {@code true} for a trust anchor, else {@code false}.
	 */
	public boolean isTrustAnchor() {
		
		return getClaimsSet().isSelfStatement() && CollectionUtils.isEmpty(getClaimsSet().getAuthorityHints());
	}
	
	
	/**
	 * Verifies the signature for a self-statement (typically for a trust
	 * anchor or leaf) and checks the statement issue and expiration times.
	 *
	 * @return The SHA-256 thumbprint of the key used to successfully
	 *         verify the signature.
	 *
	 * @throws BadJOSEException If the signature is invalid or the
	 *                          statement is expired or before the issue
	 *                          time.
	 * @throws JOSEException    On a internal JOSE exception.
	 */
	public Base64URL verifySignatureOfSelfStatement() throws BadJOSEException, JOSEException {
		
		if (! getClaimsSet().isSelfStatement()) {
			throw new BadJOSEException("Entity statement not self-issued");
		}
		
		return verifySignature(getClaimsSet().getJWKSet());
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
		
		if (! JOSE_OBJECT_TYPE.equals(statementJWT.getHeader().getType())) {
			throw new BadJOSEException("Entity statement rejected: Invalid or missing JWT typ (type) header");
		}
		
		List<JWK> jwkMatches = new JWKSelector(JWKMatcher.forJWSHeader(statementJWT.getHeader())).select(jwkSet);
		
		if (jwkMatches.isEmpty()) {
			throw new BadJOSEException("Entity statement rejected: Another JOSE algorithm expected, or no matching key(s) found");
		}
		
		JWSVerifierFactory verifierFactory = new DefaultJWSVerifierFactory();
		
		JWK signingJWK = null;
		
		for (JWK candidateJWK: jwkMatches) {
			
			if (candidateJWK instanceof AsymmetricJWK) {
				PublicKey publicKey = ((AsymmetricJWK)candidateJWK).toPublicKey();
				JWSVerifier jwsVerifier = verifierFactory.createJWSVerifier(statementJWT.getHeader(), publicKey);
				if (statementJWT.verify(jwsVerifier)) {
					// success
					signingJWK = candidateJWK;
				}
			}
		}
		
		if (signingJWK == null) {
			throw new BadJOSEException("Entity statement rejected: Invalid signature");
		}
		
		// Double check claims with JWT framework
		
		try {
			new EntityStatementClaimsVerifier(null).verify(statementJWT.getJWTClaimsSet(), null);
		} catch (java.text.ParseException e) {
			throw new BadJOSEException(e.getMessage(), e);
		}
		
		return signingJWK.computeThumbprint();
	}
	
	
	/**
	 * Signs the specified federation entity claims set.
	 *
	 * @param claimsSet  The claims set. Must not be {@code null}.
	 * @param signingJWK The private signing JWK. Must be contained in the
	 *                   entity JWK set and not {@code null}.
	 *
	 * @return The signed federation entity statement.
	 *
	 * @throws JOSEException On a internal signing exception.
	 */
	public static EntityStatement sign(final EntityStatementClaimsSet claimsSet,
					   final JWK signingJWK)
		throws JOSEException {
		
		return sign(claimsSet, signingJWK, resolveSigningAlgorithm(signingJWK));
	}
	
	
	/**
	 * Signs the specified federation entity claims set.
	 *
	 * @param claimsSet  The claims set. Must not be {@code null}.
	 * @param signingJWK The private signing JWK. Must be contained in the
	 *                   entity JWK set and not {@code null}.
	 * @param jwsAlg     The signing algorithm. Must be supported by the
	 *                   JWK and not {@code null}.
	 *
	 * @return The signed federation entity statement.
	 *
	 * @throws JOSEException On a internal signing exception.
	 */
	public static EntityStatement sign(final EntityStatementClaimsSet claimsSet,
					   final JWK signingJWK,
					   final JWSAlgorithm jwsAlg)
		throws JOSEException {
		
		if (claimsSet.isSelfStatement() && ! claimsSet.getJWKSet().containsJWK(signingJWK)) {
			throw new JOSEException("Signing JWK not found in JWK set of self-statement");
		}
		
		JWSSigner jwsSigner = new DefaultJWSSignerFactory().createJWSSigner(signingJWK, jwsAlg);
		
		JWSHeader jwsHeader = new JWSHeader.Builder(jwsAlg)
			.type(JOSE_OBJECT_TYPE)
			.keyID(signingJWK.getKeyID())
			.build();
		
		SignedJWT signedJWT;
		try {
			signedJWT = new SignedJWT(jwsHeader, claimsSet.toJWTClaimsSet());
		} catch (ParseException e) {
			throw new JOSEException(e.getMessage(), e);
		}
		signedJWT.sign(jwsSigner);
		return new EntityStatement(signedJWT, claimsSet);
	}
	
	
	private static JWSAlgorithm resolveSigningAlgorithm(final JWK jwk)
		throws JOSEException {
		
		KeyType jwkType = jwk.getKeyType();
		
		if (KeyType.RSA.equals(jwkType)) {
			if (jwk.getAlgorithm() != null) {
				return new JWSAlgorithm(jwk.getAlgorithm().getName());
			} else {
				return JWSAlgorithm.RS256; // assume RS256 as default
			}
		} else if (KeyType.EC.equals(jwkType)) {
			ECKey ecJWK = jwk.toECKey();
			if (jwk.getAlgorithm() != null) {
				return new JWSAlgorithm(ecJWK.getAlgorithm().getName());
			} else {
				if (Curve.P_256.equals(ecJWK.getCurve())) {
					return JWSAlgorithm.ES256;
				} else if (Curve.P_384.equals(ecJWK.getCurve())) {
					return JWSAlgorithm.ES384;
				} else if (Curve.P_521.equals(ecJWK.getCurve())) {
					return JWSAlgorithm.ES512;
				} else {
					throw new JOSEException("Unsupported ECDSA curve: " + ecJWK.getCurve());
				}
			}
		} else if (KeyType.OKP.equals(jwkType)){
			OctetKeyPair okp = jwk.toOctetKeyPair();
			if (Curve.Ed25519.equals(okp.getCurve())) {
				return JWSAlgorithm.EdDSA;
			} else {
				throw new JOSEException("Unsupported EdDSA curve: " + okp.getCurve());
			}
		} else {
			throw new JOSEException("Unsupported JWK type: " + jwkType);
		}
	}
	
	
	/**
	 * Parses a federation entity statement.
	 *
	 * @param signedStmt The signed statement as a signed JWT. Must not
	 *                   be {@code null}.
	 *
	 * @return The federation entity statement.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static EntityStatement parse(final SignedJWT signedStmt)
		throws ParseException {
		
		if (JWSObject.State.UNSIGNED.equals(signedStmt.getState())) {
			throw new ParseException("The statement is not signed");
		}
		
		JWTClaimsSet jwtClaimsSet;
		try {
			jwtClaimsSet = signedStmt.getJWTClaimsSet();
		} catch (java.text.ParseException e) {
			throw new ParseException(e.getMessage(), e);
		}
		
		EntityStatementClaimsSet claimsSet = new EntityStatementClaimsSet(jwtClaimsSet);
		return new EntityStatement(signedStmt, claimsSet);
	}
	
	
	/**
	 * Parses a federation entity statement.
	 *
	 * @param signedStmtString The signed statement as a signed JWT string.
	 *                         Must not be {@code null}.
	 *
	 * @return The federation entity statement.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static EntityStatement parse(final String signedStmtString)
		throws ParseException {
		
		try {
			return parse(SignedJWT.parse(signedStmtString));
		} catch (java.text.ParseException e) {
			throw new ParseException("Invalid entity statement: " + e.getMessage(), e);
		}
	}
}
