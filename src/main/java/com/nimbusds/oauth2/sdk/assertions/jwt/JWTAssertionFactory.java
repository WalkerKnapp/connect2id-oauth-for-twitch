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


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;


/**
 * Static JWT bearer assertion factory.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Assertion Framework for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7521)
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523)
 * </ul>
 */
public class JWTAssertionFactory {


	/**
	 * Returns the supported signature JSON Web Algorithms (JWAs).
	 *
	 * @return The supported JSON Web Algorithms (JWAs).
	 */
	public static Set<JWSAlgorithm> supportedJWAs() {

		Set<JWSAlgorithm> supported = new HashSet<>();
		supported.addAll(JWSAlgorithm.Family.HMAC_SHA);
		supported.addAll(JWSAlgorithm.Family.RSA);
		supported.addAll(JWSAlgorithm.Family.EC);
		return Collections.unmodifiableSet(supported);
	}


	/**
	 * Creates a new HMAC-protected JWT bearer assertion.
	 *
	 * @param details      The JWT bearer assertion details. Must not be
	 *                     {@code null}.
	 * @param jwsAlgorithm The expected HMAC algorithm (HS256, HS384 or
	 *                     HS512) for the JWT assertion. Must be supported
	 *                     and not {@code null}.
	 * @param secret       The secret. Must be at least 256-bits long.
	 *
	 * @return The JWT bearer assertion.
	 *
	 * @throws JOSEException If the client secret is too short, or HMAC
	 *                       computation failed.
	 */
	public static SignedJWT create(final JWTAssertionDetails details,
				       final JWSAlgorithm jwsAlgorithm,
				       final Secret secret)
		throws JOSEException {

		SignedJWT signedJWT = new SignedJWT(new JWSHeader(jwsAlgorithm), details.toJWTClaimsSet());
		signedJWT.sign(new MACSigner(secret.getValueBytes()));
		return signedJWT;
	}


	/**
	 * Creates a new signed JWT bearer assertion.
	 *
	 * @param details      The JWT bearer assertion details. Must not be
	 *                     {@code null}.
	 * @param jwsAlgorithm The expected RSA (RS256, RS384, RS512, PS256,
	 *                     PS384 or PS512) or EC (ES256, ES384, ES512)
	 *                     signature algorithm for the JWT assertion. Must
	 *                     be supported and not {@code null}.
	 * @param privateKey   The signing private RSA or EC key. Must not be
	 *                     {@code null}.
	 * @param keyID        Optional identifier for the key, to aid key
	 *                     selection on the recipient side. Recommended.
	 *                     {@code null} if not specified.
	 * @param x5c          Optional X.509 certificate chain for the public
	 *                     key, {@code null} if not specified.
	 * @param x5t256       Optional X.509 certificate SHA-256 thumbprint,
	 *                     {@code null} if not specified.
	 * @param jcaProvider  Optional specific JCA provider, {@code null} to
	 *                     use the default one.
	 *
	 * @return The JWT bearer assertion.
	 *
	 * @throws JOSEException If signing failed.
	 */
	public static SignedJWT create(final JWTAssertionDetails details,
				       final JWSAlgorithm jwsAlgorithm,
				       final PrivateKey privateKey,
				       final String keyID,
				       final List<Base64> x5c,
				       final Base64URL x5t256,
				       final Provider jcaProvider)
		throws JOSEException {

		SignedJWT signedJWT = new SignedJWT(
			new JWSHeader.Builder(jwsAlgorithm)
				.keyID(keyID)
				.x509CertChain(x5c)
				.x509CertSHA256Thumbprint(x5t256)
				.build(),
			details.toJWTClaimsSet());
		
		final JWSSigner signer;
		if (RSASSASigner.SUPPORTED_ALGORITHMS.contains(jwsAlgorithm)) {
			signer = new RSASSASigner(privateKey);
		} else if (ECDSASigner.SUPPORTED_ALGORITHMS.contains(jwsAlgorithm)) {
			Set<Curve> curves = Curve.forJWSAlgorithm(jwsAlgorithm);
			if (curves.size() != 1) {
				throw new JOSEException("Couldn't determine curve for JWS algorithm: " + jwsAlgorithm);
			}
			signer = new ECDSASigner(privateKey, curves.iterator().next());
		} else {
			throw new JOSEException("Unsupported JWS algorithm: " + jwsAlgorithm);
		}
		
		if (jcaProvider != null) {
			signer.getJCAContext().setProvider(jcaProvider);
		}
		
		signedJWT.sign(signer);
		
		return signedJWT;
	}


	/**
	 * Creates a new RSA-signed JWT bearer assertion.
	 *
	 * @param details       The JWT bearer assertion details. Must not be
	 *                      {@code null}.
	 * @param jwsAlgorithm  The expected RSA signature algorithm (RS256,
	 *                      RS384, RS512, PS256, PS384 or PS512) for the
	 *                      JWT assertion. Must be supported and not
	 *                      {@code null}.
	 * @param rsaPrivateKey The RSA private key. Must not be {@code null}.
	 * @param keyID         Optional identifier for the RSA key, to aid key
	 *                      selection on the recipient side. Recommended.
	 *                      {@code null} if not specified.
	 * @param jcaProvider   Optional specific JCA provider, {@code null} to
	 *                      use the default one.
	 *
	 * @return The JWT bearer assertion.
	 *
	 * @throws JOSEException If RSA signing failed.
	 */
	@Deprecated
	public static SignedJWT create(final JWTAssertionDetails details,
				       final JWSAlgorithm jwsAlgorithm,
				       final RSAPrivateKey rsaPrivateKey,
				       final String keyID,
				       final Provider jcaProvider)
		throws JOSEException {

		return create(details, jwsAlgorithm, rsaPrivateKey, keyID, null, null, jcaProvider);
	}


	/**
	 * Creates a new EC-signed JWT bearer assertion.
	 *
	 * @param details      The JWT bearer assertion details. Must not be
	 *                     {@code null}.
	 * @param jwsAlgorithm The expected EC signature algorithm (ES256,
	 *                     ES384 or ES512) for the JWT assertion. Must be
	 *                     supported and not {@code null}.
	 * @param ecPrivateKey The EC private key. Must not be {@code null}.
	 * @param keyID        Optional identifier for the EC key, to aid key
	 *                     selection on the recipient side. Recommended.
	 *                     {@code null} if not specified.
	 * @param jcaProvider  Optional specific JCA provider, {@code null} to
	 *                     use the default one.
	 *
	 * @return The JWT bearer assertion.
	 *
	 * @throws JOSEException If RSA signing failed.
	 */
	@Deprecated
	public static SignedJWT create(final JWTAssertionDetails details,
				       final JWSAlgorithm jwsAlgorithm,
				       final ECPrivateKey ecPrivateKey,
				       final String keyID,
				       final Provider jcaProvider)
		throws JOSEException {

		return create(details, jwsAlgorithm, ecPrivateKey, keyID, null, null, jcaProvider);
	}


	/**
	 * Prevents public instantiation.
	 */
	private JWTAssertionFactory() {}
}
