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

package com.nimbusds.openid.connect.sdk.validators;


import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.proc.*;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import net.jcip.annotations.ThreadSafe;


/**
 * Validator of ID tokens issued by an OpenID Provider (OP).
 *
 * <p>Supports processing of ID tokens with the following protection:
 *
 * <ul>
 *     <li>ID tokens signed (JWS) with the OP's RSA or EC key, require the
 *         OP public JWK set (provided by value or URL) to verify them.
 *     <li>ID tokens authenticated with a JWS HMAC, require the client's secret
 *         to verify them.
 *     <li>Unsecured (plain) ID tokens received at the token endpoint.
 * </ul>
 *
 * <p>Convenience static methods for creating an ID token validator from OpenID
 * Provider metadata or issuer URL, and the registered Relying Party
 * information:
 *
 * <ul>
 *     <li>{@link #create(OIDCProviderMetadata, OIDCClientInformation)}
 *     <li>{@link #create(Issuer, OIDCClientInformation)}
 * </ul>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, sections 3.1.3.7, 3.2.2.11 and 3.3.2.12.
 * </ul>
 */
@ThreadSafe
public class IDTokenValidator extends AbstractJWTValidator implements ClockSkewAware {


	/**
	 * Creates a new validator for unsecured (plain) ID tokens.
	 *
	 * @param expectedIssuer The expected ID token issuer (OpenID
	 *                       Provider). Must not be {@code null}.
	 * @param clientID       The client ID. Must not be {@code null}.
	 */
	public IDTokenValidator(final Issuer expectedIssuer,
				final ClientID clientID) {

		this(expectedIssuer, clientID, (JWSKeySelector) null, null);
	}


	/**
	 * Creates a new validator for RSA or EC signed ID tokens where the
	 * OpenID Provider's JWK set is specified by value.
	 *
	 * @param expectedIssuer The expected ID token issuer (OpenID
	 *                       Provider). Must not be {@code null}.
	 * @param clientID       The client ID. Must not be {@code null}.
	 * @param expectedJWSAlg The expected RSA or EC JWS algorithm. Must not
	 *                       be {@code null}.
	 * @param jwkSet         The OpenID Provider JWK set. Must not be
	 *                       {@code null}.
	 */
	public IDTokenValidator(final Issuer expectedIssuer,
				final ClientID clientID,
				final JWSAlgorithm expectedJWSAlg,
				final JWKSet jwkSet) {

		this(expectedIssuer, clientID, new JWSVerificationKeySelector(expectedJWSAlg, new ImmutableJWKSet(jwkSet)),  null);
	}


	/**
	 * Creates a new validator for RSA or EC signed ID tokens where the
	 * OpenID Provider's JWK set is specified by URL.
	 *
	 * @param expectedIssuer The expected ID token issuer (OpenID
	 *                       Provider). Must not be {@code null}.
	 * @param clientID       The client ID. Must not be {@code null}.
	 * @param expectedJWSAlg The expected RSA or EC JWS algorithm. Must not
	 *                       be {@code null}.
	 * @param jwkSetURI      The OpenID Provider JWK set URL. Must not be
	 *                       {@code null}.
	 */
	public IDTokenValidator(final Issuer expectedIssuer,
				final ClientID clientID,
				final JWSAlgorithm expectedJWSAlg,
				final URL jwkSetURI) {

		this(expectedIssuer, clientID, expectedJWSAlg, jwkSetURI, null);
	}


	/**
	 * Creates a new validator for RSA or EC signed ID tokens where the
	 * OpenID Provider's JWK set is specified by URL. Permits setting of a
	 * specific resource retriever (HTTP client) for the JWK set.
	 *
	 * @param expectedIssuer    The expected ID token issuer (OpenID
	 *                          Provider). Must not be {@code null}.
	 * @param clientID          The client ID. Must not be {@code null}.
	 * @param expectedJWSAlg    The expected RSA or EC JWS algorithm. Must
	 *                          not be {@code null}.
	 * @param jwkSetURI         The OpenID Provider JWK set URL. Must not
	 *                          be {@code null}.
	 * @param resourceRetriever For retrieving the OpenID Connect Provider
	 *                          JWK set from the specified URL. If
	 *                          {@code null} the
	 *                          {@link com.nimbusds.jose.util.DefaultResourceRetriever
	 *                          default retriever} will be used, with
	 *                          preset HTTP connect timeout, HTTP read
	 *                          timeout and entity size limit.
	 */
	public IDTokenValidator(final Issuer expectedIssuer,
				final ClientID clientID,
				final JWSAlgorithm expectedJWSAlg,
				final URL jwkSetURI,
				final ResourceRetriever resourceRetriever) {

		this(expectedIssuer, clientID, new JWSVerificationKeySelector(expectedJWSAlg, new RemoteJWKSet(jwkSetURI, resourceRetriever)),  null);
	}


	/**
	 * Creates a new validator for HMAC protected ID tokens.
	 *
	 * @param expectedIssuer The expected ID token issuer (OpenID
	 *                       Provider). Must not be {@code null}.
	 * @param clientID       The client ID. Must not be {@code null}.
	 * @param expectedJWSAlg The expected HMAC JWS algorithm. Must not be
	 *                       {@code null}.
	 * @param clientSecret   The client secret. Must not be {@code null}.
	 */
	public IDTokenValidator(final Issuer expectedIssuer,
				final ClientID clientID,
				final JWSAlgorithm expectedJWSAlg,
				final Secret clientSecret) {

		this(expectedIssuer, clientID, new JWSVerificationKeySelector(expectedJWSAlg, new ImmutableSecret(clientSecret.getValueBytes())), null);
	}


	/**
	 * Creates a new ID token validator.
	 *
	 * @param expectedIssuer The expected ID token issuer (OpenID
	 *                       Provider). Must not be {@code null}.
	 * @param clientID       The client ID. Must not be {@code null}.
	 * @param jwsKeySelector The key selector for JWS verification,
	 *                       {@code null} if unsecured (plain) ID tokens
	 *                       are expected.
	 * @param jweKeySelector The key selector for JWE decryption,
	 *                       {@code null} if encrypted ID tokens are not
	 *                       expected.
	 */
	public IDTokenValidator(final Issuer expectedIssuer,
				final ClientID clientID,
				final JWSKeySelector jwsKeySelector,
				final JWEKeySelector jweKeySelector) {
		
		super(expectedIssuer, clientID, jwsKeySelector, jweKeySelector);
	}


	/**
	 * Validates the specified ID token.
	 *
	 * @param idToken       The ID token. Must not be {@code null}.
	 * @param expectedNonce The expected nonce, {@code null} if none.
	 *
	 * @return The claims set of the verified ID token.
	 *
	 * @throws BadJOSEException If the ID token is invalid or expired.
	 * @throws JOSEException    If an internal JOSE exception was
	 *                          encountered.
	 */
	public IDTokenClaimsSet validate(final JWT idToken, final Nonce expectedNonce)
		throws BadJOSEException, JOSEException {

		if (idToken instanceof PlainJWT) {
			return validate((PlainJWT)idToken, expectedNonce);
		} else if (idToken instanceof SignedJWT) {
			return validate((SignedJWT) idToken, expectedNonce);
		} else if (idToken instanceof EncryptedJWT) {
			return validate((EncryptedJWT) idToken, expectedNonce);
		} else {
			throw new JOSEException("Unexpected JWT type: " + idToken.getClass());
		}
	}


	/**
	 * Verifies the specified unsecured (plain) ID token.
	 *
	 * @param idToken       The ID token. Must not be {@code null}.
	 * @param expectedNonce The expected nonce, {@code null} if none.
	 *
	 * @return The claims set of the verified ID token.
	 *
	 * @throws BadJOSEException If the ID token is invalid or expired.
	 * @throws JOSEException    If an internal JOSE exception was
	 *                          encountered.
	 */
	private IDTokenClaimsSet validate(final PlainJWT idToken, final Nonce expectedNonce)
		throws BadJOSEException, JOSEException {

		if (getJWSKeySelector() != null) {
			throw new BadJWTException("Signed ID token expected");
		}

		JWTClaimsSet jwtClaimsSet;

		try {
			jwtClaimsSet = idToken.getJWTClaimsSet();
		} catch (java.text.ParseException e) {
			throw new BadJWTException(e.getMessage(), e);
		}

		JWTClaimsSetVerifier<?> claimsVerifier = new IDTokenClaimsVerifier(getExpectedIssuer(), getClientID(), expectedNonce, getMaxClockSkew());
		claimsVerifier.verify(jwtClaimsSet, null);
		return toIDTokenClaimsSet(jwtClaimsSet);
	}


	/**
	 * Verifies the specified signed ID token.
	 *
	 * @param idToken       The ID token. Must not be {@code null}.
	 * @param expectedNonce The expected nonce, {@code null} if none.
	 *
	 * @return The claims set of the verified ID token.
	 *
	 * @throws BadJOSEException If the ID token is invalid or expired.
	 * @throws JOSEException    If an internal JOSE exception was
	 *                          encountered.
	 */
	private IDTokenClaimsSet validate(final SignedJWT idToken, final Nonce expectedNonce)
		throws BadJOSEException, JOSEException {

		if (getJWSKeySelector() == null) {
			throw new BadJWTException("Verification of signed JWTs not configured");
		}

		ConfigurableJWTProcessor<?> jwtProcessor = new DefaultJWTProcessor();
		jwtProcessor.setJWSKeySelector(getJWSKeySelector());
		jwtProcessor.setJWTClaimsSetVerifier(new IDTokenClaimsVerifier(getExpectedIssuer(), getClientID(), expectedNonce, getMaxClockSkew()));
		JWTClaimsSet jwtClaimsSet = jwtProcessor.process(idToken, null);
		return toIDTokenClaimsSet(jwtClaimsSet);
	}


	/**
	 * Verifies the specified signed and encrypted ID token.
	 *
	 * @param idToken       The ID token. Must not be {@code null}.
	 * @param expectedNonce The expected nonce, {@code null} if none.
	 *
	 * @return The claims set of the verified ID token.
	 *
	 * @throws BadJOSEException If the ID token is invalid or expired.
	 * @throws JOSEException    If an internal JOSE exception was
	 *                          encountered.
	 */
	private IDTokenClaimsSet validate(final EncryptedJWT idToken, final Nonce expectedNonce)
		throws BadJOSEException, JOSEException {

		if (getJWEKeySelector() == null) {
			throw new BadJWTException("Decryption of JWTs not configured");
		}
		if (getJWSKeySelector() == null) {
			throw new BadJWTException("Verification of signed JWTs not configured");
		}

		ConfigurableJWTProcessor<?> jwtProcessor = new DefaultJWTProcessor();
		jwtProcessor.setJWSKeySelector(getJWSKeySelector());
		jwtProcessor.setJWEKeySelector(getJWEKeySelector());
		jwtProcessor.setJWTClaimsSetVerifier(new IDTokenClaimsVerifier(getExpectedIssuer(), getClientID(), expectedNonce, getMaxClockSkew()));

		JWTClaimsSet jwtClaimsSet = jwtProcessor.process(idToken, null);

		return toIDTokenClaimsSet(jwtClaimsSet);
	}


	/**
	 * Converts a JWT claims set to an ID token claims set.
	 *
	 * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
	 *
	 * @return The ID token claims set.
	 *
	 * @throws JOSEException If conversion failed.
	 */
	private static IDTokenClaimsSet toIDTokenClaimsSet(final JWTClaimsSet jwtClaimsSet)
		throws JOSEException {

		try {
			return new IDTokenClaimsSet(jwtClaimsSet);
		} catch (ParseException e) {
			// Claims set must be verified at this point
			throw new JOSEException(e.getMessage(), e);
		}
	}


	/**
	 * Creates a key selector for JWS verification.
	 *
	 * @param opMetadata The OpenID Provider metadata. Must not be
	 *                   {@code null}.
	 * @param clientInfo The Relying Party metadata. Must not be
	 *                   {@code null}.
	 *
	 * @return The JWS key selector.
	 *
	 * @throws GeneralException If the supplied OpenID Provider metadata or
	 *                          Relying Party metadata are missing a
	 *                          required parameter or inconsistent.
	 */
	protected static JWSKeySelector createJWSKeySelector(final OIDCProviderMetadata opMetadata,
							     final OIDCClientInformation clientInfo)
		throws GeneralException {

		final JWSAlgorithm expectedJWSAlg = clientInfo.getOIDCMetadata().getIDTokenJWSAlg();

		if (opMetadata.getIDTokenJWSAlgs() == null) {
			throw new GeneralException("Missing OpenID Provider id_token_signing_alg_values_supported parameter");
		}

		if (! opMetadata.getIDTokenJWSAlgs().contains(expectedJWSAlg)) {
			throw new GeneralException("The OpenID Provider doesn't support " + expectedJWSAlg + " ID tokens");
		}

		if (Algorithm.NONE.equals(expectedJWSAlg)) {
			// Skip creation of JWS key selector, plain ID tokens expected
			return null;

		} else if (JWSAlgorithm.Family.RSA.contains(expectedJWSAlg) || JWSAlgorithm.Family.EC.contains(expectedJWSAlg)) {

			URL jwkSetURL;
			try {
				jwkSetURL = opMetadata.getJWKSetURI().toURL();
			} catch (MalformedURLException e) {
				throw new GeneralException("Invalid jwk set URI: " + e.getMessage(), e);
			}
			JWKSource jwkSource = new RemoteJWKSet(jwkSetURL); // TODO specify HTTP response limits

			return new JWSVerificationKeySelector(expectedJWSAlg, jwkSource);

		} else if (JWSAlgorithm.Family.HMAC_SHA.contains(expectedJWSAlg)) {

			Secret clientSecret = clientInfo.getSecret();
			if (clientSecret == null) {
				throw new GeneralException("Missing client secret");
			}
			return new JWSVerificationKeySelector(expectedJWSAlg, new ImmutableSecret(clientSecret.getValueBytes()));

		} else {
			throw new GeneralException("Unsupported JWS algorithm: " + expectedJWSAlg);
		}
	}


	/**
	 * Creates a key selector for JWE decryption.
	 *
	 * @param opMetadata      The OpenID Provider metadata. Must not be
	 *                        {@code null}.
	 * @param clientInfo      The Relying Party metadata. Must not be
	 *                        {@code null}.
	 * @param clientJWKSource The client private JWK source, {@code null}
	 *                        if encrypted ID tokens are not expected.
	 *
	 * @return The JWE key selector.
	 *
	 * @throws GeneralException If the supplied OpenID Provider metadata or
	 *                          Relying Party metadata are missing a
	 *                          required parameter or inconsistent.
	 */
	protected static JWEKeySelector createJWEKeySelector(final OIDCProviderMetadata opMetadata,
							     final OIDCClientInformation clientInfo,
							     final JWKSource clientJWKSource)
		throws GeneralException {

		final JWEAlgorithm expectedJWEAlg = clientInfo.getOIDCMetadata().getIDTokenJWEAlg();
		final EncryptionMethod expectedJWEEnc = clientInfo.getOIDCMetadata().getIDTokenJWEEnc();

		if (expectedJWEAlg == null) {
			// Encrypted ID tokens not expected
			return null;
		}

		if (expectedJWEEnc == null) {
			throw new GeneralException("Missing required ID token JWE encryption method for " + expectedJWEAlg);
		}

		if (opMetadata.getIDTokenJWEAlgs() == null || ! opMetadata.getIDTokenJWEAlgs().contains(expectedJWEAlg)) {
			throw new GeneralException("The OpenID Provider doesn't support " + expectedJWEAlg + " ID tokens");
		}

		if (opMetadata.getIDTokenJWEEncs() == null || ! opMetadata.getIDTokenJWEEncs().contains(expectedJWEEnc)) {
			throw new GeneralException("The OpenID Provider doesn't support " + expectedJWEAlg + " / " + expectedJWEEnc + " ID tokens");
		}

		return new JWEDecryptionKeySelector(expectedJWEAlg, expectedJWEEnc, clientJWKSource);
	}


	/**
	 * Creates a new ID token validator for the specified OpenID Provider
	 * metadata and OpenID Relying Party registration.
	 *
	 * @param opMetadata      The OpenID Provider metadata. Must not be
	 *                        {@code null}.
	 * @param clientInfo      The OpenID Relying Party registration. Must
	 *                        not be {@code null}.
	 * @param clientJWKSource The client private JWK source, {@code null}
	 *                        if encrypted ID tokens are not expected.
	 *
	 * @return The ID token validator.
	 *
	 * @throws GeneralException If the supplied OpenID Provider metadata or
	 *                          Relying Party metadata are missing a
	 *                          required parameter or inconsistent.
	 */
	public static IDTokenValidator create(final OIDCProviderMetadata opMetadata,
					      final OIDCClientInformation clientInfo,
					      final JWKSource clientJWKSource)
		throws GeneralException {

		// Create JWS key selector, unless id_token alg = none
		final JWSKeySelector jwsKeySelector = createJWSKeySelector(opMetadata, clientInfo);

		// Create JWE key selector if encrypted ID tokens are expected
		final JWEKeySelector jweKeySelector = createJWEKeySelector(opMetadata, clientInfo, clientJWKSource);

		return new IDTokenValidator(opMetadata.getIssuer(), clientInfo.getID(), jwsKeySelector, jweKeySelector);
	}


	/**
	 * Creates a new ID token validator for the specified OpenID Provider
	 * metadata and OpenID Relying Party registration.
	 *
	 * @param opMetadata The OpenID Provider metadata. Must not be
	 *                   {@code null}.
	 * @param clientInfo The OpenID Relying Party registration. Must not be
	 *                   {@code null}.
	 *
	 * @return The ID token validator.
	 *
	 * @throws GeneralException If the supplied OpenID Provider metadata or
	 *                          Relying Party metadata are missing a
	 *                          required parameter or inconsistent.
	 */
	public static IDTokenValidator create(final OIDCProviderMetadata opMetadata,
					      final OIDCClientInformation clientInfo)
		throws GeneralException {

		return create(opMetadata, clientInfo, null);
	}
	
	
	/**
	 * Creates a new ID token validator for the specified OpenID Provider,
	 * which must publish its metadata at
	 * {@code [issuer-url]/.well-known/openid-configuration}.
	 *
	 * @param opIssuer   The OpenID Provider issuer identifier. Must not be
	 *                   {@code null}.
	 * @param clientInfo The OpenID Relying Party registration. Must not be
	 *                   {@code null}.
	 *
	 * @return The ID token validator.
	 *
	 * @throws GeneralException If the resolved OpenID Provider metadata is
	 *                          invalid.
	 * @throws IOException      On a HTTP exception.
	 */
	public static IDTokenValidator create(final Issuer opIssuer,
					      final OIDCClientInformation clientInfo)
		throws GeneralException, IOException {
		
		return create(opIssuer, clientInfo, null, 0, 0);
	}
	
	
	/**
	 * Creates a new ID token validator for the specified OpenID Provider,
	 * which must publish its metadata at
	 * {@code [issuer-url]/.well-known/openid-configuration}.
	 *
	 * @param opIssuer        The OpenID Provider issuer identifier. Must
	 *                        not be {@code null}.
	 * @param clientInfo      The OpenID Relying Party registration. Must
	 *                        not be {@code null}.
	 * @param clientJWKSource The client private JWK source, {@code null}
	 *                        if encrypted ID tokens are not expected.
	 * @param connectTimeout  The HTTP connect timeout, in milliseconds.
	 *                        Zero implies no timeout. Must not be
	 *                        negative.
	 * @param readTimeout     The HTTP response read timeout, in
	 *                        milliseconds. Zero implies no timeout. Must
	 *                        not be negative.
	 *
	 * @return The ID token validator.
	 *
	 * @throws GeneralException If the resolved OpenID Provider metadata is
	 *                          invalid.
	 * @throws IOException      On a HTTP exception.
	 */
	public static IDTokenValidator create(final Issuer opIssuer,
					      final OIDCClientInformation clientInfo,
					      final JWKSource clientJWKSource,
					      final int connectTimeout,
					      final int readTimeout)
		throws GeneralException, IOException {
		
		OIDCProviderMetadata opMetadata = OIDCProviderMetadata.resolve(opIssuer, connectTimeout, readTimeout);
		
		return create(opMetadata, clientInfo, clientJWKSource);
	}
}
