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

package com.nimbusds.oauth2.sdk.jarm;


import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.*;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ClockSkewAware;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.client.ClientInformation;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.AbstractJWTValidator;
import net.jcip.annotations.ThreadSafe;


/**
 * Validator of JSON Web Token (JWT) secured authorisation responses (JARM).
 *
 * <p>Supports processing of JWT responses with the following protection:
 *
 * <ul>
 *     <li>JWTs signed (JWS) with the Authorisation Server's RSA or EC key,
 *         require the Authorisation Server's public JWK set (provided by value
 *         or URL) to verify them.
 *     <li>JWTs authenticated with a JWS HMAC, require the client's secret
 *         to verify them.
 * </ul>
 *
 * <p>Convenience static methods for creating a validator from Authorisation
 * Server  metadata or issuer URL, and the registered OAuth 2.0 client
 * information:
 *
 * <ul>
 *     <li>{@link #create(AuthorizationServerMetadata, ClientInformation)}
 *     <li>{@link #create(Issuer, ClientInformation)}
 * </ul>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM)
 * </ul>
 */
@ThreadSafe
public class JARMValidator extends AbstractJWTValidator implements ClockSkewAware {
	
	
	/**
	 * Creates a new JARM validator for RSA or EC signed authorisation
	 * responses where the Authorisation Server's JWK set is specified by
	 * value.
	 *
	 * @param expectedIssuer The expected issuer (Authorisation Server).
	 *                       Must not be {@code null}.
	 * @param clientID       The client ID. Must not be {@code null}.
	 * @param expectedJWSAlg The expected RSA or EC JWS algorithm. Must not
	 *                       be {@code null}.
	 * @param jwkSet         The Authorisation Server JWK set. Must not be
	 *                       {@code null}.
	 */
	public JARMValidator(final Issuer expectedIssuer,
			     final ClientID clientID,
			     final JWSAlgorithm expectedJWSAlg,
			     final JWKSet jwkSet) {
		
		this(expectedIssuer, clientID, new JWSVerificationKeySelector(expectedJWSAlg, new ImmutableJWKSet(jwkSet)),  null);
	}
	
	
	/**
	 * Creates a new JARM validator for RSA or EC signed authorisation
	 * responses where the Authorisation Server's JWK set is specified by
	 * URL.
	 *
	 * @param expectedIssuer The expected issuer (Authorisation Server).
	 *                       Must not be {@code null}.
	 * @param clientID       The client ID. Must not be {@code null}.
	 * @param expectedJWSAlg The expected RSA or EC JWS algorithm. Must not
	 *                       be {@code null}.
	 * @param jwkSetURI      The OpenID Provider JWK set URL. Must not be
	 *                       {@code null}.
	 */
	public JARMValidator(final Issuer expectedIssuer,
			     final ClientID clientID,
			     final JWSAlgorithm expectedJWSAlg,
			     final URL jwkSetURI) {
		
		this(expectedIssuer, clientID, expectedJWSAlg, jwkSetURI, null);
	}
	
	
	/**
	 * Creates a new JARM validator for RSA or EC signed authorisation
	 * responses where the Authorisation Server's JWK set is specified by
	 * URL. Permits setting of a specific resource retriever (HTTP client)
	 * for the JWK set.
	 *
	 * @param expectedIssuer    The expected issuer (Authorisation Server).
	 *                          Must not be {@code null}.
	 * @param clientID          The client ID. Must not be {@code null}.
	 * @param expectedJWSAlg    The expected RSA or EC JWS algorithm. Must
	 *                          not be {@code null}.
	 * @param jwkSetURI         The Authorisation Server JWK set URL. Must
	 *                          not be {@code null}.
	 * @param resourceRetriever For retrieving the Authorisation Server JWK
	 *                          from the specified URL. If {@code null} the
	 *                          {@link com.nimbusds.jose.util.DefaultResourceRetriever
	 *                          default retriever} will be used, with
	 *                          preset HTTP connect timeout, HTTP read
	 *                          timeout and entity size limit.
	 */
	public JARMValidator(final Issuer expectedIssuer,
			     final ClientID clientID,
			     final JWSAlgorithm expectedJWSAlg,
			     final URL jwkSetURI,
			     final ResourceRetriever resourceRetriever) {
		
		this(expectedIssuer, clientID, new JWSVerificationKeySelector(expectedJWSAlg, new RemoteJWKSet(jwkSetURI, resourceRetriever)),  null);
	}
	
	
	/**
	 * Creates a new JARM validator for HMAC protected authorisation
	 * responses.
	 *
	 * @param expectedIssuer The expected issuer (Authorisation Server).
	 *                       Must not be {@code null}.
	 * @param clientID       The client ID. Must not be {@code null}.
	 * @param expectedJWSAlg The expected HMAC JWS algorithm. Must not be
	 *                       {@code null}.
	 * @param clientSecret   The client secret. Must not be {@code null}.
	 */
	public JARMValidator(final Issuer expectedIssuer,
			     final ClientID clientID,
			     final JWSAlgorithm expectedJWSAlg,
			     final Secret clientSecret) {
		
		this(expectedIssuer, clientID, new JWSVerificationKeySelector(expectedJWSAlg, new ImmutableSecret(clientSecret.getValueBytes())), null);
	}
	
	
	/**
	 * Creates a new JARM validator.
	 *
	 * @param expectedIssuer The expected issuer (Authorisation Server).
	 *                       Must not be {@code null}.
	 * @param clientID       The client ID. Must not be {@code null}.
	 * @param jwsKeySelector The key selector for JWS verification, must
	 *                       not be {@code null}.
	 * @param jweKeySelector The key selector for JWE decryption,
	 *                       {@code null} if encrypted authorisation
	 *                       responses are not expected.
	 */
	public JARMValidator(final Issuer expectedIssuer,
			     final ClientID clientID,
			     final JWSKeySelector jwsKeySelector,
			     final JWEKeySelector jweKeySelector) {
		
		super(expectedIssuer, clientID, jwsKeySelector, jweKeySelector);
	}
	
	
	/**
	 * Validates the specified JWT-secured authorisation response.
	 *
	 * @param jwtResponseString The JWT-secured authorisation response
	 *                          string. Must not be {@code null}.
	 *
	 * @return The claims set of the verified JWT.
	 *
	 * @throws BadJOSEException If the JWT is invalid or expired.
	 * @throws JOSEException    If an internal JOSE exception was
	 *                          encountered.
	 */
	public JWTClaimsSet validate(final String jwtResponseString)
		throws BadJOSEException, JOSEException {
		
		try {
			return validate(JWTParser.parse(jwtResponseString));
		} catch (ParseException e) {
			throw new BadJOSEException("Invalid JWT: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Validates the specified JWT-secured authorisation response.
	 *
	 * @param jwtResponse The JWT-secured authorisation response. Must not
	 *                    be {@code null}.
	 *
	 * @return The claims set of the verified JWT.
	 *
	 * @throws BadJOSEException If the JWT is invalid or expired.
	 * @throws JOSEException    If an internal JOSE exception was
	 *                          encountered.
	 */
	public JWTClaimsSet validate(final JWT jwtResponse)
		throws BadJOSEException, JOSEException {
		
		if (jwtResponse instanceof SignedJWT) {
			return validate((SignedJWT) jwtResponse);
		} else if (jwtResponse instanceof EncryptedJWT) {
			return validate((EncryptedJWT) jwtResponse);
		} else if (jwtResponse instanceof PlainJWT) {
			throw new BadJWTException("The JWT must not be plain (unsecured)");
		} else {
			throw new BadJOSEException("Unexpected JWT type: " + jwtResponse.getClass());
		}
	}
	
	
	/**
	 * Verifies the specified signed authorisation response.
	 *
	 * @param jwtResponse The JWT-secured authorisation response. Must not
	 *                    be {@code null}.
	 *
	 * @return The claims set of the verified JWT.
	 *
	 * @throws BadJOSEException If the JWT is invalid or expired.
	 * @throws JOSEException    If an internal JOSE exception was
	 *                          encountered.
	 */
	private JWTClaimsSet validate(final SignedJWT jwtResponse)
		throws BadJOSEException, JOSEException {
		
		if (getJWSKeySelector() == null) {
			throw new BadJWTException("Verification of signed JWTs not configured");
		}
		
		ConfigurableJWTProcessor<?> jwtProcessor = new DefaultJWTProcessor();
		jwtProcessor.setJWSKeySelector(getJWSKeySelector());
		jwtProcessor.setJWTClaimsSetVerifier(new JARMClaimsVerifier(getExpectedIssuer(), getClientID(), getMaxClockSkew()));
		return jwtProcessor.process(jwtResponse, null);
	}
	
	
	/**
	 * Verifies the specified signed and encrypted authorisation response.
	 *
	 * @param jwtResponse The JWT-secured authorisation response. Must not
	 *                    be {@code null}.
	 *
	 * @return The claims set of the verified JWT.
	 *
	 * @throws BadJOSEException If the JWT is invalid or expired.
	 * @throws JOSEException    If an internal JOSE exception was
	 *                          encountered.
	 */
	private JWTClaimsSet validate(final EncryptedJWT jwtResponse)
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
		jwtProcessor.setJWTClaimsSetVerifier(new JARMClaimsVerifier(getExpectedIssuer(), getClientID(), getMaxClockSkew()));
		
		return jwtProcessor.process(jwtResponse, null);
	}
	
	
	/**
	 * Creates a key selector for JWS verification.
	 *
	 * @param asMetadata The Authorisation Server metadata. Must not be
	 *                   {@code null}.
	 * @param clientInfo The OAuth 2.0 client information. Must not be
	 *                   {@code null}.
	 *
	 * @return The JWS key selector.
	 *
	 * @throws GeneralException If the supplied Authorisation Server
	 *                          metadata or OAuth 2.0 client information
	 *                          are missing a required parameter or
	 *                          inconsistent.
	 */
	protected static JWSKeySelector createJWSKeySelector(final com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata asMetadata,
							     final ClientInformation clientInfo)
		throws GeneralException {
		
		final JWSAlgorithm expectedJWSAlg = clientInfo.getMetadata().getAuthorizationJWSAlg();
		
		if (asMetadata.getAuthorizationJWSAlgs() == null) {
			throw new GeneralException("Missing Authorization Server authorization_signing_alg_values_supported parameter");
		}
		
		if (! asMetadata.getAuthorizationJWSAlgs().contains(expectedJWSAlg)) {
			throw new GeneralException("The Authorization Server doesn't support " + expectedJWSAlg + " authorization responses");
		}
		
		if (Algorithm.NONE.equals(expectedJWSAlg)) {
			// Skip creation of JWS key selector, plain ID tokens expected
			return null;
			
		} else if (JWSAlgorithm.Family.RSA.contains(expectedJWSAlg) || JWSAlgorithm.Family.EC.contains(expectedJWSAlg)) {
			
			URL jwkSetURL;
			try {
				jwkSetURL = asMetadata.getJWKSetURI().toURL();
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
	 * @param asMetadata      The Authorisation Server metadata. Must not
	 *                        be {@code null}.
	 * @param clientInfo      The OAuth 2.0 client information. Must not be
	 *                        {@code null}.
	 * @param clientJWKSource The client private JWK source, {@code null}
	 *                        if encrypted JWT-secured authorisation
	 *                        responses are not expected.
	 *
	 * @return The JWE key selector.
	 *
	 * @throws GeneralException If the supplied Authorisation Server
	 *                          metadata or OAuth 2.0 client information
	 *                          are missing a required parameter or
	 *                          inconsistent.
	 */
	protected static JWEKeySelector createJWEKeySelector(final AuthorizationServerMetadata asMetadata,
							     final ClientInformation clientInfo,
							     final JWKSource clientJWKSource)
		throws GeneralException {
		
		final JWEAlgorithm expectedJWEAlg = clientInfo.getMetadata().getAuthorizationJWEAlg();
		final EncryptionMethod expectedJWEEnc = clientInfo.getMetadata().getAuthorizationJWEEnc();
		
		if (expectedJWEAlg == null) {
			// Encrypted JWTs not expected
			return null;
		}
		
		if (expectedJWEEnc == null) {
			throw new GeneralException("Missing required authorization response JWE encryption method for " + expectedJWEAlg);
		}
		
		if (asMetadata.getAuthorizationJWEAlgs() == null || ! asMetadata.getAuthorizationJWEAlgs().contains(expectedJWEAlg)) {
			throw new GeneralException("The Authorization Server doesn't support " + expectedJWEAlg + " authorization responses");
		}
		
		if (asMetadata.getAuthorizationJWEEncs() == null || ! asMetadata.getAuthorizationJWEEncs().contains(expectedJWEEnc)) {
			throw new GeneralException("The Authorization Server doesn't support " + expectedJWEAlg + " / " + expectedJWEEnc + " authorization responses");
		}
		
		return new JWEDecryptionKeySelector(expectedJWEAlg, expectedJWEEnc, clientJWKSource);
	}
	
	
	/**
	 * Creates a new JARM validator for the specified Authorisation Server
	 * metadata and OAuth 2.0 client registration.
	 *
	 * @param asMetadata      The Authorisation Server metadata. Must not
	 *                        be {@code null}.
	 * @param clientInfo      The OAuth 2.0 client registration. Must not
	 *                        be {@code null}.
	 * @param clientJWKSource The client private JWK source, {@code null}
	 *                        if encrypted authorisation responses are not
	 *                        expected.
	 *
	 * @return The JARM validator.
	 *
	 * @throws GeneralException If the supplied Authorisation Server
	 *                          metadata or OAuth 2.0 client information
	 *                          are missing a required parameter or
	 *                          inconsistent.
	 */
	public static JARMValidator create(final AuthorizationServerMetadata asMetadata,
					   final ClientInformation clientInfo,
					   final JWKSource clientJWKSource)
		throws GeneralException {
		
		// Create JWS key selector, unless id_token alg = none
		final JWSKeySelector jwsKeySelector = createJWSKeySelector(asMetadata, clientInfo);
		
		// Create JWE key selector if encrypted ID tokens are expected
		final JWEKeySelector jweKeySelector = createJWEKeySelector(asMetadata, clientInfo, clientJWKSource);
		
		return new JARMValidator(asMetadata.getIssuer(), clientInfo.getID(), jwsKeySelector, jweKeySelector);
	}
	
	
	/**
	 * Creates a new JARM validator for the specified Authorisation Server
	 * metadata and OAuth 2.0 client registration.
	 *
	 * @param asMetadata The Authorisation Server metadata. Must not be
	 *                   {@code null}.
	 * @param clientInfo The OAuth 2.0 client registration. Must not be
	 *                   {@code null}.
	 *
	 * @return The JARM validator.
	 *
	 * @throws GeneralException If the supplied Authorisation Server
	 *                          metadata or OAuth 2.0 client information
	 *                          are missing a required parameter or
	 *                          inconsistent.
	 */
	public static JARMValidator create(final AuthorizationServerMetadata asMetadata,
					   final ClientInformation clientInfo)
		throws GeneralException {
		
		return create(asMetadata, clientInfo, null);
	}
	
	
	/**
	 * Creates a new JARM validator for the specified Authorisation Server
	 * or OpenID Provider, which must publish its metadata at
	 * {@code [issuer-url]/.well-known/oauth-authorization-server} resp.
	 * {@code [issuer-url]/.well-known/openid-configuration}.
	 *
	 * @param issuer     The Authorisation Server / OpenID Provider issuer 
	 *                   identifier. Must not be {@code null}.
	 * @param clientInfo The OAuth 2.0 client registration. Must not be
	 *                   {@code null}.
	 *
	 * @return The JARM validator.
	 *
	 * @throws GeneralException If the resolved Authorisation Server / 
	 *                          OpenID Provider metadata is invalid.
	 * @throws IOException      On an HTTP exception.
	 */
	public static JARMValidator create(final Issuer issuer,
					   final ClientInformation clientInfo)
		throws GeneralException, IOException {
		
		return create(issuer, clientInfo, null, 0, 0);
	}
	
	
	/**
	 * Creates a new JARM validator for the specified Authorisation Server
	 * or OpenID Provider, which must publish its metadata at
	 * {@code [issuer-url]/.well-known/oauth-authorization-server} resp.
	 * {@code [issuer-url]/.well-known/openid-configuration}.
	 *
	 * @param issuer          The Authorisation Server / OpenID Provider 
	 *                        issuer identifier. Must not be {@code null}.
	 * @param clientInfo      The OAuth 2.0 client registration. Must not 
	 *                        be {@code null}.
	 * @param clientJWKSource The client private JWK source, {@code null}
	 *                        if encrypted authorisation responses are not 
	 *                        expected.
	 * @param connectTimeout  The HTTP connect timeout, in milliseconds.
	 *                        Zero implies no timeout. Must not be
	 *                        negative.
	 * @param readTimeout     The HTTP response read timeout, in
	 *                        milliseconds. Zero implies no timeout. Must
	 *                        not be negative.
	 *
	 * @return The JARM validator.
	 *
	 * @throws GeneralException If the resolved Authorisation Server / 
	 *                          OpenID Provider metadata is invalid.
	 * @throws IOException      On an HTTP exception.
	 */
	public static JARMValidator create(final Issuer issuer,
					   final ClientInformation clientInfo,
					   final JWKSource clientJWKSource,
					   final int connectTimeout,
					   final int readTimeout)
		throws GeneralException, IOException {
		
		AuthorizationServerMetadata asMetadata;
		
		try {
			// Try OP well-known URL first
			asMetadata = OIDCProviderMetadata.resolve(issuer, connectTimeout, readTimeout);
			
		} catch (Exception e) {
			
			// Retry with AS well-known URL
			asMetadata = AuthorizationServerMetadata.resolve(issuer, connectTimeout, readTimeout); 
		}
		
		return create(asMetadata, clientInfo, clientJWKSource);
	}
}
