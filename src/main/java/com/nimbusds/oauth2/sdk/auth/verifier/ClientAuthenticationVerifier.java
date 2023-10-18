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


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.proc.JWSVerifierFactory;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.auth.*;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.oauth2.sdk.util.ListUtils;
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils;
import net.jcip.annotations.ThreadSafe;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;


/**
 * Client authentication verifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 2.3.1 and 3.2.1.
 *     <li>OpenID Connect Core 1.0, section 9.
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523).
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (RFC 8705), section 2.
 * </ul>
 */
@ThreadSafe
public class ClientAuthenticationVerifier<T> {


	/**
	 * The client credentials selector.
	 */
	private final ClientCredentialsSelector<T> clientCredentialsSelector;
	
	
	/**
	 * Optional client X.509 certificate binding verifier for
	 * {@code tls_client_auth}.
	 * @deprecated Replaced by pkiCertBindingVerifier
	 */
	@Deprecated
	private final ClientX509CertificateBindingVerifier<T> certBindingVerifier;


	/**
	 * Optional client X.509 certificate binding verifier for
	 * {@code tls_client_auth}.
	 */
	private final PKIClientX509CertificateBindingVerifier<T> pkiCertBindingVerifier;


	/**
	 * The JWT assertion claims set verifier.
	 */
	private final JWTAuthenticationClaimsSetVerifier claimsSetVerifier;


	/**
	 * Optional expended JWT ID (jti) checker.
	 */
	private final ExpendedJTIChecker<T> expendedJTIChecker;


	/**
	 * JWS verifier factory for private_key_jwt authentication.
	 */
	private final JWSVerifierFactory jwsVerifierFactory = new DefaultJWSVerifierFactory();


	/**
	 * Creates a new client authentication verifier.
	 *
	 * @param clientCredentialsSelector The client credentials selector.
	 *                                  Must not be {@code null}.
	 * @param certBindingVerifier       Optional client X.509 certificate
	 *                                  binding verifier for
	 *                                  {@code tls_client_auth},
	 *                                  {@code null} if not supported.
	 * @param expectedAudience          The permitted audience (aud) claim
	 *                                  values in JWT authentication
	 *                                  assertions. Must not be empty or
	 *                                  {@code null}. Should typically
	 *                                  contain the token endpoint URI and
	 *                                  for OpenID provider it may also
	 *                                  include the issuer URI.
	 *
	 * @deprecated Use the constructor with {@link PKIClientX509CertificateBindingVerifier}
	 */
	@Deprecated
	public ClientAuthenticationVerifier(final ClientCredentialsSelector<T> clientCredentialsSelector,
					    final ClientX509CertificateBindingVerifier<T> certBindingVerifier,
					    final Set<Audience> expectedAudience) {

		claimsSetVerifier = new JWTAuthenticationClaimsSetVerifier(expectedAudience);

		if (clientCredentialsSelector == null) {
			throw new IllegalArgumentException("The client credentials selector must not be null");
		}
		
		this.certBindingVerifier = certBindingVerifier;
		this.pkiCertBindingVerifier = null;

		this.clientCredentialsSelector = clientCredentialsSelector;

		this.expendedJTIChecker = null;
	}

	
	/**
	 * Creates a new client authentication verifier without support for
	 * {@code tls_client_auth}.
	 *
	 * @param clientCredentialsSelector The client credentials selector.
	 *                                  Must not be {@code null}.
	 * @param expectedAudience          The permitted audience (aud) claim
	 *                                  values in JWT authentication
	 *                                  assertions. Must not be empty or
	 *                                  {@code null}. Should typically
	 *                                  contain the token endpoint URI and
	 *                                  for OpenID provider it may also
	 *                                  include the issuer URI.
	 */
	public ClientAuthenticationVerifier(final ClientCredentialsSelector<T> clientCredentialsSelector,
					    final Set<Audience> expectedAudience) {

		this(clientCredentialsSelector, expectedAudience, null);
	}


	/**
	 * Creates a new client authentication verifier without support for
	 * {@code tls_client_auth}.
	 *
	 * @param clientCredentialsSelector The client credentials selector.
	 *                                  Must not be {@code null}.
	 * @param expectedAudience          The permitted audience (aud) claim
	 *                                  values in JWT authentication
	 *                                  assertions. Must not be empty or
	 *                                  {@code null}. Should typically
	 *                                  contain the token endpoint URI and
	 *                                  for OpenID provider it may also
	 *                                  include the issuer URI.
	 * @param expendedJTIChecker        Optional expended JWT ID (jti)
	 *                                  claim checker to prevent JWT
	 *                                  replay, {@code null} if none.
	 */
	public ClientAuthenticationVerifier(final ClientCredentialsSelector<T> clientCredentialsSelector,
					    final Set<Audience> expectedAudience,
					    final ExpendedJTIChecker<T> expendedJTIChecker) {

		claimsSetVerifier = new JWTAuthenticationClaimsSetVerifier(expectedAudience);

		if (clientCredentialsSelector == null) {
			throw new IllegalArgumentException("The client credentials selector must not be null");
		}

		this.certBindingVerifier = null;
		this.pkiCertBindingVerifier = null;

		this.clientCredentialsSelector = clientCredentialsSelector;

		this.expendedJTIChecker = expendedJTIChecker;
	}
	

	/**
	 * Creates a new client authentication verifier.
	 *
	 * @param clientCredentialsSelector The client credentials selector.
	 *                                  Must not be {@code null}.
	 * @param pkiCertBindingVerifier    Optional client X.509 certificate
	 *                                  binding verifier for
	 *                                  {@code tls_client_auth},
	 *                                  {@code null} if not supported.
	 * @param expectedAudience          The permitted audience (aud) claim
	 *                                  values in JWT authentication
	 *                                  assertions. Must not be empty or
	 *                                  {@code null}. Should typically
	 *                                  contain the token endpoint URI and
	 *                                  for OpenID provider it may also
	 *                                  include the issuer URI.
	 */
	public ClientAuthenticationVerifier(final ClientCredentialsSelector<T> clientCredentialsSelector,
					    final PKIClientX509CertificateBindingVerifier<T> pkiCertBindingVerifier,
					    final Set<Audience> expectedAudience) {

		this(clientCredentialsSelector, pkiCertBindingVerifier, expectedAudience, null);
	}


	/**
	 * Creates a new client authentication verifier.
	 *
	 * @param clientCredentialsSelector The client credentials selector.
	 *                                  Must not be {@code null}.
	 * @param pkiCertBindingVerifier    Optional client X.509 certificate
	 *                                  binding verifier for
	 *                                  {@code tls_client_auth},
	 *                                  {@code null} if not supported.
	 * @param expectedAudience          The permitted audience (aud) claim
	 *                                  values in JWT authentication
	 *                                  assertions. Must not be empty or
	 *                                  {@code null}. Should typically
	 *                                  contain the token endpoint URI and
	 *                                  for OpenID provider it may also
	 *                                  include the issuer URI.
	 * @param expendedJTIChecker        Optional expended JWT ID (jti)
	 *                                  claim checker to prevent JWT
	 *                                  replay, {@code null} if none.
	 */
	public ClientAuthenticationVerifier(final ClientCredentialsSelector<T> clientCredentialsSelector,
					    final PKIClientX509CertificateBindingVerifier<T> pkiCertBindingVerifier,
					    final Set<Audience> expectedAudience,
					    final ExpendedJTIChecker<T> expendedJTIChecker) {

		claimsSetVerifier = new JWTAuthenticationClaimsSetVerifier(expectedAudience);

		if (clientCredentialsSelector == null) {
			throw new IllegalArgumentException("The client credentials selector must not be null");
		}

		this.certBindingVerifier = null;
		this.pkiCertBindingVerifier = pkiCertBindingVerifier;

		this.clientCredentialsSelector = clientCredentialsSelector;

		this.expendedJTIChecker = expendedJTIChecker;
	}


	/**
	 * Returns the client credentials selector.
	 *
	 * @return The client credentials selector.
	 */
	public ClientCredentialsSelector<T> getClientCredentialsSelector() {

		return clientCredentialsSelector;
	}
	
	
	/**
	 * Returns the client X.509 certificate binding verifier for use in
	 * {@code tls_client_auth}.
	 *
	 * @return The client X.509 certificate binding verifier, {@code null}
	 *         if not specified.
	 * @deprecated See {@link PKIClientX509CertificateBindingVerifier}
	 */
	@Deprecated
	public ClientX509CertificateBindingVerifier<T> getClientX509CertificateBindingVerifier() {
		
		return certBindingVerifier;
	}
	
	
	/**
	 * Returns the client X.509 certificate binding verifier for use in
	 * {@code tls_client_auth}.
	 *
	 * @return The client X.509 certificate binding verifier, {@code null}
	 *         if not specified.
	 */
	public PKIClientX509CertificateBindingVerifier<T> getPKIClientX509CertificateBindingVerifier() {
		
		return pkiCertBindingVerifier;
	}
	
	
	/**
	 * Returns the permitted audience values in JWT authentication
	 * assertions.
	 *
	 * @return The permitted audience (aud) claim values.
	 */
	public Set<Audience> getExpectedAudience() {

		return claimsSetVerifier.getExpectedAudience();
	}


	/**
	 * Returns the optional expended JWT ID (jti) claim checker to prevent
	 * JWT replay.
	 *
	 * @return The expended JWT ID (jti) claim checker, {@code null} if
	 *         none.
	 */
	public ExpendedJTIChecker<T> getExpendedJTIChecker() {

		return expendedJTIChecker;
	}


	private static List<Secret> removeNullOrErased(final List<Secret> secrets) {
		List<Secret> allSet = ListUtils.removeNullItems(secrets);
		if (allSet == null) {
			return null;
		}
		List<Secret> out = new LinkedList<>();
		for (Secret secret: secrets) {
			if (secret.getValue() != null && secret.getValueBytes() != null) {
				out.add(secret);
			}
		}
		return out;
	}


	private void preventJWTReplay(final JWTID jti, final Context<T> context)
		throws InvalidClientException {

		if (jti == null || getExpendedJTIChecker() == null) {
			return;
		}

		if (getExpendedJTIChecker().isExpended(jti, context)) {
			throw new InvalidClientException("Detected JWT ID replay");
		}
	}


	private void markExpended(final JWTID jti, final Date exp, final Context<T> context) {

		if (jti == null || getExpendedJTIChecker() == null) {
			return;
		}

		getExpendedJTIChecker().markExpended(jti, exp, context);
	}


	/**
	 * Verifies a client authentication request.
	 *
	 * @param clientAuth The client authentication. Must not be
	 *                   {@code null}.
	 * @param hints      Optional hints to the verifier, empty set of
	 *                   {@code null} if none.
	 * @param context    Additional context to be passed to the client
	 *                   credentials selector. May be {@code null}.
	 *
	 * @throws InvalidClientException If the client authentication is
	 *                                invalid, typically due to bad
	 *                                credentials.
	 * @throws JOSEException          If authentication failed due to an
	 *                                internal JOSE / JWT processing
	 *                                exception.
	 */
	public void verify(final ClientAuthentication clientAuth, final Set<Hint> hints, final Context<T> context)
		throws InvalidClientException, JOSEException {

		if (clientAuth instanceof PlainClientSecret) {

			List<Secret> secretCandidates = ListUtils.removeNullItems(
				clientCredentialsSelector.selectClientSecrets(
					clientAuth.getClientID(),
					clientAuth.getMethod(),
					context
				)
			);

			if (CollectionUtils.isEmpty(secretCandidates)) {
				throw InvalidClientException.NO_REGISTERED_SECRET;
			}

			PlainClientSecret plainAuth = (PlainClientSecret)clientAuth;

			for (Secret candidate: secretCandidates) {
				
				// Constant time, SHA-256 based, unless overridden
				if (candidate.equals(plainAuth.getClientSecret())) {
					return; // success
				}
			}

			throw InvalidClientException.BAD_SECRET;

		} else if (clientAuth instanceof ClientSecretJWT) {

			ClientSecretJWT jwtAuth = (ClientSecretJWT) clientAuth;

			// Check claims first before requesting secret from backend
			JWTAuthenticationClaimsSet jwtAuthClaims = jwtAuth.getJWTAuthenticationClaimsSet();

			preventJWTReplay(jwtAuthClaims.getJWTID(), context);

			try {
				claimsSetVerifier.verify(jwtAuthClaims.toJWTClaimsSet(), null);
			} catch (BadJWTException e) {
				throw new InvalidClientException("Bad / expired JWT claims: " + e.getMessage());
			}

			List<Secret> secretCandidates = removeNullOrErased(
				clientCredentialsSelector.selectClientSecrets(
					clientAuth.getClientID(),
					clientAuth.getMethod(),
					context
				)
			);

			if (CollectionUtils.isEmpty(secretCandidates)) {
				throw InvalidClientException.NO_REGISTERED_SECRET;
			}

			SignedJWT assertion = jwtAuth.getClientAssertion();

			for (Secret candidate : secretCandidates) {

				boolean valid = assertion.verify(new MACVerifier(candidate.getValueBytes()));

				if (valid) {

					markExpended(jwtAuthClaims.getJWTID(), jwtAuthClaims.getExpirationTime(), context);

					return; // success
				}
			}

			throw InvalidClientException.BAD_JWT_HMAC;

		} else if (clientAuth instanceof PrivateKeyJWT) {
			
			PrivateKeyJWT jwtAuth = (PrivateKeyJWT) clientAuth;
			
			// Check claims first before requesting / retrieving public keys
			JWTAuthenticationClaimsSet jwtAuthClaims = jwtAuth.getJWTAuthenticationClaimsSet();

			preventJWTReplay(jwtAuthClaims.getJWTID(), context);

			try {
				claimsSetVerifier.verify(jwtAuthClaims.toJWTClaimsSet(), null);
			} catch (BadJWTException e) {
				throw new InvalidClientException("Bad / expired JWT claims: " + e.getMessage());
			}
			
			List<? extends PublicKey> keyCandidates = ListUtils.removeNullItems(
				clientCredentialsSelector.selectPublicKeys(
					jwtAuth.getClientID(),
					jwtAuth.getMethod(),
					jwtAuth.getClientAssertion().getHeader(),
					false,        // don't force refresh if we have a remote JWK set;
					// selector may however do so if it encounters an unknown key ID
					context
				)
			);
			
			if (CollectionUtils.isEmpty(keyCandidates)) {
				throw InvalidClientException.NO_MATCHING_JWK;
			}
			
			SignedJWT assertion = jwtAuth.getClientAssertion();
			
			for (PublicKey candidate : keyCandidates) {
				
				JWSVerifier jwsVerifier = jwsVerifierFactory.createJWSVerifier(
					jwtAuth.getClientAssertion().getHeader(),
					candidate);
				
				boolean valid = assertion.verify(jwsVerifier);
				
				if (valid) {
					markExpended(jwtAuthClaims.getJWTID(), jwtAuthClaims.getExpirationTime(), context);
					return; // success
				}
			}
			
			// Second pass
			if (hints != null && hints.contains(Hint.CLIENT_HAS_REMOTE_JWK_SET)) {
				// Client possibly registered JWK set URL with keys that have no IDs
				// force JWK set reload from URL and retry
				keyCandidates = ListUtils.removeNullItems(
					clientCredentialsSelector.selectPublicKeys(
						jwtAuth.getClientID(),
						jwtAuth.getMethod(),
						jwtAuth.getClientAssertion().getHeader(),
						true, // force reload of remote JWK set
						context
					)
				);
				
				if (CollectionUtils.isEmpty(keyCandidates)) {
					throw InvalidClientException.NO_MATCHING_JWK;
				}
				
				assertion = jwtAuth.getClientAssertion();
				
				for (PublicKey candidate : keyCandidates) {
					
					JWSVerifier jwsVerifier = jwsVerifierFactory.createJWSVerifier(
						jwtAuth.getClientAssertion().getHeader(),
						candidate);
					
					boolean valid = assertion.verify(jwsVerifier);
					
					if (valid) {
						markExpended(jwtAuthClaims.getJWTID(), jwtAuthClaims.getExpirationTime(), context);
						return; // success
					}
				}
			}
			
			throw InvalidClientException.BAD_JWT_SIGNATURE;
			
		} else if (clientAuth instanceof SelfSignedTLSClientAuthentication) {
			
			SelfSignedTLSClientAuthentication tlsClientAuth = (SelfSignedTLSClientAuthentication) clientAuth;
			
			X509Certificate clientCert = tlsClientAuth.getClientX509Certificate();
			
			if (clientCert == null) {
				// Sanity check
				throw new InvalidClientException("Missing client X.509 certificate");
			}
			
			// Self-signed certs bound to registered public key in client jwks / jwks_uri
			List<? extends PublicKey> keyCandidates = ListUtils.removeNullItems(
				clientCredentialsSelector.selectPublicKeys(
					tlsClientAuth.getClientID(),
					tlsClientAuth.getMethod(),
					null,
					false, // don't force refresh if we have a remote JWK set;
					// selector may however do so if it encounters an unknown key ID
					context
				)
			);
			
			if (CollectionUtils.isEmpty(keyCandidates)) {
				throw InvalidClientException.NO_MATCHING_JWK;
			}
			
			for (PublicKey candidate : keyCandidates) {
				
				boolean valid = X509CertificateUtils.publicKeyMatches(clientCert, candidate);
				
				if (valid) {
					return; // success
				}
			}
			
			// Second pass
			if (hints != null && hints.contains(Hint.CLIENT_HAS_REMOTE_JWK_SET)) {
				// Client possibly registered JWK set URL with keys that have no IDs
				// force JWK set reload from URL and retry
				keyCandidates = ListUtils.removeNullItems(
					clientCredentialsSelector.selectPublicKeys(
						tlsClientAuth.getClientID(),
						tlsClientAuth.getMethod(),
						null,
						true, // force reload of remote JWK set
						context
					)
				);
				
				if (CollectionUtils.isEmpty(keyCandidates)) {
					throw InvalidClientException.NO_MATCHING_JWK;
				}
				
				for (PublicKey candidate : keyCandidates) {
					
					if (candidate == null) {
						continue; // skip
					}
					
					boolean valid = X509CertificateUtils.publicKeyMatches(clientCert, candidate);
					
					if (valid) {
						return; // success
					}
				}
			}
			
			throw InvalidClientException.BAD_SELF_SIGNED_CLIENT_CERTIFICATE;
			
		} else if (clientAuth instanceof PKITLSClientAuthentication) {
			
			PKITLSClientAuthentication tlsClientAuth = (PKITLSClientAuthentication) clientAuth;
			if (pkiCertBindingVerifier != null) {
				pkiCertBindingVerifier.verifyCertificateBinding(
						clientAuth.getClientID(),
						tlsClientAuth.getClientX509Certificate(),
						context);
				
			} else if (certBindingVerifier != null) {
				certBindingVerifier.verifyCertificateBinding(
						clientAuth.getClientID(),
						tlsClientAuth.getClientX509CertificateSubjectDN(),
						context);
			} else {
				throw new InvalidClientException("Mutual TLS client Authentication (tls_client_auth) not supported");
			}
		} else {
			throw new RuntimeException("Unexpected client authentication: " + clientAuth.getMethod());
		}
	}
}
