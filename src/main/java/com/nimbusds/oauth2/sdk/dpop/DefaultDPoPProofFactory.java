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

package com.nimbusds.oauth2.sdk.dpop;


import java.net.URI;
import java.security.Provider;
import java.util.Date;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;


/**
 * Default DPoP proof factory.
 */
public class DefaultDPoPProofFactory implements DPoPProofFactory {
	
	
	/**
	 * The public signing JWK.
	 */
	private final JWK publicJWK;
	
	
	/**
	 * The signing JWS algorithm.
	 */
	private final JWSAlgorithm jwsAlg;
	
	
	/**
	 * The JWS signer.
	 */
	private final JWSSigner jwsSigner;
	
	
	/**
	 * Creates a new DPoP proof factory using the default JCA provider.
	 *
	 * @param jwk    The signing JWK. Must not be {@code null}.
	 * @param jwsAlg The signing JWS algorithm. Must not be {@code null}.
	 *
	 * @throws JOSEException If signer creation failed.
	 */
	public DefaultDPoPProofFactory(final JWK jwk, final JWSAlgorithm jwsAlg)
		throws JOSEException {
		
		this(jwk, jwsAlg, null);
	}
	
	
	/**
	 * Creates a new DPoP proof factory.
	 *
	 * @param jwk         The signing JWK. Must not be {@code null}.
	 * @param jwsAlg      The signing JWS algorithm. Must not be
	 *                    {@code null}.
	 * @param jcaProvider The JCA provider to use for signing, {@code null}
	 *                    to use the default.
	 *
	 * @throws JOSEException If signer creation failed.
	 */
	public DefaultDPoPProofFactory(final JWK jwk, final JWSAlgorithm jwsAlg, final Provider jcaProvider)
		throws JOSEException {
		
		if (! jwk.isPrivate()) {
			throw new IllegalArgumentException("The JWK must include private parameters");
		}
		
		if (! JWSAlgorithm.Family.SIGNATURE.contains(jwsAlg)) {
			throw new IllegalArgumentException("The JWS algorithm must be for a digital signature");
		}
		
		this.jwsAlg = jwsAlg;
		
		DefaultJWSSignerFactory factory = new DefaultJWSSignerFactory();
		if (jcaProvider != null) {
			factory.getJCAContext().setProvider(jcaProvider);
		}
		jwsSigner = factory.createJWSSigner(jwk, jwsAlg);
		
		publicJWK = jwk.toPublicJWK();
	}
	
	
	/**
	 * Returns the configured public signing JWK.
	 *
	 * @return The public signing JWK.
	 */
	public JWK getPublicJWK() {
		return publicJWK;
	}
	
	
	/**
	 * Returns the configured JWS algorithm.
	 *
	 * @return The JWS algorithm.
	 */
	public JWSAlgorithm getJWSAlgorithm() {
		return jwsAlg;
	}
	
	
	/**
	 * Returns the JWS signer.
	 *
	 * @return The JWS signer.
	 */
	public JWSSigner getJWSSigner() {
		return jwsSigner;
	}
	
	
	@Override
	public SignedJWT createDPoPJWT(final String htm,
				       final URI htu)
		throws JOSEException {
		
		return createDPoPJWT(htm, htu, null, null);
	}
	
	
	@Override
	public SignedJWT createDPoPJWT(final String htm,
				       final URI htu,
				       final Nonce nonce)
		throws JOSEException {
		
		return createDPoPJWT(htm, htu, null, nonce);
	}
	
	
	@Override
	public SignedJWT createDPoPJWT(final String htm,
				       final URI htu,
				       final AccessToken accessToken)
		throws JOSEException {
		
		return createDPoPJWT(htm, htu, accessToken, null);
	}
	
	
	@Override
	public SignedJWT createDPoPJWT(final String htm,
				       final URI htu,
				       final AccessToken accessToken,
				       final Nonce nonce)
		throws JOSEException {
		
		return createDPoPJWT(new JWTID(MINIMAL_JTI_BYTE_LENGTH), htm, htu, new Date(), accessToken, nonce);
	}
	
	
	@Override
	public SignedJWT createDPoPJWT(final JWTID jti,
				       final String htm,
				       final URI htu,
				       final Date iat,
				       final AccessToken accessToken)
		throws JOSEException {
		
		return createDPoPJWT(jti, htm, htu, iat, accessToken, null);
	}
	
	
	@Override
	public SignedJWT createDPoPJWT(final JWTID jti,
				       final String htm,
				       final URI htu,
				       final Date iat,
				       final AccessToken accessToken,
				       final Nonce nonce)
		throws JOSEException {
		
		JWSHeader jwsHeader = new JWSHeader.Builder(getJWSAlgorithm())
			.type(TYPE)
			.jwk(getPublicJWK())
			.build();
		
		JWTClaimsSet jwtClaimsSet = DPoPUtils.createJWTClaimsSet(jti, htm, htu, iat, accessToken, nonce);
		SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaimsSet);
		signedJWT.sign(getJWSSigner());
		return signedJWT;
	}
}
