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


import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ClockSkewAware;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.validators.BadJWTExceptions;
import net.jcip.annotations.ThreadSafe;

import java.util.Date;
import java.util.List;
import java.util.Objects;


/**
 * JSON Web Token (JWT) encoded authorisation response claims verifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM)
 * </ul>
 */
@ThreadSafe
public class JARMClaimsVerifier implements JWTClaimsSetVerifier, ClockSkewAware {
	
	
	/**
	 * The expected Authorisation Server.
	 */
	private final Issuer expectedIssuer;
	
	
	/**
	 * The requesting client (for the JWT audience).
	 */
	private final ClientID expectedClientID;
	
	
	/**
	 * The maximum acceptable clock skew, in seconds.
	 */
	private int maxClockSkew;
	
	
	/**
	 * Creates a new ID token claims verifier.
	 *
	 * @param issuer       The expected Authorisation Server. Must not be
	 *                     {@code null}.
	 * @param clientID     The client ID. Must not be {@code null}.
	 * @param maxClockSkew The maximum acceptable clock skew (absolute
	 *                     value), in seconds. Must be zero (no clock skew)
	 *                     or positive integer.
	 */
	public JARMClaimsVerifier(final Issuer issuer,
				  final ClientID clientID,
				  final int maxClockSkew) {
		
		this.expectedIssuer = Objects.requireNonNull(issuer);
		this.expectedClientID = Objects.requireNonNull(clientID);
		setMaxClockSkew(maxClockSkew);
	}
	
	
	/**
	 * Returns the expected Authorisation Server.
	 *
	 * @return The Authorisation Server issuer.
	 */
	public Issuer getExpectedIssuer() {
		
		return expectedIssuer;
	}
	
	
	/**
	 * Returns the client ID for verifying the JWT audience.
	 *
	 * @return The client ID.
	 */
	public ClientID getClientID() {
		
		return expectedClientID;
	}
	
	
	@Override
	public int getMaxClockSkew() {
		
		return maxClockSkew;
	}
	
	
	@Override
	public void setMaxClockSkew(final int maxClockSkew) {
		if (maxClockSkew < 0) {
			throw new IllegalArgumentException("The max clock skew must be zero or positive");
		}
		this.maxClockSkew = maxClockSkew;
	}
	
	
	@Override
	public void verify(final JWTClaimsSet claimsSet, final SecurityContext ctx)
		throws BadJWTException {
		
		// See http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
		
		final String tokenIssuer = claimsSet.getIssuer();
		
		if (tokenIssuer == null) {
			throw BadJWTExceptions.MISSING_ISS_CLAIM_EXCEPTION;
		}
		
		if (! expectedIssuer.getValue().equals(tokenIssuer)) {
			throw new BadJWTException("Unexpected JWT issuer: " + tokenIssuer);
		}
		
		final List<String> tokenAudience = claimsSet.getAudience();
		
		if (tokenAudience == null || tokenAudience.isEmpty()) {
			throw BadJWTExceptions.MISSING_AUD_CLAIM_EXCEPTION;
		}
		
		if (! tokenAudience.contains(expectedClientID.getValue())) {
			throw new BadJWTException("Unexpected JWT audience: " + tokenAudience);
		}
		
		final Date exp = claimsSet.getExpirationTime();
		
		if (exp == null) {
			throw BadJWTExceptions.MISSING_EXP_CLAIM_EXCEPTION;
		}
		
		final Date nowRef = new Date();
		
		// Expiration must be after current time, given acceptable clock skew
		if (! DateUtils.isAfter(exp, nowRef, maxClockSkew)) {
			throw BadJWTExceptions.EXPIRED_EXCEPTION;
		}
	}
}
