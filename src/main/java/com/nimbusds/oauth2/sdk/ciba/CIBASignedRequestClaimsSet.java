/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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

package com.nimbusds.oauth2.sdk.ciba;


import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

import java.util.*;


/**
 * CIBA signed request claims set, serialisable to a JSON object.
 *
 * <p>Example signed request claims set:
 *
 * <pre>
 * {
 *   "iss": "s6BhdRkqt3",
 *   "aud": "https://server.example.com",
 *   "exp": 1537820086,
 *   "iat": 1537819486,
 *   "nbf": 1537818886,
 *   "jti": "4LTCqACC2ESC5BWCnN3j58EnA",
 *   "scope": "openid email example-scope",
 *   "client_notification_token": "8d67dc78-7faa-4d41-aabd-67707b374255",
 *   "binding_message": "W4SCT",
 *   "login_hint_token": "eyJraWQiOiJsdGFjZXNidyIsImFsZyI6IkVTMjU2I
 *     n0.eyJzdWJfaWQiOnsic3ViamVjdF90eXBlIjoicGhvbmUiLCJwaG9uZSI6I
 *     isxMzMwMjgxODAwNCJ9fQ.Kk8jcUbHjJAQkRSHyDuFQr3NMEOSJEZc85VfER
 *     74tX6J9CuUllr89WKUHUR7MA0-mWlptMRRhdgW1ZDt7g1uwQ"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect CIBA Flow - Core 1.0
 * </ul>
 */
public class CIBASignedRequestClaimsSet extends ClaimsSet {
	
	
	/**
	 * The request claim name.
	 */
	public static final String REQUEST_CLAIM_NAME = "request";
	
	
	/**
	 * The issue time claim name.
	 */
	public static final String IAT_CLAIM_NAME = "iat";
	
	
	/**
	 * The not-before time claim name.
	 */
	public static final String NBF_CLAIM_NAME = "nbf";
	
	
	/**
	 * The expiration time claim name.
	 */
	public static final String EXP_CLAIM_NAME = "exp";
	
	
	/**
	 * The JWT ID claim name.
	 */
	public static final String JTI_CLAIM_NAME = "jti";
	
	
	/**
	 * The names of the standard top-level claims.
	 */
	private static final Set<String> STD_CLAIM_NAMES;
	
	
	static {
		Set<String> claimNames = new HashSet<>(ClaimsSet.getStandardClaimNames());
		claimNames.add(REQUEST_CLAIM_NAME);
		claimNames.add(ISS_CLAIM_NAME);
		claimNames.add(AUD_CLAIM_NAME);
		claimNames.add(IAT_CLAIM_NAME);
		claimNames.add(NBF_CLAIM_NAME);
		claimNames.add(EXP_CLAIM_NAME);
		claimNames.add(JTI_CLAIM_NAME);
		STD_CLAIM_NAMES = Collections.unmodifiableSet(claimNames);
	}
	
	
	/**
	 * Gets the names of the standard top-level claims.
	 *
	 * @return The names of the standard top-level claims (read-only set).
	 */
	public static Set<String> getStandardClaimNames() {
		
		return STD_CLAIM_NAMES;
	}
	
	
	/**
	 * Creates a new CIBA signed request claims set.
	 *
	 * @param cibaPlainRequest The CIBA plain request to use. Must not be
	 *                         {@code null}.
	 * @param iss              The issuer, must be set to the
	 *                         {@code client_id}.
	 * @param aud              The audience, must be set to the OpenID
	 *                         provider / OAuth 2.0 authorisation server
	 *                         issuer URI.
	 * @param iat              The issue time. Must not be {@code null}.
	 * @param nbf              The not-before time. Must not be
	 *                         {@code null}.
	 * @param exp              The expiration time. Must not be
	 *                         {@code null}.
	 * @param jti              The JWT ID. Must not be {@code null}.
	 */
	public CIBASignedRequestClaimsSet(
		final CIBARequest cibaPlainRequest,
		final Issuer iss,
		final Audience aud,
		final Date iat,
		final Date nbf,
		final Date exp,
		final JWTID jti) {
		
		if (cibaPlainRequest.isSigned()) {
			throw new IllegalArgumentException("The CIBA request must be plain");
		}
		
		for (Map.Entry<String,Object> claim: cibaPlainRequest.toJWTClaimsSet().getClaims().entrySet()) {
			setClaim(claim.getKey(), claim.getValue());
		}
		
		setIssuer(Objects.requireNonNull(iss));
		setAudience(Objects.requireNonNull(aud));
		setDateClaim(IAT_CLAIM_NAME, Objects.requireNonNull(iat));
		setDateClaim(NBF_CLAIM_NAME, Objects.requireNonNull(nbf));
		setDateClaim(EXP_CLAIM_NAME, Objects.requireNonNull(exp));
		setClaim(JTI_CLAIM_NAME, jti.getValue());
	}
}
