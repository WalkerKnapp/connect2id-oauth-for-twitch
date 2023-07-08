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

package com.nimbusds.openid.connect.sdk.federation.api;


import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.MapUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.CommonFederationClaimsSet;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.trust.TrustChain;
import net.minidev.json.JSONObject;

import java.util.*;


/**
 * Resolve response claims set.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 7.2.2.
 * </ul>
 */
public class ResolveClaimsSet extends CommonFederationClaimsSet {
	
	
	/**
	 * The trust chain claim name.
	 */
	public static final String TRUST_CHAIN_CLAIM_NAME = "trust_chain";
	
	
	/**
	 * The names of the standard top-level claims.
	 */
	private static final Set<String> STD_CLAIM_NAMES;
	
	static {
		Set<String> claimNames = new HashSet<>();
		claimNames.add(ISS_CLAIM_NAME);
		claimNames.add(SUB_CLAIM_NAME);
		claimNames.add(IAT_CLAIM_NAME);
		claimNames.add(EXP_CLAIM_NAME);
		claimNames.add(METADATA_CLAIM_NAME);
		claimNames.add(TRUST_MARKS_CLAIM_NAME);
		claimNames.add(TRUST_CHAIN_CLAIM_NAME);
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
	 * Creates a new resolve response claims set with the minimum required
	 * claims.
	 *
	 * @param iss      The issuer. Must not be {@code null}.
	 * @param sub      The subject. Must not be {@code null}.
	 * @param iat      The issue time. Must not be {@code null}.
	 * @param exp      The expiration time. Must not be {@code null}.
	 * @param metadata The metadata JSON object. Must not be {@code null}.
	 */
	public ResolveClaimsSet(final Issuer iss,
				final Subject sub,
				final Date iat,
				final Date exp,
				final JSONObject metadata) {
		
		this(new EntityID(iss.getValue()), new EntityID(sub.getValue()), iat, exp, metadata);
	}
	
	
	/**
	 * Creates a new resolve response claims set with the minimum required
	 * claims.
	 *
	 * @param iss      The issuer. Must not be {@code null}.
	 * @param sub      The subject. Must not be {@code null}.
	 * @param iat      The issue time. Must not be {@code null}.
	 * @param exp      The expiration time. Must not be {@code null}.
	 * @param metadata The metadata JSON object. Must not be {@code null}.
	 */
	public ResolveClaimsSet(final EntityID iss,
				final EntityID sub,
				final Date iat,
				final Date exp,
				final JSONObject metadata) {
		
		setClaim(ISS_CLAIM_NAME, iss.getValue());
		setClaim(SUB_CLAIM_NAME, sub.getValue());
		
		if (iat == null) {
			throw new IllegalArgumentException("The iat (issued-at) claim must not be null");
		}
		setDateClaim(IAT_CLAIM_NAME, iat);
		
		if (exp == null) {
			throw new IllegalArgumentException("The exp (expiration) claim must not be null");
		}
		setDateClaim(EXP_CLAIM_NAME, exp);
		
		if (metadata == null || metadata.isEmpty()) {
			throw new IllegalArgumentException("The metadata claim must not be null");
		}
		setClaim(METADATA_CLAIM_NAME, metadata);
	}
	
	
	/**
	 * Creates a new resolve response claims set from the specified JWT
	 * claims set.
	 *
	 * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
	 *
	 * @throws ParseException If the JWT claims set doesn't represent a
	 * 	                  valid resolve response claims set.
	 */
	public ResolveClaimsSet(final JWTClaimsSet jwtClaimsSet)
		throws ParseException {
		
		super(JSONObjectUtils.toJSONObject(jwtClaimsSet));
		
		validateRequiredClaimsPresence();
	}
	
	
	/**
	 * Validates this claims set for having all minimum required claims for
	 * a resolve response.
	 *
	 * @throws ParseException If the validation failed and a required claim
	 *                        is missing.
	 */
	public void validateRequiredClaimsPresence()
		throws ParseException {
		
		super.validateRequiredClaimsPresence();
		
		if (MapUtils.isEmpty(getJSONObjectClaim(METADATA_CLAIM_NAME))) {
			throw new ParseException("Missing metadata claim");
		}
	}
	
	
	/**
	 * Gets the trust chain. Corresponds to the {@code trust_chain} claim.
	 *
	 * @return The trust chain, {@code null} if not specified or parsing
	 *         failed.
	 */
	public TrustChain getTrustChain() {
		
		List<String> chainJWTs = getStringListClaim(TRUST_CHAIN_CLAIM_NAME);
		
		if (CollectionUtils.isEmpty(chainJWTs)) {
			return null;
		}
		
		try {
			return TrustChain.parseSerialized(chainJWTs);
		} catch (ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Sets the trust chain. Corresponds to the {@code trust_chain} claim.
	 *
	 * @param trustChain The trust chain, {@code null} if not specified.
	 */
	public void setTrustChain(final TrustChain trustChain) {
		
		if (trustChain != null) {
			setClaim(TRUST_CHAIN_CLAIM_NAME, trustChain.toSerializedJWTs());
		} else {
			setClaim(TRUST_CHAIN_CLAIM_NAME, null);
		}
	}
}
