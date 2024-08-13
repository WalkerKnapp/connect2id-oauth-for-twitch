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

package com.nimbusds.openid.connect.sdk.claims;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSet;


/**
 * UserInfo claims set, serialisable to a JSON object.
 *
 * <p>Supports normal, aggregated and distributed claims.
 *
 * <p>Example UserInfo claims set:
 *
 * <pre>
 * {
 *   "sub"                : "248289761001",
 *   "name"               : "Jane Doe",
 *   "given_name"         : "Jane",
 *   "family_name"        : "Doe",
 *   "preferred_username" : "j.doe",
 *   "email"              : "janedoe@example.com",
 *   "picture"            : "http://example.com/janedoe/me.jpg"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
public class UserInfo extends PersonClaims {


	/**
	 * The subject claim name.
	 */
	public static final String SUB_CLAIM_NAME = "sub";
	
	
	
	/**
	 * The verified claims claim name.
	 */
	public static final String VERIFIED_CLAIMS_CLAIM_NAME = "verified_claims";
	
	
	/**
	 * Gets the names of the standard top-level UserInfo claims.
	 *
	 * @return The names of the standard top-level UserInfo claims 
	 *         (read-only set).
	 */
	public static Set<String> getStandardClaimNames() {
	
		Set<String> names = new HashSet<>(PersonClaims.getStandardClaimNames());
		names.add(SUB_CLAIM_NAME);
		names.add(VERIFIED_CLAIMS_CLAIM_NAME);
		return Collections.unmodifiableSet(names);
	}
	
	
	/**
	 * Creates a new minimal UserInfo claims set.
	 *
	 * @param sub The subject. Must not be {@code null}.
	 */
	public UserInfo(final Subject sub) {
	
		super();
		setClaim(SUB_CLAIM_NAME, sub.getValue());
	}


	/**
	 * Creates a new UserInfo claims set from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @throws IllegalArgumentException If the JSON object doesn't contain
	 *                                  a subject {@code sub} string claim.
	 */
	public UserInfo(final JSONObject jsonObject) {

		super(jsonObject);

		if (getStringClaim(SUB_CLAIM_NAME) == null)
			throw new IllegalArgumentException("Missing or invalid \"sub\" claim");
	}


	/**
	 * Creates a new UserInfo claims set from the specified JSON Web Token
	 * (JWT) claims set.
	 *
	 * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
	 *
	 * @throws IllegalArgumentException If the JWT claims set doesn't
	 *                                  contain a subject {@code sub}
	 *                                  string claim.
	 */
	public UserInfo(final JWTClaimsSet jwtClaimsSet) {

		this(JSONObjectUtils.toJSONObject(jwtClaimsSet));
	}


	/**
	 * Puts all claims from the specified other UserInfo claims set.
	 * Aggregated and distributed claims are properly merged.
	 *
	 * @param other The other UserInfo. Must have the same
	 *              {@link #getSubject subject}. Must not be {@code null}.
	 *
	 * @throws IllegalArgumentException If the other UserInfo claims set
	 *                                  doesn't have an identical subject,
	 *                                  or if the external claims source ID
	 *                                  of the other UserInfo matches an
	 *                                  existing source ID.
	 */
	public void putAll(final UserInfo other) {

		Subject otherSubject = other.getSubject();

		if (otherSubject == null)
			throw new IllegalArgumentException("The subject of the other UserInfo is missing");

		if (! otherSubject.equals(getSubject()))
			throw new IllegalArgumentException("The subject of the other UserInfo must be identical");
		
		// Save present aggregated and distributed claims, to prevent
		// overwrite by put to claims JSON object
		Set<AggregatedClaims> savedAggregatedClaims = getAggregatedClaims();
		Set<DistributedClaims> savedDistributedClaims = getDistributedClaims();
		
		// Save other present aggregated and distributed claims
		Set<AggregatedClaims> otherAggregatedClaims = other.getAggregatedClaims();
		Set<DistributedClaims> otherDistributedClaims = other.getDistributedClaims();
		
		// Ensure external source IDs don't conflict during merge
		Set<String> externalSourceIDs = new HashSet<>();
		
		if (savedAggregatedClaims != null) {
			for (AggregatedClaims ac: savedAggregatedClaims) {
				externalSourceIDs.add(ac.getSourceID());
			}
		}
		
		if (savedDistributedClaims != null) {
			for (DistributedClaims dc: savedDistributedClaims) {
				externalSourceIDs.add(dc.getSourceID());
			}
		}
		
		if (otherAggregatedClaims != null) {
			for (AggregatedClaims ac: otherAggregatedClaims) {
				if (externalSourceIDs.contains(ac.getSourceID())) {
					throw new IllegalArgumentException("Aggregated claims source ID conflict: " + ac.getSourceID());
				}
			}
		}
		
		if (otherDistributedClaims != null) {
			for (DistributedClaims dc: otherDistributedClaims) {
				if (externalSourceIDs.contains(dc.getSourceID())) {
					throw new IllegalArgumentException("Distributed claims source ID conflict: " + dc.getSourceID());
				}
			}
		}
		
		putAll((ClaimsSet)other);
		
		// Merge saved external claims, if any
		if (savedAggregatedClaims != null) {
			for (AggregatedClaims ac: savedAggregatedClaims) {
				addAggregatedClaims(ac);
			}
		}
		
		if (savedDistributedClaims != null) {
			for (DistributedClaims dc: savedDistributedClaims) {
				addDistributedClaims(dc);
			}
		}
	}
	
	
	/**
	 * Gets the UserInfo subject. Corresponds to the {@code sub} claim.
	 *
	 * @return The subject.
	 */
	public Subject getSubject() {
	
		return new Subject(getStringClaim(SUB_CLAIM_NAME));
	}
	
	
	/**
	 * Gets the verified claims. Corresponds to the {@code verified_claims}
	 * claim from OpenID Connect for Identity Assurance 1.0.
	 *
	 * @return List of the verified claims sets, {@code null} if not
	 *         specified or parsing failed.
	 */
	public List<VerifiedClaimsSet> getVerifiedClaims() {
		
		// Try JSON object first
		Object value = getClaim(VERIFIED_CLAIMS_CLAIM_NAME);
		
		if (value instanceof JSONObject) {
			
			// Single verified_claims
			try {
				return Collections.singletonList(VerifiedClaimsSet.parse((JSONObject)value));
			} catch (ParseException e) {
				return null;
			}
			
		} else if (value instanceof List) {
			
			// JSON array of verified_claims
			
			List<?> rawList = (List<?>)value;
			
			if (rawList.isEmpty()) {
				return null;
			}
			
			List<VerifiedClaimsSet> list = new LinkedList<>();
			
			for (Object item : rawList) {
				if (item instanceof JSONObject) {
					try {
						list.add(VerifiedClaimsSet.parse((JSONObject) item));
					} catch (ParseException e) {
						return null;
					}
				} else {
					return null;
				}
			}
			
			return list;
		} else {
			// Invalid
			return null;
		}
	}
	
	
	/**
	 * Sets the verified claims. Corresponds to the {@code verified_claims}
	 * claim from OpenID Connect for Identity Assurance 1.0.
	 *
	 * @param verifiedClaims The verified claims set, {@code null} if not
	 *                       specified.
	 */
	public void setVerifiedClaims(final VerifiedClaimsSet verifiedClaims) {
		
		if (verifiedClaims != null) {
			setClaim(VERIFIED_CLAIMS_CLAIM_NAME, verifiedClaims.toJSONObject());
		} else {
			setClaim(VERIFIED_CLAIMS_CLAIM_NAME, null);
		}
	}
	
	
	/**
	 * Sets a list of verified claims with separate verifications.
	 * Corresponds to the {@code verified_claims} claim from OpenID Connect
	 * for Identity Assurance 1.0.
	 *
	 * @param verifiedClaimsList List of the verified claims sets,
	 *                           {@code null} if not specified or parsing
	 *                           failed.
	 */
	public void setVerifiedClaims(final List<VerifiedClaimsSet> verifiedClaimsList) {
		
		if (verifiedClaimsList != null) {
			List<JSONObject> jsonObjects = new LinkedList<>();
			for (VerifiedClaimsSet verifiedClaims: verifiedClaimsList) {
				if (verifiedClaims != null) {
					jsonObjects.add(verifiedClaims.toJSONObject());
				}
			}
			setClaim(VERIFIED_CLAIMS_CLAIM_NAME, jsonObjects);
		} else {
			setClaim(VERIFIED_CLAIMS_CLAIM_NAME, null);
		}
	}
	
	
	/**
	 * Adds the specified aggregated claims provided by an external claims
	 * source.
	 *
	 * @param aggregatedClaims The aggregated claims instance, if
	 *                         {@code null} nothing will be added.
	 */
	public void addAggregatedClaims(final AggregatedClaims aggregatedClaims) {
		
		if (aggregatedClaims == null) {
			return;
		}
		
		aggregatedClaims.mergeInto(claims);
	}
	
	
	/**
	 * Gets the included aggregated claims provided by each external claims
	 * source.
	 *
	 * @return The aggregated claims, {@code null} if none are found.
	 */
	public Set<AggregatedClaims> getAggregatedClaims() {
	
		Map<String,JSONObject> claimSources = ExternalClaimsUtils.getExternalClaimSources(claims);
		
		if (claimSources == null) {
			return null; // No external _claims_sources
		}
		
		Set<AggregatedClaims> aggregatedClaimsSet = new HashSet<>();
		
		for (Map.Entry<String,JSONObject> en: claimSources.entrySet()) {
			
			String sourceID = en.getKey();
			JSONObject sourceSpec = en.getValue();
			
			Object jwtValue = sourceSpec.get("JWT");
			if (! (jwtValue instanceof String)) {
				continue; // skip
			}
			
			JWT claimsJWT;
			try {
				claimsJWT = JWTParser.parse((String)jwtValue);
			} catch (java.text.ParseException e) {
				continue; // invalid JWT, skip
			}
			
			Set<String> claimNames = ExternalClaimsUtils.getExternalClaimNamesForSource(claims, sourceID);
			
			if (claimNames.isEmpty()) {
				continue; // skip
			}
			
			aggregatedClaimsSet.add(new AggregatedClaims(sourceID, claimNames, claimsJWT));
		}
		
		if (aggregatedClaimsSet.isEmpty()) {
			return null;
		}
		
		return aggregatedClaimsSet;
	}
	
	
	/**
	 * Adds the specified distributed claims from an external claims source.
	 *
	 * @param distributedClaims The distributed claims instance, if
	 *                          {@code null} nothing will be added.
	 */
	public void addDistributedClaims(final DistributedClaims distributedClaims) {
		
		if (distributedClaims == null) {
			return;
		}
		
		distributedClaims.mergeInto(claims);
	}
	
	
	/**
	 * Gets the included distributed claims provided by each external
	 * claims source.
	 *
	 * @return The distributed claims, {@code null} if none are found.
	 */
	public Set<DistributedClaims> getDistributedClaims() {
		
		Map<String,JSONObject> claimSources = ExternalClaimsUtils.getExternalClaimSources(claims);
		
		if (claimSources == null) {
			return null; // No external _claims_sources
		}
		
		Set<DistributedClaims> distributedClaimsSet = new HashSet<>();
		
		for (Map.Entry<String,JSONObject> en: claimSources.entrySet()) {
			
			String sourceID = en.getKey();
			JSONObject sourceSpec = en.getValue();
	
			Object endpointValue = sourceSpec.get("endpoint");
			if (! (endpointValue instanceof String)) {
				continue; // skip
			}
			
			URI endpoint;
			try {
				endpoint = new URI((String)endpointValue);
			} catch (URISyntaxException e) {
				continue; // invalid URI, skip
			}
			
			AccessToken accessToken = null;
			Object accessTokenValue = sourceSpec.get("access_token");
			if (accessTokenValue instanceof String) {
				accessToken = new TypelessAccessToken((String)accessTokenValue);
			}
			
			Set<String> claimNames = ExternalClaimsUtils.getExternalClaimNamesForSource(claims, sourceID);
			
			if (claimNames.isEmpty()) {
				continue; // skip
			}
			
			distributedClaimsSet.add(new DistributedClaims(sourceID, claimNames, endpoint, accessToken));
		}
		
		if (distributedClaimsSet.isEmpty()) {
			return null;
		}
		
		return distributedClaimsSet;
	}
	
	
	/**
	 * Parses a UserInfo claims set from the specified JSON object string.
	 *
	 * @param json The JSON object string to parse. Must not be
	 *             {@code null}.
	 *
	 * @return The UserInfo claims set.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static UserInfo parse(final String json)
		throws ParseException {

		JSONObject jsonObject = JSONObjectUtils.parse(json);

		try {
			return new UserInfo(jsonObject);

		} catch (IllegalArgumentException e) {

			throw new ParseException(e.getMessage(), e);
		}
	}
}
