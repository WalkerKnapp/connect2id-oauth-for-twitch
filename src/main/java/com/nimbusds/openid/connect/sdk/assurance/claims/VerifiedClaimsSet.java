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

package com.nimbusds.openid.connect.sdk.assurance.claims;


import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.assurance.IdentityVerification;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.PersonClaims;


/**
 * Verified claims set.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
public class VerifiedClaimsSet implements JSONAware {
	
	
	/**
	 * The verification element.
	 */
	public static final String VERIFICATION_ELEMENT = "verification";
	
	
	/**
	 * The claims element.
	 */
	public static final String CLAIMS_ELEMENT = "claims";
	
	
	/**
	 * The identity verification.
	 */
	private final IdentityVerification identityVerification;
	
	
	/**
	 * The verified claims.
	 */
	private final ClaimsSet claimsSet;
	
	
	/**
	 * Creates a new verified claims set.
	 *
	 * @param verification The identity verification. Must not be
	 *                     {@code null}.
	 * @param claims       The verified claims. Must not be {@code null}.
	 */
	public VerifiedClaimsSet(final IdentityVerification verification,
				 final ClaimsSet claims) {
		
		if (verification == null) {
			throw new IllegalArgumentException("The verification must not be null");
		}
		identityVerification = verification;
		
		if (claims == null) {
			throw new IllegalArgumentException("The claims must not be null");
		}
		claimsSet = claims;
	}
	
	
	/**
	 * Returns the identity verification.
	 *
	 * @return The identity verification.
	 */
	public IdentityVerification getVerification() {
	
		return identityVerification;
	}
	
	
	/**
	 * Returns the verified claims.
	 *
	 * @return The verified claims wrapped in a person claims object for
	 *         convenience.
	 */
	public PersonClaims getClaimsSet() {
	
		return new PersonClaims(claimsSet.toJSONObject());
	}
	
	
	/**
	 * Returns a JSON object representation of this verified claims set.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		
		JSONObject o = new JSONObject();
		o.put(VERIFICATION_ELEMENT, identityVerification.toJSONObject());
		o.put(CLAIMS_ELEMENT, claimsSet.toJSONObject());
		return o;
	}
	
	
	@Override
	public String toJSONString() {
		
		return toJSONObject().toJSONString();
	}
	
	
	/**
	 * Parses a verified claims set from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse.
	 *
	 * @return The verifier claims set.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static VerifiedClaimsSet parse(final JSONObject jsonObject)
		throws ParseException {
		
		return new VerifiedClaimsSet(
			IdentityVerification.parse(JSONObjectUtils.getJSONObject(jsonObject, VERIFICATION_ELEMENT)),
			new PersonClaims(JSONObjectUtils.getJSONObject(jsonObject, CLAIMS_ELEMENT)));
	}
}
