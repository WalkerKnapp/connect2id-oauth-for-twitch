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


import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;


/**
 * Birthplace claims set, serialisable to a JSON object.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
public final class Birthplace extends ClaimsSet {
	
	
	/**
	 * The country code claim name.
	 */
	public static final String COUNTRY_CLAIM_NAME = "country";
	
	
	/**
	 * The region claim name.
	 */
	public static final String REGION_CLAIM_NAME = "region";
	
	
	/**
	 * The locality claim name.
	 */
	public static final String LOCALITY_CLAIM_NAME = "locality";
	
	
	/**
	 * The names of the standard place of birth claims.
	 */
	private static final Set<String> stdClaimNames = new LinkedHashSet<>();
	
	
	static {
		stdClaimNames.add(LOCALITY_CLAIM_NAME);
		stdClaimNames.add(REGION_CLAIM_NAME);
		stdClaimNames.add(COUNTRY_CLAIM_NAME);
	}
	
	
	/**
	 * Gets the names of the standard birthplace claims.
	 *
	 * @return The names of the standard birthplace claims (read-only set).
	 */
	public static Set<String> getStandardClaimNames() {
		
		return Collections.unmodifiableSet(stdClaimNames);
	}
	
	
	/**
	 * Creates a new birthplace claims set.
	 *
	 * @param countryCode The country code, as ISO3166-1 or ISO3166-3 code,
	 *                    {@code null} if not specified.
	 * @param region      State, province, prefecture, or region component,
	 *                    {@code null} if not specified.
	 * @param locality    City or other locality, {@code null} if not
	 *                    specified.
	 */
	public Birthplace(final CountryCode countryCode, final String region, final String locality) {
	
		if (countryCode != null) {
			setClaim(COUNTRY_CLAIM_NAME, countryCode.getValue());
		}
		
		setClaim(REGION_CLAIM_NAME, region);
		setClaim(LOCALITY_CLAIM_NAME, locality);
	}
	
	
	/**
	 * Creates a new birthplace claims set from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 */
	public Birthplace(final JSONObject jsonObject) {
		
		super(jsonObject);
	}
	
	
	/**
	 * Gets the country code.
	 *
	 * @return The country code, {@code null} if not specified or illegal
	 *         ISO3166-1 or ISO3166-3 country code.
	 */
	public CountryCode getCountry() {
	
		String code = getStringClaim(COUNTRY_CLAIM_NAME);
		if (code == null) {
			return null;
		}
		
		try {
			return CountryCode.parse(code);
		} catch (ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Sets the country.
	 *
	 * @param country The country, {@code null} if not specified.
	 */
	public void setCountry(final CountryCode country) {
	
		if (country != null) {
			setClaim(COUNTRY_CLAIM_NAME, country.getValue());
		} else {
			setClaim(COUNTRY_CLAIM_NAME, null);
		}
	}
	
	
	/**
	 * Gets the tate, province, prefecture, or region component.
	 *
	 * @return The state, province, prefecture, or region component,
	 *         {@code null} if not specified.
	 */
	public String getRegion() {
		
		return getStringClaim(REGION_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the tate, province, prefecture, or region component.
	 *
	 * @param region The state, province, prefecture, or region component,
	 *               {@code null} if not specified.
	 */
	public void setRegion(final String region) {
		
		setClaim(REGION_CLAIM_NAME, region);
	}
	
	
	/**
	 * Gets the city or other locality.
	 *
	 * @return The city or other locality, {@code null} if not specified.
	 */
	public String getLocality() {
		
		return getStringClaim(LOCALITY_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the city or other locality.
	 *
	 * @param locality The city or other locality, {@code null} if not
	 *                 specified.
	 */
	public void setLocality(final String locality) {
		
		setClaim(LOCALITY_CLAIM_NAME, locality);
	}
}
