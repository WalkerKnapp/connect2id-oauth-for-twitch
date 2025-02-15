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


import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.assurance.claims.CountryCode;


/**
 * UserInfo address claims set, serialisable to a JSON object.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
public class Address extends ClaimsSet {


	/**
	 * The formatted claim name.
	 */
	public static final String FORMATTED_CLAIM_NAME = "formatted";


	/**
	 * The street address claim name.
	 */
	public static final String STREET_ADDRESS_CLAIM_NAME = "street_address";


	/**
	 * The locality claim name.
	 */
	public static final String LOCALITY_CLAIM_NAME = "locality";


	/**
	 * The region claim name.
	 */
	public static final String REGION_CLAIM_NAME = "region";


	/**
	 * The postal code claim name.
	 */
	public static final String POSTAL_CODE_CLAIM_NAME = "postal_code";


	/**
	 * The country claim name.
	 */
	public static final String COUNTRY_CLAIM_NAME = "country";
	
	
	/**
	 * The country code claim name.
	 */
	public static final String COUNTRY_CODE_CLAIM_NAME = "country_code";


	/**
	 * The names of the standard UserInfo address claims.
	 */
	private static final Set<String> stdClaimNames = new LinkedHashSet<>();
	
	
	static {
		stdClaimNames.add(FORMATTED_CLAIM_NAME);
		stdClaimNames.add(STREET_ADDRESS_CLAIM_NAME);
		stdClaimNames.add(LOCALITY_CLAIM_NAME);
		stdClaimNames.add(REGION_CLAIM_NAME);
		stdClaimNames.add(POSTAL_CODE_CLAIM_NAME);
		stdClaimNames.add(COUNTRY_CLAIM_NAME);
		stdClaimNames.add(COUNTRY_CODE_CLAIM_NAME);
	}
	
	
	/**
	 * Gets the names of the standard UserInfo address claims.
	 *
	 * @return The names of the standard UserInfo address claims 
	 *         (read-only set).
	 */
	public static Set<String> getStandardClaimNames() {
	
		return Collections.unmodifiableSet(stdClaimNames);
	}
	
	
	/**
	 * Creates a new minimal (empty) UserInfo address claims set.
	 */
	public Address() { }


	/**
	 * Creates a new UserInfo address claims set from the specified JSON 
	 * object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 */
	public Address(final JSONObject jsonObject) {

		super(jsonObject);
	}
	
	
	/**
	 * Sets the full mailing address, formatted for display or use with a 
	 * mailing label. May contain newlines. Corresponds to the
	 * {@code formatted} claim.
	 *
	 * @param formatted The full mailing address. {@code null} if not 
	 *                  specified.
	 */
	public void setFormatted(final String formatted) {
	
		setClaim(FORMATTED_CLAIM_NAME, formatted);
	}
	
	
	/**
	 * Gets the full mailing address, formatted for display or use with a
	 * mailing label. May contain newlines. Corresponds to the 
	 * {@code formatted} claim.
	 *
	 * @return The full mailing address, {@code null} if not specified.
	 */
	public String getFormatted() {
	
		return getStringClaim(FORMATTED_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the full street address component, which may include house
	 * number, street name, PO BOX, and multi-line extended street address
	 * information. May contain newlines. Corresponds to the 
	 * {@code street_address} claim.
	 *
	 * @param streetAddress The full street address component. If
	 *                      {@code null} the claim will be removed.
	 */
	public void setStreetAddress(final String streetAddress) {
	
		setClaim(STREET_ADDRESS_CLAIM_NAME, streetAddress);
	}
	
	
	/**
	 * Gets the full street address component, which may include house 
	 * number, street name, PO BOX, and multi-line extended street address 
	 * information. May contain newlines. Corresponds to the 
	 * {@code street_address} claim.
	 *
	 * @return The full street address component, {@code null} if not 
	 *         specified.
	 */
	public String getStreetAddress() {
	
		return getStringClaim(STREET_ADDRESS_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the city or locality component. Corresponds to the 
	 * {@code locality} claim.
	 *
	 * @param locality The city or locality component. If {@code null} the
	 *                 claim will be removed.
	 */
	public void setLocality(final String locality) {
	
		setClaim(LOCALITY_CLAIM_NAME, locality);
	}
	
	
	/**
	 * Gets the city or locality component. Corresponds to the 
	 * {@code locality} claim, with no language tag.
	 *
	 * @return The city or locality component, {@code null} if not 
	 *         specified.
	 */
	public String getLocality() {
	
		return getStringClaim(LOCALITY_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the state, province, prefecture or region component. 
	 * Corresponds to the {@code region} claim.
	 *
	 * @param region The state, province, prefecture or region component.
	 *               If {@code null} the claim will be removed.
	 */
	public void setRegion(final String region) {
	
		setClaim(REGION_CLAIM_NAME, region);
	}
	
	
	/**
	 * Gets the state, province, prefecture or region component. 
	 * Corresponds to the {@code region} claim.
	 *
	 * @return The state, province, prefecture or region component,
	 *         {@code null} if not specified.
	 */
	public String getRegion() {
	
		return getStringClaim(REGION_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the zip code or postal code component. Corresponds to the
	 * {@code postal_code} claim.
	 *
	 * @param postalCode The zip code or postal code component. If 
	 *                   {@code null} the claim will be removed.
	 */
	public void setPostalCode(final String postalCode) {
	
		setClaim(POSTAL_CODE_CLAIM_NAME, postalCode);
	}
	
	
	/**
	 * Gets the zip code or postal code component. Corresponds to the
	 * {@code postal_code} claim.
	 *
	 * @return The zip code or postal code component, {@code null} if not 
	 *         specified.
	 */
	public String getPostalCode() {
	
		return getStringClaim(POSTAL_CODE_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the country name component. Corresponds to the {@code country} 
	 * claim.
	 *
	 * @param country The country name component. If {@code null} the claim
	 *                will be removed.
	 */
	public void setCountry(final String country) {
	
		setClaim(COUNTRY_CLAIM_NAME, country);
	}
	
	
	/**
	 * Gets the country name component. Corresponds to the {@code country}
	 * claim.
	 *
	 * @return The country name component, {@code null} if not specified.
	 */
	public String getCountry() {
	
		return getStringClaim(COUNTRY_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the country code component. Corresponds to the
	 * {@code country_code} claim.
	 *
	 * @param countryCode The country code component. If {@code null} the
	 *                    claim will be removed.
	 */
	public void setCountryCode(final CountryCode countryCode) {
	
		String value = countryCode != null ? countryCode.getValue() : null;
		setClaim(COUNTRY_CODE_CLAIM_NAME, value);
	}
	
	
	/**
	 * Gets the country code component. Corresponds to the
	 * {@code country_code} claim.
	 *
	 * @return The country code component, {@code null} if not specified.
	 */
	public CountryCode getCountryCode() {
	
		String value = getStringClaim(COUNTRY_CODE_CLAIM_NAME);
		
		if (value == null) {
			return null;
		}
		
		try {
			return CountryCode.parse(value);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Parses an address claims set from the specified JSON object string.
	 *
	 * @param json The JSON object string to parse. Must not be
	 *             {@code null}.
	 *
	 * @return The address claims set.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static Address parse(final String json)
		throws ParseException {

		JSONObject jsonObject = JSONObjectUtils.parse(json);

		try {
			return new Address(jsonObject);

		} catch (IllegalArgumentException e) {

			throw new ParseException(e.getMessage(), e);
		}
	}
}
