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

package com.nimbusds.openid.connect.sdk.assurance.evidences;


import java.util.Objects;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.assurance.claims.CountryCode;
import com.nimbusds.openid.connect.sdk.claims.Address;


/**
 * Common attributes in a {@link DocumentIssuer} and
 * {@link ElectronicRecordSource}.
 */
class CommonOriginatorAttributes {
	
	
	/**
	 * The name.
	 */
	private final Name name;
	
	
	/**
	 * The address.
	 */
	private final Address address;
	
	
	/**
	 * The country code.
	 */
	private final CountryCode countryCode;
	
	
	/**
	 * The jurisdiction.
	 */
	private final Jurisdiction jurisdiction;
	
	
	/**
	 * Creates the common attributes for a document issuer or electronic
	 * record source.
	 *
	 * @param name         The name, {@code null} if not specified.
	 * @param address      The address elements, {@code null} if not
	 *                     specified.
	 * @param countryCode  The country code, {@code null} if not
	 *                     specified.
	 * @param jurisdiction The jurisdiction, {@code null} if not
	 *                     specified.
	 */
	public CommonOriginatorAttributes(final Name name,
			      final Address address,
			      final CountryCode countryCode,
			      final Jurisdiction jurisdiction) {
		this.name = name;
		this.address = address;
		this.countryCode = countryCode;
		this.jurisdiction = jurisdiction;
	}
	
	
	/**
	 * Returns the name.
	 *
	 * @return The name, {@code null} if not specified.
	 */
	public Name getName() {
		return name;
	}
	
	
	/**
	 * Returns the address elements.
	 *
	 * @return The address elements, {@code null} if not specified.
	 */
	public Address getAddress() {
		return address;
	}
	
	
	/**
	 * Returns the country code.
	 *
	 * @return The country code, {@code null} if not specified.
	 */
	public CountryCode getCountryCode() {
		return countryCode;
	}
	
	
	/**
	 * Returns the jurisdiction.
	 *
	 * @return The jurisdiction, {@code null} if not specified.
	 */
	public Jurisdiction getJurisdiction() {
		return jurisdiction;
	}
	
	
	/**
	 * Returns a JSON object representation.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		
		JSONObject o = new JSONObject();
		if (getName() != null) {
			o.put("name", getName().getValue());
		}
		if (getAddress() != null) {
			o.putAll(getAddress().toJSONObject());
		}
		if (getCountryCode() != null) {
			o.put("country_code", getCountryCode().getValue());
		}
		if (getJurisdiction() != null) {
			o.put("jurisdiction", getJurisdiction().getValue());
		}
		
		return o;
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(getName(), getAddress(), getCountryCode(), getJurisdiction());
	}
	
	
	/**
	 * Parses the common originator attributes from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The common originator attributes.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static CommonOriginatorAttributes parse(final JSONObject jsonObject)
		throws ParseException {
		
		try {
			Name name = null;
			if (jsonObject.get("name") != null) {
				name = new Name(JSONObjectUtils.getNonBlankString(jsonObject, "name"));
			}
			
			CountryCode countryCode = null;
			if (jsonObject.get("country_code") != null) {
				countryCode = CountryCode.parse(JSONObjectUtils.getNonBlankString(jsonObject, "country_code"));
			}
			
			Jurisdiction jurisdiction = null;
			if (jsonObject.get("jurisdiction") != null) {
				jurisdiction = new Jurisdiction(JSONObjectUtils.getNonBlankString(jsonObject, "jurisdiction"));
			}
			
			Address address = null;
			if (CollectionUtils.intersect(Address.getStandardClaimNames(), jsonObject.keySet())) {
				
				JSONObject addressSpecific = new JSONObject(jsonObject);
				addressSpecific.remove("name");
				addressSpecific.remove("country_code");
				addressSpecific.remove("jurisdiction");
				address = new Address(addressSpecific);
			}
			
			return new CommonOriginatorAttributes(name, address, countryCode, jurisdiction);
			
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage(), e);
		}
	}
}
