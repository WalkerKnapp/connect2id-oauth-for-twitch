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

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.claims.Address;


/**
 * Voucher.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
public class Voucher {
	
	
	/**
	 * The name.
	 */
	private final Name name;
	
	
	/**
	 * The birthdate.
	 */
	private final String birthdateString;
	
	
	/**
	 * The address.
	 */
	private final Address address;
	
	
	/**
	 * The occupation.
	 */
	private final Occupation occupation;
	
	
	/**
	 * The organisation.
	 */
	private final Organization organization;
	
	
	/**
	 * Creates a new voucher.
	 *
	 * @param name            The name, {@code null} if not specified.
	 * @param birthdateString The birthday string, {@code null} if not
	 *                        specified.
	 * @param address         The address elements, {@code null} if not
	 *                        specified.
	 * @param occupation      The occupation, {@code null} if not
	 *                        specified.
	 * @param organization    The organisation, {@code null} if not
	 *                        specified.
	 */
	public Voucher(final Name name,
		       final String birthdateString,
		       final Address address,
		       final Occupation occupation,
		       final Organization organization) {
		
		this.name = name;
		this.birthdateString = birthdateString;
		this.address = address;
		this.occupation = occupation;
		this.organization = organization;
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
	 * Returns the birthdate string.
	 *
	 * @return The birthdate string, {@code null} if not specified.
	 */
	public String getBirthdateString() {
		return birthdateString;
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
	 * Returns the occupation.
	 *
	 * @return The occupation, {@code null} if not specified.
	 */
	public Occupation getOccupation() {
		return occupation;
	}
	
	
	/**
	 * Returns the organisation.
	 *
	 * @return The organisation, {@code null} if not specified.
	 */
	public Organization getOrganization() {
		return organization;
	}
	
	
	/**
	 * Returns a JSON object representation of this voucher.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		
		JSONObject o = new JSONObject();
		if (getName() != null) {
			o.put("name", getName().getValue());
		}
		if (getBirthdateString() != null) {
			o.put("birthdate", getBirthdateString());
		}
		if (getAddress() != null) {
			o.putAll(getAddress().toJSONObject());
		}
		if (getOccupation() != null) {
			o.put("occupation", getOccupation().getValue());
		}
		if (getOrganization() != null) {
			o.put("organization", getOrganization().getValue());
		}
		return o;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof Voucher)) return false;
		Voucher voucher = (Voucher) o;
		return Objects.equals(getName(), voucher.getName()) &&
			Objects.equals(getBirthdateString(), voucher.getBirthdateString()) &&
			Objects.equals(getAddress(), voucher.getAddress()) &&
			Objects.equals(getOccupation(), voucher.getOccupation()) &&
			Objects.equals(getOrganization(), voucher.getOrganization());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(
			getName(),
			getBirthdateString(),
			getAddress(),
			getOccupation(),
			getOrganization()
		);
	}
	
	
	/**
	 * Parses a voucher from the specified JSON objecassertEquals("Equality", voucher, Voucher.parse(jsonObject));
		assertEquals("Hash code", voucher.hashCode(), Voucher.parse(jsonObject).hashCode());t.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The voucher.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static Voucher parse(final JSONObject jsonObject)
		throws ParseException {
		
		try {
			Name name = null;
			if (jsonObject.get("name") != null) {
				name = new Name(JSONObjectUtils.getNonBlankString(jsonObject, "name"));
			}
			
			String birthdateString = JSONObjectUtils.getString(jsonObject, "birthdate", null);
			
			Occupation occupation = null;
			if (jsonObject.get("occupation") != null) {
				occupation = new Occupation(JSONObjectUtils.getNonBlankString(jsonObject, "occupation"));
			}
			
			Organization organization = null;
			if (jsonObject.get("organization") != null) {
				organization = new Organization(JSONObjectUtils.getNonBlankString(jsonObject, "organization"));
			}
			
			Address address = null;
			if (CollectionUtils.intersect(Address.getStandardClaimNames(), jsonObject.keySet())) {
				
				JSONObject addressSpecific = new JSONObject(jsonObject);
				addressSpecific.remove("name");
				addressSpecific.remove("birthdate");
				addressSpecific.remove("occupation");
				addressSpecific.remove("organization");
				address = new Address(addressSpecific);
			}
			
			return new Voucher(name, birthdateString, address, occupation, organization);
			
		} catch (Exception e) {
			throw new ParseException(e.getMessage(), e);
		}
	}
}
