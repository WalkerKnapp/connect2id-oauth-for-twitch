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
import com.nimbusds.openid.connect.sdk.assurance.claims.CountryCode;
import com.nimbusds.openid.connect.sdk.claims.Address;


/**
 * Electronic record source.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
public class ElectronicRecordSource extends CommonOriginatorAttributes {
	
	
	/**
	 * Creates a new electronic record source.
	 *
	 * @param name         The source name, {@code null} if not specified.
	 * @param address      The source address elements, {@code null} if not
	 *                     specified.
	 * @param countryCode  The source country code, {@code null} if not
	 *                     specified.
	 * @param jurisdiction The source jurisdiction, {@code null} if not
	 *                     specified.
	 */
	public ElectronicRecordSource(final Name name,
				      final Address address,
				      final CountryCode countryCode,
				      final Jurisdiction jurisdiction) {
		
		super(name, address, countryCode, jurisdiction);
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof ElectronicRecordSource)) return false;
		ElectronicRecordSource that = (ElectronicRecordSource) o;
		return Objects.equals(
			getName(), that.getName()) &&
			Objects.equals(getAddress(), that.getAddress()) &&
			Objects.equals(getCountryCode(), that.getCountryCode()) &&
			Objects.equals(getJurisdiction(), that.getJurisdiction());
	}
	
	
	/**
	 * Parses an electronic record source from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The electronic record source.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ElectronicRecordSource parse(final JSONObject jsonObject)
		throws ParseException {
		
		CommonOriginatorAttributes commonOriginatorAttributes = CommonOriginatorAttributes.parse(jsonObject);
		
		return new ElectronicRecordSource(
			commonOriginatorAttributes.getName(),
			commonOriginatorAttributes.getAddress(),
			commonOriginatorAttributes.getCountryCode(),
			commonOriginatorAttributes.getJurisdiction()
		);
	}
}
