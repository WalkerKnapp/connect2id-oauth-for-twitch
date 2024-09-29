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

package com.nimbusds.openid.connect.sdk.assurance.evidences;


import java.util.Objects;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.date.DateWithTimeZoneOffset;
import com.nimbusds.oauth2.sdk.util.date.SimpleDate;


/**
 * Electronic record details.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
public class ElectronicRecordDetails {
	
	
	/**
	 * The electronic record type.
	 */
	private final ElectronicRecordType type;
	
	
	/**
	 * The personal number.
	 */
	private final PersonalNumber personalNumber;
	
	
	/**
	 * The time of creation.
	 */
	private final DateWithTimeZoneOffset createdAt;
	
	
	/**
	 * The date of expiry.
	 */
	private final SimpleDate dateOfExpiry;
	
	
	/**
	 * The electronic record source.
	 */
	private final ElectronicRecordSource source;
	
	
	/**
	 * Creates a new electronic record details instance.
	 *
	 * @param type           The electronic record type. Must not be
	 *                       {@code null}.
	 * @param personalNumber The personal number, {@code null} if not
	 *                       specified.
	 * @param createdAt      The time of creation, {@code null} if not
	 *                       specified.
	 * @param dateOfExpiry   The date of expiry, {@code null} if not
	 *                       specified.
	 * @param source         The electronic record source, {@code null} if
	 *                       not specified.
	 */
	public ElectronicRecordDetails(final ElectronicRecordType type,
				       final PersonalNumber personalNumber,
				       final DateWithTimeZoneOffset createdAt,
				       final SimpleDate dateOfExpiry,
				       final ElectronicRecordSource source) {
		Objects.requireNonNull(type);
		this.type = type;
		this.personalNumber = personalNumber;
		this.createdAt = createdAt;
		this.dateOfExpiry = dateOfExpiry;
		this.source = source;
	}
	
	
	/**
	 * Returns the electronic record type.
	 *
	 * @return The electronic record type.
	 */
	public ElectronicRecordType getType() {
		return type;
	}
	
	
	/**
	 * Returns the personal number.
	 *
	 * @return The personal number, {@code null} if not specified.
	 */
	public PersonalNumber getPersonalNumber() {
		return personalNumber;
	}
	
	
	/**
	 * Returns the time of creation.
	 *
	 * @return The time of creation, {@code null} if not specified.
	 */
	public DateWithTimeZoneOffset getCreatedAt() {
		return createdAt;
	}
	
	
	/**
	 * Returns the date of expiry.
	 *
	 * @return The date of expiry, {@code null} if not specified.
	 */
	public SimpleDate getDateOfExpiry() {
		return dateOfExpiry;
	}
	
	
	/**
	 * Returns the electronic record source.
	 *
	 * @return The electronic record source, {@code null} if not specified.
	 */
	public ElectronicRecordSource getSource() {
		return source;
	}
	
	
	/**
	 * Returns a JSON object representation of this electronic record
	 * details instance.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		JSONObject o = new JSONObject();
		o.put("type", getType().getValue());
		if (getPersonalNumber() != null) {
			o.put("personal_number", getPersonalNumber().getValue());
		}
		if (getCreatedAt() != null) {
				o.put("created_at", getCreatedAt().toISO8601String());
		}
		if (getDateOfExpiry() != null) {
			o.put("date_of_expiry", getDateOfExpiry().toISO8601String());
		}
		if (getSource() != null) {
			JSONObject sourceObject = getSource().toJSONObject();
			if (! sourceObject.isEmpty()) {
				o.put("source", sourceObject);
			}
		}
		return o;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof ElectronicRecordDetails)) return false;
		ElectronicRecordDetails that = (ElectronicRecordDetails) o;
		return getType().equals(that.getType()) &&
			Objects.equals(getPersonalNumber(), that.getPersonalNumber()) &&
			Objects.equals(getCreatedAt(), that.getCreatedAt()) &&
			Objects.equals(getDateOfExpiry(), that.getDateOfExpiry()) &&
			Objects.equals(getSource(), that.getSource());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(getType(), getPersonalNumber(), getCreatedAt(), getDateOfExpiry(), getSource());
	}
	
	
	/**
	 * Parses an electronic record details instance from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The electronic record details instance.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ElectronicRecordDetails parse(final JSONObject jsonObject)
		throws ParseException {
		
		try {
			ElectronicRecordType type = new ElectronicRecordType(JSONObjectUtils.getNonBlankString(jsonObject, "type"));
			
			PersonalNumber personalNumber = null;
			if (jsonObject.get("personal_number") != null) {
				personalNumber = new PersonalNumber(JSONObjectUtils.getNonBlankString(jsonObject, "personal_number"));
			}
			
			DateWithTimeZoneOffset createdAt = null;
			if (jsonObject.get("created_at") != null) {
				createdAt = DateWithTimeZoneOffset.parseISO8601String(JSONObjectUtils.getNonBlankString(jsonObject, "created_at"));
			}
			
			SimpleDate dateOfExpiry = null;
			if (jsonObject.get("date_of_expiry") != null) {
				dateOfExpiry = SimpleDate.parseISO8601String(JSONObjectUtils.getNonBlankString(jsonObject, "date_of_expiry"));
			}
			
			ElectronicRecordSource source = null;
			if (jsonObject.get("source") != null) {
				source = ElectronicRecordSource.parse(JSONObjectUtils.getJSONObject(jsonObject, "source"));
			}
			
			return new ElectronicRecordDetails(type, personalNumber, createdAt, dateOfExpiry, source);
			
		} catch (Exception e) {
			throw new ParseException(e.getMessage(), e);
		}
	}
}
