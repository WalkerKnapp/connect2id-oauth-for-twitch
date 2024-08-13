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

import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.date.SimpleDate;
import com.nimbusds.openid.connect.sdk.assurance.claims.CountryCode;
import com.nimbusds.openid.connect.sdk.assurance.claims.ISO3166_1Alpha2CountryCode;


/**
 * Identity document description.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
@Deprecated
public class IDDocumentDescription implements JSONAware {
	
	
	/**
	 * The type.
	 */
	private final IDDocumentType type;
	
	
	/**
	 * The number.
	 */
	private final String number;
	
	
	/**
	 * The issuer name.
	 */
	private final String issuerName;
	
	
	/**
	 * The issuer country.
	 */
	private final CountryCode issuerCountry;
	
	
	/**
	 * The date of issuance.
	 */
	private final SimpleDate dateOfIssuance;
	
	
	/**
	 * The date of expiry.
	 */
	private final SimpleDate dateOfExpiry;
	
	
	/**
	 * Creates a new identity document description.
	 *
	 * @param type           The type. Must not be {@code null}.
	 * @param number         The number, {@code null} if not specified.
	 * @param issuerName     The issuer name, {@code null} if not
	 *                       specified.
	 * @param issuerCountry  The issuer country, {@code null} if not
	 *                       specified.
	 * @param dateOfIssuance The date of issuance, {@code null} if not
	 *                       specified.
	 * @param dateOfExpiry   The date of expiry, {@code null} if not
	 *                       specified.
	 */
	public IDDocumentDescription(final IDDocumentType type,
				     final String number,
				     final String issuerName,
				     final CountryCode issuerCountry,
				     final SimpleDate dateOfIssuance,
				     final SimpleDate dateOfExpiry) {
		
		if (type == null) {
			throw new IllegalArgumentException("The type must not be null");
		}
		this.type = type;
		
		this.number = number;
		this.issuerName = issuerName;
		this.issuerCountry = issuerCountry;
		this.dateOfIssuance = dateOfIssuance;
		this.dateOfExpiry = dateOfExpiry;
	}
	
	
	/**
	 * Returns the identity document type.
	 *
	 * @return The identity document type.
	 */
	public IDDocumentType getType() {
		return type;
	}
	
	
	/**
	 * Returns the identity document number.
	 *
	 * @return The identity document number, {@code null} if not specified.
	 */
	public String getNumber() {
		return number;
	}
	
	
	/**
	 * Returns the issuer name.
	 *
	 * @return The issuer name, {@code null} if not specified.
	 */
	public String getIssuerName() {
		return issuerName;
	}
	
	
	/**
	 * Returns the issuer country.
	 *
	 * @return The issuer country code, {@code null} if not specified.
	 */
	public CountryCode getIssuerCountry() {
		return issuerCountry;
	}
	
	
	/**
	 * Returns the date of issuance.
	 *
	 * @return The date of issuance, {@code null} if not specified.
	 */
	public SimpleDate getDateOfIssuance() {
		return dateOfIssuance;
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
	 * Returns a JSON object representation of this identity document
	 * description.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		JSONObject o = new JSONObject();
		o.put("type", getType().getValue());
		if (getNumber() != null) {
			o.put("number", getNumber());
		}
		JSONObject issuerObject = new JSONObject();
		if (getIssuerName() != null) {
			issuerObject.put("name", getIssuerName());
		}
		if (getIssuerCountry() != null) {
			issuerObject.put("country", getIssuerCountry().getValue());
		}
		if (! issuerObject.isEmpty()) {
			o.put("issuer", issuerObject);
		}
		if (getDateOfIssuance() != null) {
			o.put("date_of_issuance", getDateOfIssuance().toISO8601String());
		}
		if (getDateOfExpiry() != null) {
			o.put("date_of_expiry", getDateOfExpiry().toISO8601String());
		}
		return o;
	}
	
	
	@Override
	public String toJSONString() {
		return toJSONObject().toJSONString();
	}
	
	
	@Override
	public String toString() {
		return toJSONString();
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof IDDocumentDescription)) return false;
		IDDocumentDescription that = (IDDocumentDescription) o;
		return getType().equals(that.getType()) &&
			Objects.equals(getNumber(), that.getNumber()) &&
			Objects.equals(getIssuerName(), that.getIssuerName()) &&
			Objects.equals(getIssuerCountry(), that.getIssuerCountry()) &&
			Objects.equals(getDateOfIssuance(), that.getDateOfIssuance()) &&
			Objects.equals(getDateOfExpiry(), that.getDateOfExpiry());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(getType(), getNumber(), getIssuerName(), getIssuerCountry(), getDateOfIssuance(), getDateOfExpiry());
	}
	
	
	/**
	 * Parses an identity document description from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The identity document description.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static IDDocumentDescription parse(final JSONObject jsonObject)
		throws ParseException {
		
		IDDocumentType type = new IDDocumentType(JSONObjectUtils.getString(jsonObject, "type"));
		String number = JSONObjectUtils.getString(jsonObject, "number", null);
		
		JSONObject issuerObject = JSONObjectUtils.getJSONObject(jsonObject, "issuer", null);
		
		String issuerName = null;
		CountryCode issuerCountry = null;
		if (issuerObject != null) {
			issuerName = JSONObjectUtils.getString(issuerObject, "name", null);
			if (issuerObject.get("country") != null) {
				issuerCountry = ISO3166_1Alpha2CountryCode.parse(JSONObjectUtils.getString(issuerObject, "country"));
			}
		}
		
		SimpleDate dateOfIssuance = null;
		if (jsonObject.get("date_of_issuance") != null) {
			dateOfIssuance = SimpleDate.parseISO8601String(JSONObjectUtils.getString(jsonObject, "date_of_issuance"));
		}
		
		SimpleDate dateOfExpiry = null;
		if (jsonObject.get("date_of_expiry") != null) {
			dateOfExpiry = SimpleDate.parseISO8601String(JSONObjectUtils.getString(jsonObject, "date_of_expiry"));
		}
		
		return new IDDocumentDescription(type, number, issuerName, issuerCountry, dateOfIssuance, dateOfExpiry);
	}
}
