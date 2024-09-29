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
import com.nimbusds.oauth2.sdk.util.date.SimpleDate;


/**
 * Attestation.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
public class Attestation {
	
	
	/**
	 * The vouch type.
	 */
	private final VouchType type;
	
	
	/**
	 * The reference number.
	 */
	private final ReferenceNumber referenceNumber;
	
	
	/**
	 * The personal number.
	 */
	private final PersonalNumber personalNumber;
	
	
	/**
	 * The date of issuance.
	 */
	private final SimpleDate dateOfIssuance;
	
	
	/**
	 * The date of expiry.
	 */
	private final SimpleDate dateOfExpiry;
	
	
	/**
	 * The voucher information.
	 */
	private final Voucher voucher;
	
	
	/**
	 * Creates a new attestation instance.
	 *
	 * @param type            The vouch type. Must not be {@code null}.
	 * @param referenceNumber The reference number, {@code null} if not
	 *                        specified.
	 * @param personalNumber  The personal number, {@code null} if not
	 *                        specified.
	 * @param dateOfIssuance  The date of issuance, {@code null} if not
	 *                        specified.
	 * @param dateOfExpiry    The date of expiry, {@code null} if not
	 *                        specified.
	 * @param voucher         The voucher information, {@code null} if not
	 *                        specified.
	 */
	public Attestation(final VouchType type,
			   final ReferenceNumber referenceNumber,
			   final PersonalNumber personalNumber,
			   final SimpleDate dateOfIssuance,
			   final SimpleDate dateOfExpiry,
			   final Voucher voucher) {
		Objects.requireNonNull(type);
		this.type = type;
		this.referenceNumber = referenceNumber;
		this.personalNumber = personalNumber;
		this.dateOfIssuance = dateOfIssuance;
		this.dateOfExpiry = dateOfExpiry;
		this.voucher = voucher;
	}
	
	
	/**
	 * Returns the vouch type.
	 *
	 * @return The vouch type.
	 */
	public VouchType getType() {
		return type;
	}
	
	
	/**
	 * Returns the reference number.
	 *
	 * @return The reference number, {@code null} if not specified.
	 */
	public ReferenceNumber getReferenceNumber() {
		return referenceNumber;
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
	 * Returns the voucher information.
	 *
	 * @return The voucher information, {@code null} if not specified.
	 */
	public Voucher getVoucher() {
		return voucher;
	}
	
	
	/**
	 * Returns a JSON object representation of this attestation instance.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		JSONObject o = new JSONObject();
		o.put("type", getType().getValue());
		if (getReferenceNumber() != null) {
			o.put("reference_number", getReferenceNumber().getValue());
		}
		if (getPersonalNumber() != null) {
			o.put("personal_number", getPersonalNumber().getValue());
		}
		if (getDateOfIssuance() != null) {
			o.put("date_of_issuance", getDateOfIssuance().toISO8601String());
		}
		if (getDateOfExpiry() != null) {
			o.put("date_of_expiry", getDateOfExpiry().toISO8601String());
		}
		if (getVoucher() != null) {
			JSONObject voucherObject = getVoucher().toJSONObject();
			if (! voucherObject.isEmpty()) {
				o.put("voucher", voucherObject);
			}
		}
		return o;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof Attestation)) return false;
		Attestation that = (Attestation) o;
		return getType().equals(that.getType()) &&
			Objects.equals(getReferenceNumber(), that.getReferenceNumber()) &&
			Objects.equals(getPersonalNumber(), that.getPersonalNumber()) &&
			Objects.equals(getDateOfIssuance(), that.getDateOfIssuance()) &&
			Objects.equals(getDateOfExpiry(), that.getDateOfExpiry()) &&
			Objects.equals(getVoucher(), that.getVoucher());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(getType(), getReferenceNumber(), getPersonalNumber(), getDateOfIssuance(), getDateOfExpiry(), getVoucher());
	}
	
	
	/**
	 * Parses an attestation instance from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The attestation instance.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static Attestation parse(final JSONObject jsonObject)
		throws ParseException {
		
		try {
			VouchType type = new VouchType(JSONObjectUtils.getNonBlankString(jsonObject, "type"));
			
			ReferenceNumber referenceNumber = null;
			if (jsonObject.get("reference_number") != null) {
				referenceNumber = new ReferenceNumber(JSONObjectUtils.getNonBlankString(jsonObject, "reference_number"));
			}
			
			PersonalNumber personalNumber = null;
			if (jsonObject.get("personal_number") != null) {
				personalNumber = new PersonalNumber(JSONObjectUtils.getNonBlankString(jsonObject, "personal_number"));
			}
			
			SimpleDate dateOfIssuance = null;
			if (jsonObject.get("date_of_issuance") != null) {
				dateOfIssuance = SimpleDate.parseISO8601String(JSONObjectUtils.getNonBlankString(jsonObject, "date_of_issuance"));
			}
			
			SimpleDate dateOfExpiry = null;
			if (jsonObject.get("date_of_expiry") != null) {
				dateOfExpiry = SimpleDate.parseISO8601String(JSONObjectUtils.getNonBlankString(jsonObject, "date_of_expiry"));
			}
			
			Voucher voucher = null;
			if (jsonObject.get("voucher") != null) {
				voucher = Voucher.parse(JSONObjectUtils.getJSONObject(jsonObject, "voucher"));
			}
			
			return new Attestation(type, referenceNumber, personalNumber, dateOfIssuance, dateOfExpiry, voucher);
			
		} catch (Exception e) {
			throw new ParseException(e.getMessage(), e);
		}
	}
}
