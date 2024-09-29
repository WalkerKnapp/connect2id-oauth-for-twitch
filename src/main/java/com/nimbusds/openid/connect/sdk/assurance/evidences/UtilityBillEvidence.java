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


import java.util.List;
import java.util.Objects;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.date.DateWithTimeZoneOffset;
import com.nimbusds.oauth2.sdk.util.date.SimpleDate;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.Attachment;
import com.nimbusds.openid.connect.sdk.claims.Address;


/**
 * Utility bill used as identity evidence.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
@Deprecated
public class UtilityBillEvidence extends IdentityEvidence {
	
	
	/**
	 * The utility provider name.
	 */
	private final String providerName;
	
	
	/**
	 * The utility provider address details.
	 */
	private final Address providerAddress;
	
	
	/**
	 * The utility bill date.
	 */
	private final SimpleDate date;
	
	
	/**
	 * The utility bill verification timestamp.
	 */
	private final DateWithTimeZoneOffset time;
	
	
	/**
	 * The identity verification method.
	 */
	private final IdentityVerificationMethod method;
	
	
	/**
	 * Creates a new utility bill used as identity evidence.
	 *
	 * @param providerName    The utility provider name, {@code null} if
	 *                        not specified.
	 * @param providerAddress The utility provider address details,
	 *                        {@code null} if not specified.
	 * @param date            The utility bill date, {@code null} if not
	 *                        specified.
	 */
	@Deprecated
	public UtilityBillEvidence(final String providerName, final Address providerAddress, final SimpleDate date) {
		
		this(providerName, providerAddress, date, null, null, null);
	}
	
	
	/**
	 * Creates a new utility bill used as identity evidence.
	 *
	 * @param providerName    The utility provider name, {@code null} if
	 *                        not specified.
	 * @param providerAddress The utility provider address details,
	 *                        {@code null} if not specified.
	 * @param date            The utility bill date, {@code null} if not
	 *                        specified.
	 * @param time             The utility bill verification timestamp,
	 *                        {@code null} if not specified.
	 * @param method          The identity verification method,
	 *                        {@code null} if not specified.
	 * @param attachments     The optional attachments, {@code null} if not
	 *                        specified.
	 */
	public UtilityBillEvidence(final String providerName,
				   final Address providerAddress,
				   final SimpleDate date,
				   final DateWithTimeZoneOffset time,
				   final IdentityVerificationMethod method,
				   final List<Attachment> attachments) {
		
		super(IdentityEvidenceType.UTILITY_BILL, attachments);
		this.providerName = providerName;
		this.providerAddress = providerAddress;
		this.date = date;
		this.time = time;
		this.method = method;
	}
	
	
	/**
	 * The utility provider name.
	 *
	 * @return The utility provider name, {@code null} if not specified.
	 */
	public String getUtilityProviderName() {
		return providerName;
	}
	
	
	/**
	 * Returns the utility provider address details.
	 *
	 * @return The utility provider address details, {@code null} if not
	 *         specified.
	 */
	public Address getUtilityProviderAddress() {
		return providerAddress;
	}
	
	
	/**
	 * Returns the utility bill date.
	 *
	 * @return The utility bill date, {@code null} if not specified.
	 */
	public SimpleDate getUtilityBillDate() {
		return date;
	}
	
	
	/**
	 * Returns the utility bill verification timestamp.
	 *
	 * @return The utility bill verification timestamp, {@code null} if not
	 *         specified.
	 */
	public DateWithTimeZoneOffset getVerificationTime() {
		return time;
	}
	
	
	/**
	 * Returns the utility bill verification method.
	 *
	 * @return The utility bill verification method, {@code null} if not
	 *         specified.
	 */
	public IdentityVerificationMethod getVerificationMethod() {
		return method;
	}
	
	
	@Override
	public JSONObject toJSONObject() {
		
		JSONObject o = super.toJSONObject();
		
		JSONObject providerDetails = new JSONObject();
		if (getUtilityProviderName() != null) {
			providerDetails.put("name", getUtilityProviderName());
		}
		if (getUtilityProviderAddress() != null) {
			providerDetails.putAll(getUtilityProviderAddress().toJSONObject());
		}
		if (! providerDetails.isEmpty()) {
			o.put("provider", providerDetails);
		}
		
		if (getUtilityBillDate() != null) {
			o.put("date", getUtilityBillDate().toISO8601String());
		}
		
		if (getVerificationTime() != null) {
			o.put("time", getVerificationTime().toISO8601String());
		}
		
		if (getVerificationMethod() != null) {
			o.put("method", getVerificationMethod().getValue());
		}
		
		return o;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof UtilityBillEvidence)) return false;
		UtilityBillEvidence evidence = (UtilityBillEvidence) o;
		return Objects.equals(getUtilityProviderName(), evidence.getUtilityProviderName()) &&
			Objects.equals(getUtilityProviderAddress(), evidence.getUtilityProviderAddress()) &&
			Objects.equals(getUtilityBillDate(), evidence.getUtilityBillDate()) &&
			Objects.equals(getVerificationTime(), evidence.getVerificationTime()) &&
			Objects.equals(getVerificationMethod(), evidence.getVerificationMethod());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(
			getUtilityProviderName(),
			getUtilityProviderAddress(),
			getUtilityBillDate(),
			getVerificationTime(),
			getVerificationMethod()
		);
	}
	
	
	/**
	 * Parses a utility bill evidence from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The utility bill evidence.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static UtilityBillEvidence parse(final JSONObject jsonObject)
		throws ParseException {
		
		ensureType(IdentityEvidenceType.UTILITY_BILL, jsonObject);
		
		JSONObject providerDetails = JSONObjectUtils.getJSONObject(jsonObject, "provider", null);
		
		String providerName = null;
		Address providerAddress = null;
		if (providerDetails != null) {
			providerName = JSONObjectUtils.getString(providerDetails, "name", null);
			
			JSONObject providerDetailsCopy = new JSONObject(providerDetails);
			providerDetailsCopy.remove("name");
			
			if (! providerDetailsCopy.isEmpty()) {
				providerAddress = new Address(providerDetailsCopy);
			}
		}
		
		SimpleDate date = null;
		if (jsonObject.get("date") != null) {
			date = SimpleDate.parseISO8601String(JSONObjectUtils.getNonBlankString(jsonObject, "date"));
		}
		
		DateWithTimeZoneOffset dtz = null;
		if (jsonObject.get("time") != null) {
			dtz = DateWithTimeZoneOffset.parseISO8601String(JSONObjectUtils.getNonBlankString(jsonObject, "time"));
		}
		
		IdentityVerificationMethod method = null;
		if (jsonObject.get("method") != null) {
			method = new IdentityVerificationMethod(JSONObjectUtils.getNonBlankString(jsonObject, "method"));
		}
		
		List<Attachment> attachments = null;
		if (jsonObject.get("attachments") != null) {
			attachments = Attachment.parseList(JSONObjectUtils.getJSONArray(jsonObject, "attachments"));
		}
		
		return new UtilityBillEvidence(providerName, providerAddress, date, dtz, method, attachments);
	}
}
