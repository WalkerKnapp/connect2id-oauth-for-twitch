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
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.Attachment;


/**
 * Electronic record used as identity evidence.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
public class ElectronicRecordEvidence extends IdentityEvidence {
	
	
	/**
	 * The electronic record validation method.
	 */
	private final ValidationMethod validationMethod;
	
	
	/**
	 * The person verification method.
	 */
	private final VerificationMethod verificationMethod;
	
	
	/**
	 * The identity verifier if not the OpenID provider itself.
	 */
	private final IdentityVerifier verifier;
	
	
	/**
	 * The electronic record verification timestamp.
	 */
	private final DateWithTimeZoneOffset time;
	
	
	/**
	 * The electronic record details.
	 */
	private final ElectronicRecordDetails recordDetails;
	
	
	/**
	 * Creates a new electronic record evidence.
	 *
	 * @param validationMethod   The eletronic record validation method,
	 *                           {@code null} if not specified.
	 * @param verificationMethod The person verification method,
	 *                           {@code null} if not specified.
	 * @param verifier           Optional verifier if not the OpenID
	 *                           provider itself, {@code null} if none.
	 * @param time                The electronic record verification
	 *                           timestamp, {@code null} if not specified.
	 * @param recordDetails      The electronic record details,
	 *                           {@code null} if not specified.
	 * @param attachments        The optional attachments, {@code null} if
	 *                           not specified.
	 */
	public ElectronicRecordEvidence(final ValidationMethod validationMethod,
					final VerificationMethod verificationMethod,
					final IdentityVerifier verifier,
					final DateWithTimeZoneOffset time,
					final ElectronicRecordDetails recordDetails,
					final List<Attachment> attachments) {
		super(IdentityEvidenceType.ELECTRONIC_RECORD, attachments);
		this.validationMethod = validationMethod;
		this.verificationMethod = verificationMethod;
		this.time = time;
		this.verifier = verifier;
		this.recordDetails = recordDetails;
	}
	
	
	/**
	 * Returns the electronic record validation method.
	 *
	 * @return The electronic record validation method, {@code null} if not
	 *         specified.
	 */
	public ValidationMethod getValidationMethod() {
		return validationMethod;
	}
	
	
	/**
	 * Returns the person verification method.
	 *
	 * @return The person verification method, {@code null} if not
	 *         specified.
	 */
	public VerificationMethod getVerificationMethod() {
		return verificationMethod;
	}
	
	
	/**
	 * Returns the optional verifier if not the OpenID provider itself.
	 *
	 * @return The optional verifier if not the OpenID provider itself,
	 *         {@code null} if none.
	 */
	public IdentityVerifier getVerifier() {
		return verifier;
	}
	
	
	/**
	 * Returns the electronic record verification timestamp.
	 *
	 * @return The electronic record verification timestamp, {@code null}
	 *         if not specified.
	 */
	public DateWithTimeZoneOffset getVerificationTime() {
		return time;
	}
	
	
	/**
	 * Returns the electronic record details.
	 *
	 * @return The electronic record details, {@code null} if not
	 *          specified.
	 */
	public ElectronicRecordDetails getRecordDetails() {
		return recordDetails;
	}
	
	
	@Override
	public JSONObject toJSONObject() {
		JSONObject o = super.toJSONObject();
		if (getValidationMethod() != null) {
			o.put("validation_method", getValidationMethod().toJSONObject());
		}
		if (getVerificationMethod() != null) {
			o.put("verification_method", getVerificationMethod().toJSONObject());
		}
		if (getVerifier() != null) {
			o.put("verifier", getVerifier().toJSONObject());
		}
		if (getVerificationTime() != null) {
			o.put("time", getVerificationTime().toISO8601String());
		}
		if (getRecordDetails() != null) {
			o.put("record", getRecordDetails().toJSONObject());
		}
		return o;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof ElectronicRecordEvidence)) return false;
		ElectronicRecordEvidence that = (ElectronicRecordEvidence) o;
		return Objects.equals(getValidationMethod(), that.getValidationMethod()) &&
			Objects.equals(getVerificationMethod(), that.getVerificationMethod()) &&
			Objects.equals(getVerifier(), that.getVerifier()) &&
			Objects.equals(getVerificationTime(), that.getVerificationTime()) &&
			Objects.equals(getRecordDetails(), that.getRecordDetails());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(getValidationMethod(), getVerificationMethod(), getVerifier(), getVerificationTime(), getRecordDetails());
	}
	
	
	/**
	 * Parses an electronic record evidence from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The electronic record evidence.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ElectronicRecordEvidence parse(final JSONObject jsonObject)
		throws ParseException {
		
		ensureType(IdentityEvidenceType.ELECTRONIC_RECORD, jsonObject);
		
		ValidationMethod validationMethod = null;
		if (jsonObject.get("validation_method") != null) {
			validationMethod = ValidationMethod.parse(JSONObjectUtils.getJSONObject(jsonObject, "validation_method"));
		}
		
		VerificationMethod verificationMethod = null;
		if (jsonObject.get("verification_method") != null) {
			verificationMethod = VerificationMethod.parse(JSONObjectUtils.getJSONObject(jsonObject, "verification_method"));
		}
		IdentityVerifier verifier = null;
		if (jsonObject.get("verifier") != null) {
			verifier = IdentityVerifier.parse(JSONObjectUtils.getJSONObject(jsonObject, "verifier"));
		}
		DateWithTimeZoneOffset dtz = null;
		if (jsonObject.get("time") != null) {
			dtz = DateWithTimeZoneOffset.parseISO8601String(JSONObjectUtils.getString(jsonObject, "time"));
		}
		
		ElectronicRecordDetails recordDetails = null;
		if (jsonObject.get("record") != null) {
			recordDetails = ElectronicRecordDetails.parse(JSONObjectUtils.getJSONObject(jsonObject, "record"));
		}
		
		List<Attachment> attachments = null;
		if (jsonObject.get("attachments") != null) {
			attachments = Attachment.parseList(JSONObjectUtils.getJSONArray(jsonObject, "attachments"));
		}
		
		return new ElectronicRecordEvidence(validationMethod, verificationMethod, verifier, dtz, recordDetails, attachments);
	}
}
