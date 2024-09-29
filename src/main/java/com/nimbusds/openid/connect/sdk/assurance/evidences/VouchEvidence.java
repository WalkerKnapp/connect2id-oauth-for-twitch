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
 * Vouch used as identity evidence.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
public class VouchEvidence extends IdentityEvidence {
	
	
	/**
	 * The vouch validation method.
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
	 * The vouch verification timestamp.
	 */
	private final DateWithTimeZoneOffset time;
	
	
	/**
	 * The attestation details.
	 */
	private final Attestation attestation;
	
	
	/**
	 * Creates a new vouch evidence.
	 *
	 * @param validationMethod   The vouch validation method, {@code null} 
	 *                           if not specified.
	 * @param verificationMethod The person verification method,
	 *                           {@code null} if not specified.
	 * @param verifier           Optional verifier if not the OpenID
	 *                           provider itself, {@code null} if none.
	 * @param time               The vouch verification timestamp,
	 *                           {@code null} if not specified.
	 * @param attestation        The attestation, {@code null} if not
	 *                           specified.
	 * @param attachments        The optional attachments, {@code null} if
	 *                           not specified.
	 */
	public VouchEvidence(final ValidationMethod validationMethod,
			     final VerificationMethod verificationMethod,
			     final IdentityVerifier verifier,
			     final DateWithTimeZoneOffset time,
			     final Attestation attestation,
			     final List<Attachment> attachments) {
		super(IdentityEvidenceType.VOUCH, attachments);
		this.validationMethod = validationMethod;
		this.verificationMethod = verificationMethod;
		this.time = time;
		this.verifier = verifier;
		this.attestation = attestation;
	}
	
	
	/**
	 * Returns the vouch validation method.
	 *
	 * @return The vouch validation method, {@code null} if not
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
	 * Returns the vouch verification timestamp.
	 *
	 * @return The vouch verification timestamp, {@code null} if not
	 *         specified.
	 */
	public DateWithTimeZoneOffset getVerificationTime() {
		return time;
	}
	
	
	/**
	 * Returns the attestation.
	 *
	 * @return The attestation, {@code null} if not specified.
	 */
	public Attestation getAttestation() {
		return attestation;
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
		if (getAttestation() != null) {
			o.put("attestation", getAttestation().toJSONObject());
		}
		return o;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof VouchEvidence)) return false;
		VouchEvidence that = (VouchEvidence) o;
		return Objects.equals(getValidationMethod(), that.getValidationMethod()) &&
			Objects.equals(getVerificationMethod(), that.getVerificationMethod()) &&
			Objects.equals(getVerifier(), that.getVerifier()) &&
			Objects.equals(getVerificationTime(), that.getVerificationTime()) &&
			Objects.equals(getAttestation(), that.getAttestation());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(
			getValidationMethod(),
			getVerificationMethod(),
			getVerifier(),
			getVerificationTime(),
			getAttestation()
		);
	}
	
	
	/**
	 * Parses a vouch evidence from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The vouch evidence.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static VouchEvidence parse(final JSONObject jsonObject)
		throws ParseException {
		
		ensureType(IdentityEvidenceType.VOUCH, jsonObject);
		
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
		
		DateWithTimeZoneOffset time = null;
		if (jsonObject.get("time") != null) {
			time = DateWithTimeZoneOffset.parseISO8601String(JSONObjectUtils.getNonBlankString(jsonObject, "time"));
		}
		
		Attestation attestation = null;
		if (jsonObject.get("attestation") != null) {
			attestation = Attestation.parse(JSONObjectUtils.getJSONObject(jsonObject, "attestation"));
		}
		
		List<Attachment> attachments = null;
		if (jsonObject.get("attachments") != null) {
			attachments = Attachment.parseList(JSONObjectUtils.getJSONArray(jsonObject, "attachments"));
		}
		
		return new VouchEvidence(validationMethod, verificationMethod, verifier, time, attestation, attachments);
	}
}
