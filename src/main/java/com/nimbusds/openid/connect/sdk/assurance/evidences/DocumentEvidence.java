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
 * Document used as identity evidence.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
public class DocumentEvidence extends IdentityEvidence {
	
	
	/**
	 * The document validation method.
	 */
	private final ValidationMethod validationMethod;
	
	
	/**
	 * The person verification method.
	 */
	private final VerificationMethod verificationMethod;
	
	
	/**
	 * The verification method.
	 */
	@Deprecated
	private final IdentityVerificationMethod method;
	
	
	/**
	 * The identity verifier if not the OpenID provider itself.
	 */
	private final IdentityVerifier verifier;
	
	
	/**
	 * The document verification timestamp.
	 */
	private final DateWithTimeZoneOffset time;
	
	
	/**
	 * The document details.
	 */
	private final DocumentDetails documentDetails;
	
	
	/**
	 * Creates a new document evidence.
	 *
	 * @param validationMethod   The document validation method,
	 *                           {@code null} if not specified.
	 * @param verificationMethod The person verification method,
	 *                           {@code null} if not specified.
	 * @param method             The alternative coarse identity
	 *                           verification method, {@code null} if not
	 *                           specified.
	 * @param verifier           Optional verifier if not the OpenID
	 *                           provider itself, {@code null} if none.
	 * @param time                The document verification timestamp,
	 *                           {@code null} if not specified.
	 * @param documentDetails    The document details, {@code null} if not
	 *                           specified.
	 * @param attachments        The optional attachments, {@code null} if
	 *                           not specified.
	 */
	public DocumentEvidence(final ValidationMethod validationMethod,
				final VerificationMethod verificationMethod,
				final IdentityVerificationMethod method,
				final IdentityVerifier verifier,
				final DateWithTimeZoneOffset time,
				final DocumentDetails documentDetails,
				final List<Attachment> attachments) {
		super(IdentityEvidenceType.DOCUMENT, attachments);
		this.validationMethod = validationMethod;
		this.verificationMethod = verificationMethod;
		this.method = method;
		this.time = time;
		this.verifier = verifier;
		this.documentDetails = documentDetails;
	}
	
	
	/**
	 * Returns the document validation method.
	 *
	 * @return The document validation method, {@code null} if not
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
	 * Returns the alternative coarse identity verification method.
	 *
	 * @return The identity verification method, {@code null} if not
	 *         specified.
	 */
	@Deprecated
	public IdentityVerificationMethod getMethod() {
		return method;
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
	 * Returns the document verification timestamp.
	 *
	 * @return The document verification timestamp, {@code null} if not
	 *         specified.
	 */
	public DateWithTimeZoneOffset getVerificationTime() {
		return time;
	}
	
	
	/**
	 * Returns the document details.
	 *
	 * @return The document details, {@code null} if not specified.
	 */
	public DocumentDetails getDocumentDetails() {
		return documentDetails;
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
		if (getMethod() != null) {
			o.put("method", getMethod().getValue());
		}
		if (getVerifier() != null) {
			o.put("verifier", getVerifier().toJSONObject());
		}
		if (getVerificationTime() != null) {
			o.put("time", getVerificationTime().toISO8601String());
		}
		if (getDocumentDetails() != null) {
			o.put("document_details", getDocumentDetails().toJSONObject());
		}
		return o;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof DocumentEvidence)) return false;
		DocumentEvidence that = (DocumentEvidence) o;
		return Objects.equals(getValidationMethod(), that.getValidationMethod()) &&
			Objects.equals(getVerificationMethod(), that.getVerificationMethod()) &&
			Objects.equals(getMethod(), that.getMethod()) &&
			Objects.equals(getVerifier(), that.getVerifier()) &&
			Objects.equals(getVerificationTime(), that.getVerificationTime()) &&
			Objects.equals(getDocumentDetails(), that.getDocumentDetails());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(getValidationMethod(), getVerificationMethod(), getMethod(), getVerifier(), getVerificationTime(), getDocumentDetails());
	}
	
	
	/**
	 * Parses a document evidence from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The document evidence.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static DocumentEvidence parse(final JSONObject jsonObject)
		throws ParseException {
		
		ensureType(IdentityEvidenceType.DOCUMENT, jsonObject);
		
		ValidationMethod validationMethod = null;
		if (jsonObject.get("validation_method") != null) {
			validationMethod = ValidationMethod.parse(JSONObjectUtils.getJSONObject(jsonObject, "validation_method"));
		}
		
		VerificationMethod verificationMethod = null;
		if (jsonObject.get("verification_method") != null) {
			verificationMethod = VerificationMethod.parse(JSONObjectUtils.getJSONObject(jsonObject, "verification_method"));
		}
		IdentityVerificationMethod method = null;
		if (jsonObject.get("method") != null) {
			method = new IdentityVerificationMethod(JSONObjectUtils.getString(jsonObject, "method"));
		}
		IdentityVerifier verifier = null;
		if (jsonObject.get("verifier") != null) {
			verifier = IdentityVerifier.parse(JSONObjectUtils.getJSONObject(jsonObject, "verifier"));
		}
		DateWithTimeZoneOffset dtz = null;
		if (jsonObject.get("time") != null) {
			dtz = DateWithTimeZoneOffset.parseISO8601String(JSONObjectUtils.getString(jsonObject, "time"));
		}
		
		DocumentDetails documentDetails = null;
		if (jsonObject.get("document_details") != null) {
			documentDetails = DocumentDetails.parse(JSONObjectUtils.getJSONObject(jsonObject, "document_details"));
		}
		
		List<Attachment> attachments = null;
		if (jsonObject.get("attachments") != null) {
			attachments = Attachment.parseList(JSONObjectUtils.getJSONArray(jsonObject, "attachments"));
		}
		
		return new DocumentEvidence(validationMethod, verificationMethod, method, verifier, dtz, documentDetails, attachments);
	}
}
