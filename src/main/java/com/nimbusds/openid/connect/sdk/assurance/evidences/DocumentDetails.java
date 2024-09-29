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


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.date.SimpleDate;
import net.minidev.json.JSONObject;

import java.util.Objects;


/**
 * Document details.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
public class DocumentDetails {
	
	
	/**
	 * The document type.
	 */
	private final DocumentType type;
	
	
	/**
	 * The document number.
	 */
	private final DocumentNumber documentNumber;
	
	
	/**
	 * The personal number.
	 */
	private final PersonalNumber personalNumber;
	
	
	/**
	 * The serial number.
	 */
	private final SerialNumber serialNumber;
	
	
	/**
	 * The date of issuance.
	 */
	private final SimpleDate dateOfIssuance;
	
	
	/**
	 * The date of expiry.
	 */
	private final SimpleDate dateOfExpiry;
	
	
	/**
	 * The document issuer information.
	 */
	private final DocumentIssuer issuer;
	
	
	/**
	 * Creates a new document details instance.
	 *
	 * @param type           The document type. Must not be {@code null}.
	 * @param documentNumber The document number, {@code null} if not
	 *                       specified.
	 * @param personalNumber The personal number, {@code null} if not
	 *                       specified.
	 * @param serialNumber   The serial number, {@code null} if not
	 *                       specified.
	 * @param dateOfIssuance The date of issuance, {@code null} if not
	 *                       specified.
	 * @param dateOfExpiry   The date of expiry, {@code null} if not
	 *                       specified.
	 * @param issuer         The document issuer information, {@code null}
	 *                       if not specified.
	 */
	public DocumentDetails(final DocumentType type,
			       final DocumentNumber documentNumber,
			       final PersonalNumber personalNumber,
			       final SerialNumber serialNumber,
			       final SimpleDate dateOfIssuance,
			       final SimpleDate dateOfExpiry,
			       final DocumentIssuer issuer) {
		Objects.requireNonNull(type);
		this.type = type;
		this.documentNumber = documentNumber;
		this.personalNumber = personalNumber;
		this.serialNumber = serialNumber;
		this.dateOfIssuance = dateOfIssuance;
		this.dateOfExpiry = dateOfExpiry;
		this.issuer = issuer;
	}
	
	
	/**
	 * Returns the document type.
	 *
	 * @return The document type.
	 */
	public DocumentType getType() {
		return type;
	}
	
	
	/**
	 * Returns the document number.
	 *
	 * @return The document number, {@code null} if not specified.
	 */
	public DocumentNumber getDocumentNumber() {
		return documentNumber;
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
	 * Returns the serial number.
	 *
	 * @return The serial number, {@code null} if not specified.
	 */
	public SerialNumber getSerialNumber() {
		return serialNumber;
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
	 * Returns the document issuer information.
	 *
	 * @return The document issuer information, {@code null} if not
	 *         specified.
	 */
	public DocumentIssuer getIssuer() {
		return issuer;
	}
	
	
	/**
	 * Returns a JSON object representation of this document details
	 * instance.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		JSONObject o = new JSONObject();
		o.put("type", getType().getValue());
		if (getDocumentNumber() != null) {
			o.put("document_number", getDocumentNumber().getValue());
		}
		if (getPersonalNumber() != null) {
			o.put("personal_number", getPersonalNumber().getValue());
		}
		if (getSerialNumber() != null) {
			o.put("serial_number", getSerialNumber().getValue());
		}
		if (getDateOfIssuance() != null) {
			o.put("date_of_issuance", getDateOfIssuance().toISO8601String());
		}
		if (getDateOfExpiry() != null) {
			o.put("date_of_expiry", getDateOfExpiry().toISO8601String());
		}
		if (getIssuer() != null) {
			JSONObject issuerObject = getIssuer().toJSONObject();
			if (! issuerObject.isEmpty()) {
				o.put("issuer", issuerObject);
			}
		}
		return o;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof DocumentDetails)) return false;
		DocumentDetails that = (DocumentDetails) o;
		return getType().equals(that.getType()) &&
			Objects.equals(getDocumentNumber(), that.getDocumentNumber()) &&
			Objects.equals(getPersonalNumber(), that.getPersonalNumber()) &&
			Objects.equals(getSerialNumber(), that.getSerialNumber()) &&
			Objects.equals(getDateOfIssuance(), that.getDateOfIssuance()) &&
			Objects.equals(getDateOfExpiry(), that.getDateOfExpiry()) &&
			Objects.equals(getIssuer(), that.getIssuer());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(
			getType(),
			getDocumentNumber(),
			getPersonalNumber(),
			getSerialNumber(),
			getDateOfIssuance(),
			getDateOfExpiry(),
			getIssuer()
		);
	}
	
	
	/**
	 * Parses a document details instance from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The document details instance.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static DocumentDetails parse(final JSONObject jsonObject)
		throws ParseException {

		DocumentType type = new DocumentType(JSONObjectUtils.getNonBlankString(jsonObject, "type"));

		DocumentNumber documentNumber = null;
		if (jsonObject.get("document_number") != null) {
			documentNumber = new DocumentNumber(JSONObjectUtils.getNonBlankString(jsonObject, "document_number"));
		}

		PersonalNumber personalNumber = null;
		if (jsonObject.get("personal_number") != null) {
			personalNumber = new PersonalNumber(JSONObjectUtils.getNonBlankString(jsonObject, "personal_number"));
		}

		SerialNumber serialNumber = null;
		if (jsonObject.get("serial_number") != null) {
			serialNumber = new SerialNumber(JSONObjectUtils.getNonBlankString(jsonObject, "serial_number"));
		}

		SimpleDate dateOfIssuance = null;
		if (jsonObject.get("date_of_issuance") != null) {
			dateOfIssuance = SimpleDate.parseISO8601String(JSONObjectUtils.getNonBlankString(jsonObject, "date_of_issuance"));
		}

		SimpleDate dateOfExpiry = null;
		if (jsonObject.get("date_of_expiry") != null) {
			dateOfExpiry = SimpleDate.parseISO8601String(JSONObjectUtils.getNonBlankString(jsonObject, "date_of_expiry"));
		}

		DocumentIssuer issuer = null;
		if (jsonObject.get("issuer") != null) {
			issuer = DocumentIssuer.parse(JSONObjectUtils.getJSONObject(jsonObject, "issuer"));
		}

		return new DocumentDetails(type, documentNumber, personalNumber, serialNumber, dateOfIssuance, dateOfExpiry, issuer);
	}
}
