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


import java.util.LinkedList;
import java.util.List;

import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.Attachment;


/**
 * The base abstract class for identity evidences.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
public abstract class IdentityEvidence implements JSONAware {
	
	
	/**
	 * The evidence type.
	 */
	private final IdentityEvidenceType evidenceType;
	
	
	/**
	 * The optional attachments.
	 */
	private final List<Attachment> attachments;
	
	
	/**
	 * Creates a new evidence with the specified type.
	 *
	 * @param evidenceType The evidence type. Must not be {@code null}.
	 * @param attachments  The optional attachments, {@code null} if not
	 *                     specified.
	 */
	protected IdentityEvidence(final IdentityEvidenceType evidenceType,
				   final List<Attachment> attachments) {
		if (evidenceType == null) {
			throw new IllegalArgumentException("The evidence type must not be null");
		}
		this.evidenceType = evidenceType;
		
		this.attachments = attachments;
	}
	
	
	/**
	 * Returns the evidence type.
	 *
	 * @return The evidence type.
	 */
	public IdentityEvidenceType getEvidenceType() {
		return evidenceType;
	}
	
	
	/**
	 * Returns the optional attachments.
	 *
	 * @return The attachments, {@code null} if not specified.
	 */
	public List<Attachment> getAttachments() {
		return attachments;
	}
	
	
	/**
	 * Casts this identity evidence to a document evidence.
	 *
	 * @return The document evidence.
	 */
	public DocumentEvidence toDocumentEvidence() {
		
		return (DocumentEvidence)this;
	}
	
	
	/**
	 * Casts this identity evidence to an ID document evidence.
	 *
	 * @return The ID document evidence.
	 */
	public IDDocumentEvidence toIDDocumentEvidence() {
		
		return (IDDocumentEvidence)this;
	}
	
	
	/**
	 * Casts this identity evidence to an electronic record evidence.
	 *
	 * @return The electronic record evidence.
	 */
	public ElectronicRecordEvidence toElectronicRecordEvidence() {
		
		return (ElectronicRecordEvidence)this;
	}
	
	
	/**
	 * Casts this identity evidence to a vouch evidence.
	 *
	 * @return The vouch evidence.
	 */
	public VouchEvidence toVouchEvidence() {
		
		return (VouchEvidence)this;
	}
	
	
	/**
	 * Casts this identity evidence to a utility bill evidence.
	 *
	 * @return The utility bill evidence.
	 */
	public UtilityBillEvidence toUtilityBillEvidence() {
		
		return (UtilityBillEvidence)this;
	}
	
	
	/**
	 * Casts this identity evidence to an electronic signature evidence.
	 *
	 * @return The electronic signature evidence.
	 */
	public ElectronicSignatureEvidence toElectronicSignatureEvidence() {
		
		return (ElectronicSignatureEvidence)this;
	}
	
	
	/**
	 * Casts this identity evidence to a QES evidence.
	 *
	 * @return The QES evidence.
	 */
	public QESEvidence toQESEvidence() {
		
		return (QESEvidence)this;
	}
	
	
	/**
	 * Returns a JSON object representation of this evidence.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
	
		JSONObject o = new JSONObject();
		
		o.put("type", getEvidenceType().getValue());
		
		if (CollectionUtils.isNotEmpty(getAttachments())) {
			List<Object> attachmentsJSONArray = new LinkedList<>();
			for (Attachment attachment: getAttachments()) {
				attachmentsJSONArray.add(attachment.toJSONObject());
			}
			o.put("attachments", attachmentsJSONArray);
		}
		return o;
	}
	
	
	@Override
	public String toJSONString() {
		return toJSONObject().toJSONString();
	}
	
	
	/**
	 * Parses an identity evidence from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return A {@link DocumentEvidence}, {@link IDDocumentEvidence},
	 *         {@link ElectronicRecordEvidence}, {@link VouchEvidence},
	 *         {@link QESEvidence}, {@link ElectronicSignatureEvidence}, or
	 *         {@link UtilityBillEvidence} instance.
	 *
	 * @throws ParseException If parsing failed or the evidence type isn't
	 *                        supported.
	 */
	public static IdentityEvidence parse(final JSONObject jsonObject)
		throws ParseException {
		
		IdentityEvidenceType type = new IdentityEvidenceType(JSONObjectUtils.getNonBlankString(jsonObject, "type"));
		
		if (IdentityEvidenceType.DOCUMENT.equals(type)) {
			return DocumentEvidence.parse(jsonObject);
		} else if (IdentityEvidenceType.ID_DOCUMENT.equals(type)) {
			return IDDocumentEvidence.parse(jsonObject);
		} else if (IdentityEvidenceType.ELECTRONIC_RECORD.equals(type)) {
			return ElectronicRecordEvidence.parse(jsonObject);
		} else if (IdentityEvidenceType.VOUCH.equals(type)) {
			return VouchEvidence.parse(jsonObject);
		} else if (IdentityEvidenceType.ELECTRONIC_SIGNATURE.equals(type)) {
			return ElectronicSignatureEvidence.parse(jsonObject);
		} else if (IdentityEvidenceType.QES.equals(type)) {
			return QESEvidence.parse(jsonObject);
		} else if (IdentityEvidenceType.UTILITY_BILL.equals(type)) {
			return UtilityBillEvidence.parse(jsonObject);
		} else {
			throw new ParseException("Unsupported type: " + type);
		}
	}
	
	
	/**
	 * Ensures the {@code type} member of the specified JSON object matches
	 * the expected.
	 *
	 * @param expectedType The expected type. Must not be {@code null}.
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @throws ParseException If parsing failed or mismatch.
	 */
	protected static void ensureType(final IdentityEvidenceType expectedType, JSONObject jsonObject)
		throws ParseException {
		
		String parsedType = JSONObjectUtils.getNonBlankString(jsonObject, "type");
		
		if (! expectedType.getValue().equals(parsedType)) {
			throw new ParseException("The identity evidence type must be " + expectedType);
		}
	}
}
