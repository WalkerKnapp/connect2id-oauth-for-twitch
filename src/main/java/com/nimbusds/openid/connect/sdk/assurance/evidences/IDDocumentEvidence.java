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


/**
 * Identity document used as identity evidence.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 *
 * @deprecated Use {@link DocumentEvidence} instead.
 */
@Deprecated
public class IDDocumentEvidence extends IdentityEvidence {
	
	
	/**
	 * The document verification method.
	 */
	private final IdentityVerificationMethod method;
	
	
	/**
	 * The document verification timestamp.
	 */
	private final DateWithTimeZoneOffset time;
	
	
	/**
	 * Optional verifier if not the OpenID provider itself.
	 */
	private final IdentityVerifier verifier;
	
	
	/**
	 * The identity document description.
	 */
	private final IDDocumentDescription idDocument;
	
	
	/**
	 * Creates a new identity document evidence.
	 *
	 * @param method     The document verification method, {@code null} if
	 *                   not specified.
	 * @param verifier   Optional verifier if not the OpenID provider
	 *                   itself, {@code null} if none.
	 * @param time        The document verification timestamp, {@code null}
	 *                   if not specified.
	 * @param idDocument The identity document description, {@code null} if
	 *                   not specified.
	 */
	public IDDocumentEvidence(final IdentityVerificationMethod method,
				  final IdentityVerifier verifier,
				  final DateWithTimeZoneOffset time,
				  final IDDocumentDescription idDocument) {
		
		super(IdentityEvidenceType.ID_DOCUMENT, null);
		
		this.method = method;
		this.time = time;
		this.verifier = verifier;
		this.idDocument = idDocument;
	}
	
	
	/**
	 * Returns the document verification method.
	 *
	 * @return The document verification method, {@code null} if not
	 *         specified.
	 */
	public IdentityVerificationMethod getVerificationMethod() {
		return method;
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
	 * Returns the optional verifier if not the OpenID provider itself.
	 *
	 * @return The optional verifier if not the OpenID provider itself,
	 *         {@code null} if none.
	 */
	public IdentityVerifier getVerifier() {
		return verifier;
	}
	
	
	/**
	 * Returns the identity document description.
	 *
	 * @return The identity document description, {@code null} if not
	 *         specified.
	 */
	public IDDocumentDescription getIdentityDocument() {
		return idDocument;
	}
	
	
	@Override
	public JSONObject toJSONObject() {
		JSONObject o = super.toJSONObject();
		if (getVerificationMethod() != null) {
			o.put("method", getVerificationMethod().getValue());
		}
		if (getVerificationTime() != null) {
			o.put("time", getVerificationTime().toISO8601String());
		}
		if (getVerifier() != null) {
			o.put("verifier", getVerifier().toJSONObject());
		}
		if (getIdentityDocument() != null) {
			o.put("document", getIdentityDocument().toJSONObject());
		}
		return o;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof IDDocumentEvidence)) return false;
		IDDocumentEvidence that = (IDDocumentEvidence) o;
		return Objects.equals(getVerificationMethod(), that.getVerificationMethod()) &&
			Objects.equals(getVerificationTime(), that.getVerificationTime()) &&
			Objects.equals(getVerifier(), that.getVerifier()) &&
			Objects.equals(getIdentityDocument(), that.getIdentityDocument());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(method, time, getVerifier(), idDocument);
	}
	
	
	/**
	 * Parses an identity document used as identity evidence from the
	 * specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The identity document used as identity evidence.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static IDDocumentEvidence parse(final JSONObject jsonObject)
		throws ParseException {
		
		ensureType(IdentityEvidenceType.ID_DOCUMENT, jsonObject);
		
		IdentityVerificationMethod method = null;
		if (jsonObject.get("method") != null) {
			method = new IdentityVerificationMethod(JSONObjectUtils.getNonBlankString(jsonObject, "method"));
		}
		
		DateWithTimeZoneOffset dtz = null;
		if (jsonObject.get("time") != null) {
			dtz = DateWithTimeZoneOffset.parseISO8601String(JSONObjectUtils.getNonBlankString(jsonObject, "time"));
		}
		
		IdentityVerifier verifier = null;
		if (jsonObject.get("verifier") != null) {
			verifier = IdentityVerifier.parse(JSONObjectUtils.getJSONObject(jsonObject, "verifier"));
		}
		
		IDDocumentDescription idDocument = null;
		if (jsonObject.get("document") != null) {
			idDocument = IDDocumentDescription.parse(JSONObjectUtils.getJSONObject(jsonObject, "document"));
		}
		
		return new IDDocumentEvidence(method, verifier, dtz, idDocument);
	}
}
