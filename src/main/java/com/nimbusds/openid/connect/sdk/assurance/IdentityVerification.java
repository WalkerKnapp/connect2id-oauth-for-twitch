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

package com.nimbusds.openid.connect.sdk.assurance;


import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.date.DateWithTimeZoneOffset;
import com.nimbusds.openid.connect.sdk.assurance.evidences.IdentityEvidence;


/**
 * Identity verification.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
@Immutable
public final class IdentityVerification implements JSONAware {
	
	
	/**
	 * The trust framework.
	 */
	private final IdentityTrustFramework trustFramework;
	
	
	/**
	 * The assurance level if required by the trust framework.
	 */
	private final IdentityAssuranceLevel assuranceLevel;
	
	
	/**
	 * The assurance process if required by the trust framework.
	 */
	private final IdentityAssuranceProcess assuranceProcess;
	
	
	/**
	 * The verification timestamp if required by the trust framework.
	 */
	private final DateWithTimeZoneOffset time;
	
	
	/**
	 * The verification process reference if required by the trust
	 * framework.
	 */
	private final VerificationProcess verificationProcess;
	
	
	/**
	 * The identity evidences.
	 */
	private final List<IdentityEvidence> evidence;
	
	
	/**
	 * Creates a new identity verification with a single evidence.
	 *
	 * @param trustFramework      The trust framework. Must not be
	 *                            {@code null}.
	 * @param time                The verification timestamp if required by
	 *                            the trust framework, {@code null} if not
	 *                            required.
	 * @param verificationProcess The verification process reference if
	 *                            required by the trust framework,
	 *                            {@code null} if not required.
	 * @param evidence            The identity evidence, {@code null} if
	 *                            not specified.
	 */
	@Deprecated
	public IdentityVerification(final IdentityTrustFramework trustFramework,
				    final DateWithTimeZoneOffset time,
				    final VerificationProcess verificationProcess,
				    final IdentityEvidence evidence) {
		
		this(trustFramework, time, verificationProcess, Collections.singletonList(evidence));
	}
	
	
	/**
	 * Creates a new identity verification with a single evidence.
	 *
	 * @param trustFramework      The trust framework. Must not be
	 *                            {@code null}.
	 * @param assuranceLevel      The assurance level if required by the
	 *                            trust framework, {@code null} if not
	 *                            required.
	 * @param assuranceProcess    The assurance process if required by the
	 *                            trust framework, {@code null} if not
	 *                            required.
	 * @param time                The verification timestamp if required by
	 *                            the trust framework, {@code null} if not
	 *                            required.
	 * @param verificationProcess The verification process reference if
	 *                            required by the trust framework,
	 *                            {@code null} if not required.
	 * @param evidence            The identity evidence, {@code null} if
	 *                            not specified.
	 */
	public IdentityVerification(final IdentityTrustFramework trustFramework,
				    final IdentityAssuranceLevel assuranceLevel,
				    final IdentityAssuranceProcess assuranceProcess,
				    final DateWithTimeZoneOffset time,
				    final VerificationProcess verificationProcess,
				    final IdentityEvidence evidence) {
		
		this(trustFramework, assuranceLevel, assuranceProcess, time, verificationProcess, Collections.singletonList(evidence));
	}
	
	
	/**
	 * Creates a new identity verification with multiple evidences.
	 *
	 * @param trustFramework      The trust framework. Must not be
	 *                            {@code null}.
	 * @param time                The verification timestamp if required by
	 *                            the trust framework, {@code null} if not
	 *                            required.
	 * @param verificationProcess The verification process reference if
	 *                            required by the trust framework,
	 *                            {@code null} if not required.
	 * @param evidence            The identity evidences, {@code null} if
	 *                            not specified.
	 */
	@Deprecated
	public IdentityVerification(final IdentityTrustFramework trustFramework,
				    final DateWithTimeZoneOffset time,
				    final VerificationProcess verificationProcess,
				    final List<IdentityEvidence> evidence) {
		
		this(trustFramework, null, null, time, verificationProcess, evidence);
	}
	
	
	/**
	 * Creates a new identity verification with multiple evidences.
	 *
	 * @param trustFramework      The trust framework. Must not be
	 *                            {@code null}.
	 * @param assuranceLevel      The assurance level if required by the
	 *                            trust framework, {@code null} if not
	 *                            required.
	 * @param assuranceProcess    The assurance process if required by the
	 *                            trust framework, {@code null} if not
	 *                            required.
	 * @param time                The verification timestamp if required by
	 *                            the trust framework, {@code null} if not
	 *                            required.
	 * @param verificationProcess The verification process reference if
	 *                            required by the trust framework,
	 *                            {@code null} if not required.
	 * @param evidence            The identity evidences, {@code null} if
	 *                            not specified.
	 */
	public IdentityVerification(final IdentityTrustFramework trustFramework,
				    final IdentityAssuranceLevel assuranceLevel,
				    final IdentityAssuranceProcess assuranceProcess,
				    final DateWithTimeZoneOffset time,
				    final VerificationProcess verificationProcess,
				    final List<IdentityEvidence> evidence) {
		
		if (trustFramework == null) {
			throw new IllegalArgumentException("The trust framework must not be null");
		}
		this.trustFramework = trustFramework;
		
		this.assuranceLevel = assuranceLevel;
		this.assuranceProcess = assuranceProcess;
		this.time = time;
		this.verificationProcess = verificationProcess;
		this.evidence = evidence;
	}
	
	
	/**
	 * Returns the trust framework.
	 *
	 * @return The trust framework.
	 */
	public IdentityTrustFramework getTrustFramework() {
		return trustFramework;
	}
	
	
	/**
	 * Returns the assurance level.
	 *
	 * @return The assurance level if required by the trust framework,
	 *         {@code null} if not specified.
	 */
	public IdentityAssuranceLevel getAssuranceLevel() {
		return assuranceLevel;
	}
	
	
	/**
	 * Returns the assurance process.
	 *
	 * @return The assurance process if required by the trust framework,
	 *         {@code null} if not specified.
	 */
	public IdentityAssuranceProcess getAssuranceProcess() {
		return assuranceProcess;
	}
	
	
	/**
	 * Returns the verification timestamp.
	 *
	 * @return The verification timestamp if required by the trust
	 *         framework, {@code null} if not specified.
	 */
	public DateWithTimeZoneOffset getVerificationTime() {
		return time;
	}
	
	
	/**
	 * Returns the verification process reference.
	 *
	 * @return The verification process reference if required by the trust
	 *         framework, {@code null} if not specified.
	 */
	public VerificationProcess getVerificationProcess() {
		return verificationProcess;
	}
	
	
	/**
	 * Returns the identity evidence.
	 *
	 * @return The identity evidence, {@code null} or empty if not
	 *         specified.
	 */
	public List<IdentityEvidence> getEvidence() {
		return evidence;
	}
	
	
	/**
	 * Returns a JSON object representation of this identity verification.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		
		JSONObject o = new JSONObject();
		o.put("trust_framework", getTrustFramework().getValue());
		
		if (getAssuranceLevel() != null) {
			o.put("assurance_level", getAssuranceLevel().getValue());
		}
		
		if (getAssuranceProcess() != null) {
			o.put("assurance_process", getAssuranceProcess().toJSONObject());
		}
		
		if (getVerificationTime() != null) {
			o.put("time", getVerificationTime().toISO8601String());
		}
		
		if (getVerificationProcess() != null) {
			o.put("verification_process", getVerificationProcess().getValue());
		}
		
		if (getEvidence() != null) {
			JSONArray evidenceArray = new JSONArray();
			for (IdentityEvidence ev : getEvidence()) {
				if (ev != null) {
					evidenceArray.add(ev.toJSONObject());
				}
			}
			if (! evidenceArray.isEmpty()) {
				o.put("evidence", evidenceArray);
			}
		}
		
		return o;
	}
	
	
	@Override
	public String toJSONString() {
		
		return toJSONObject().toJSONString();
	}
	
	
	/**
	 * Parses an identity verification from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The identity verification.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static IdentityVerification parse(final JSONObject jsonObject)
		throws ParseException {
		
		IdentityTrustFramework trustFramework = new IdentityTrustFramework(JSONObjectUtils.getNonBlankString(jsonObject, "trust_framework"));
		
		IdentityAssuranceLevel assuranceLevel = null;
		String stringValue = JSONObjectUtils.getString(jsonObject, "assurance_level", null);
		if (StringUtils.isNotBlank(stringValue)) {
			assuranceLevel = new IdentityAssuranceLevel(stringValue);
		}
		
		IdentityAssuranceProcess assuranceProcess = null;
		JSONObject jsonObjectValue = JSONObjectUtils.getJSONObject(jsonObject, "assurance_process", null);
		if (jsonObjectValue != null) {
			assuranceProcess = IdentityAssuranceProcess.parse(jsonObjectValue);
		}
		
		DateWithTimeZoneOffset time = null;
		stringValue = JSONObjectUtils.getString(jsonObject, "time", null);
		if (StringUtils.isNotBlank(stringValue)) {
			time = DateWithTimeZoneOffset.parseISO8601String(stringValue);
		}
		
		VerificationProcess verificationProcess = null;
		stringValue = JSONObjectUtils.getString(jsonObject, "verification_process", null);
		if (StringUtils.isNotBlank(stringValue)) {
			verificationProcess = new VerificationProcess(stringValue);
		}
		
		List<IdentityEvidence> evidence = null;
		if (jsonObject.get("evidence") != null) {
			evidence = new LinkedList<>();
			JSONArray jsonArray = JSONObjectUtils.getJSONArray(jsonObject, "evidence");
			for (JSONObject item : JSONArrayUtils.toJSONObjectList(jsonArray)) {
				evidence.add(IdentityEvidence.parse(item));
			}
		}
		
		return new IdentityVerification(trustFramework, assuranceLevel, assuranceProcess, time, verificationProcess, evidence);
	}
}
