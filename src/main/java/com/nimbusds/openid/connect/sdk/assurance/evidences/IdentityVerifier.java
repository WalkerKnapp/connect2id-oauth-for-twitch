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
import com.nimbusds.secevent.sdk.claims.TXN;


/**
 * Legal entity that performed an identity verification on behalf of an OpenID
 * provider.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
public class IdentityVerifier implements JSONAware {
	
	
	/**
	 * The organisation.
	 */
	private final Organization organization;
	
	
	/**
	 * Identifier for the identity verification transaction.
	 */
	private final TXN txn;
	
	
	/**
	 * Creates a new verifier.
	 *
	 * @param organization The organisation, {@code null} if not specified.
	 * @param txn          Identifier for the identity verification
	 *                     transaction, {@code null} if not specified.
	 */
	public IdentityVerifier(final Organization organization, final TXN txn) {
		this.organization = organization;
		this.txn = txn;
	}
	
	
	/**
	 * Creates a new verifier.
	 *
	 * @param organizationString The organisation string, {@code null} if
	 *                           not specified.
	 * @param txn                Identifier for the identity verification
	 *                           transaction, {@code null} if not
	 *                           specified.
	 */
	@Deprecated
	public IdentityVerifier(final String organizationString, final TXN txn) {
		this.organization = organizationString != null ? new Organization(organizationString) : null;
		this.txn = txn;
	}
	
	
	/**
	 * Returns the organisation.
	 *
	 * @return The organisation, {@code null} if not specified.
	 */
	public Organization getOrganizationEntity() {
		return organization;
	}
	
	
	/**
	 * Returns the organisation string.
	 *
	 * @return The organisation string, {@code null} if not specified.
	 */
	public String getOrganizationString() {
		return getOrganizationEntity() != null ? getOrganizationEntity().getValue() : null;
	}
	
	
	/**
	 * Returns the organisation string.
	 *
	 * @return The organisation string, {@code null} if not specified.
	 *
	 * @deprecated Use {@link #getOrganizationString()} instead.
	 */
	@Deprecated
	public String getOrganization() {
		// Deprecated to allow for strongly typed Organization in future
		return getOrganizationString();
	}
	
	
	/**
	 * Returns the identifier for the identity verification transaction.
	 *
	 * @return The identity verification transaction identifier,
	 *         {@code null} if not specified.
	 */
	public TXN getTXN() {
		return txn;
	}
	
	
	/**
	 * Returns a JSON object representation os this verifier.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		JSONObject o = new JSONObject();
		if (getOrganization() != null) {
			o.put("organization", getOrganizationEntity().getValue());
		}
		if (getTXN() != null) {
			o.put("txn", getTXN().getValue());
		}
		return o;
	}
	
	
	@Override
	public String toJSONString() {
		return toJSONObject().toJSONString();
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof IdentityVerifier)) return false;
		IdentityVerifier verifier = (IdentityVerifier) o;
		return Objects.equals(getOrganizationEntity(), verifier.getOrganizationEntity()) && Objects.equals(getTXN(), verifier.getTXN());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(getOrganizationEntity(), getTXN());
	}
	
	
	/**
	 * Parses a verifier from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The verifier.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static IdentityVerifier parse(final JSONObject jsonObject)
		throws ParseException {
		
		Organization org = null;
		if (jsonObject.get("organization") != null) {
			org = new Organization(JSONObjectUtils.getString(jsonObject, "organization"));
		}
		
		TXN txn = null;
		if (jsonObject.get("txn") != null) {
			txn = new TXN(JSONObjectUtils.getString(jsonObject, "txn"));
		}
		
		return new IdentityVerifier(org, txn);
	}
}
