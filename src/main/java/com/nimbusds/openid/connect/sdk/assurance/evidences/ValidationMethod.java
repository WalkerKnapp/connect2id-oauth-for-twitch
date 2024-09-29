/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.assurance.Policy;
import com.nimbusds.openid.connect.sdk.assurance.Procedure;
import com.nimbusds.openid.connect.sdk.assurance.Status;


/**
 * Validation method establishing the authenticity of an evidence, such as a
 * document, electronic record, vouch, utility bill or electronic signature.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
@Immutable
public final class ValidationMethod extends CommonMethodAttributes {
	
	
	/**
	 * The type.
	 */
	private final ValidationMethodType type;
	
	
	/**
	 * Creates a new validation method.
	 *
	 * @param type      The type. Must not be {@code null}.
	 * @param policy    The policy, {@code null} if not specified.
	 * @param procedure The procedure, {@code null} if not specified.
	 * @param status    The status, {@code null} if not specified.
	 */
	public ValidationMethod(final ValidationMethodType type,
				final Policy policy,
				final Procedure procedure,
				final Status status) {
		
		super(policy, procedure, status);
		
		Objects.requireNonNull(type);
		this.type = type;
	}
	
	
	/**
	 * Returns the type of this validation method.
	 *
	 * @return The type.
	 */
	public ValidationMethodType getType() {
		return type;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof ValidationMethod)) return false;
		ValidationMethod that = (ValidationMethod) o;
		return getType().equals(that.getType())
			&& Objects.equals(getPolicy(), that.getPolicy())
			&& Objects.equals(getProcedure(), that.getProcedure())
			&& Objects.equals(getStatus(), that.getStatus());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(getType(), getPolicy(), getProcedure(), getStatus());
	}
	
	
	/**
	 * Returns a JSON object representation of this validation method.
	 *
	 * @return The JSON object.
	 */
	@Override
	public JSONObject toJSONObject() {
		JSONObject o = super.toJSONObject();
		o.put("type", getType().getValue());
		return o;
	}
	
	
	/**
	 * Parses a validation method from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The validation method.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ValidationMethod parse(final JSONObject jsonObject)
		throws ParseException {
		
		try {
			ValidationMethodType type = new ValidationMethodType(JSONObjectUtils.getNonBlankString(jsonObject, "type"));
			Policy policy = null;
			if (jsonObject.get("policy") != null) {
				policy = new Policy(JSONObjectUtils.getNonBlankString(jsonObject, "policy"));
			}
			Procedure procedure = null;
			if (jsonObject.get("procedure") != null) {
				procedure = new Procedure(JSONObjectUtils.getNonBlankString(jsonObject, "procedure"));
			}
			Status status = null;
			if (jsonObject.get("status") != null) {
				status = new Status(JSONObjectUtils.getNonBlankString(jsonObject, "status"));
			}
			return new ValidationMethod(type, policy, procedure, status);
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage(), e);
		}
	}
}
