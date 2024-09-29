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

package com.nimbusds.openid.connect.sdk.assurance.request;


import java.util.List;
import java.util.Objects;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.assurance.IdentityTrustFramework;


/**
 * Minimal verification spec. Allows setting of a preferred trust framework for
 * the identity verification. Can be extended with additional setters.
 *
 * <p>Default verification example:
 *
 * <pre>
 * {
 *   "trust_framework": null
 * }
 * </pre>
 *
 * <p>Verification example with preferred trust framework:
 *
 * <pre>
 * {
 *   "trust_framework": {
 *      "value" : "eidas"
 *   }
 * }
 * </pre>
 *
 * <p>Verification example with list of two preferred trust frameworks:
 *
 * <pre>
 * {
 *   "trust_framework": {
 *      "values" : [ "eidas", "de_aml" ]
 *   }
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
@Immutable
public class MinimalVerificationSpec implements VerificationSpec {
	
	
	/**
	 * The underlying JSON object.
	 */
	protected final JSONObject jsonObject;
	
	
	/**
	 * Creates a new minimal verification spec with the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 */
	protected MinimalVerificationSpec(final JSONObject jsonObject) {
		Objects.requireNonNull(jsonObject);
		this.jsonObject = jsonObject;
	}
	
	
	/**
	 * Creates a new minimal verification spec.
	 */
	public MinimalVerificationSpec() {
		this(new JSONObject());
		jsonObject.put("trust_framework", null);
	}
	
	
	/**
	 * Creates a new minimal verification spec with a preferred trust
	 * framework.
	 *
	 * @param trustFramework The trust framework, {@code null} if not
	 *                       specified.
	 */
	public MinimalVerificationSpec(final IdentityTrustFramework trustFramework) {
		this();
		if (trustFramework != null) {
			JSONObject tfSpec = new JSONObject();
			tfSpec.put("value", trustFramework.getValue());
			jsonObject.put("trust_framework", tfSpec);
		}
	}
	
	
	/**
	 * Creates a new minimal verification spec with a list of preferred
	 * trust frameworks.
	 *
	 * @param trustFrameworks The trust frameworks, {@code null} if not
	 *                        specified.
	 */
	public MinimalVerificationSpec(final List<IdentityTrustFramework> trustFrameworks) {
		this();
		if (CollectionUtils.isNotEmpty(trustFrameworks)) {
			JSONObject tfSpec = new JSONObject();
			JSONArray tfValues = new JSONArray();
			for (IdentityTrustFramework tf: trustFrameworks) {
				if (tf != null) {
					tfValues.add(tf.getValue());
				}
			}
			tfSpec.put("values", tfValues);
			jsonObject.put("trust_framework", tfSpec);
		}
	}
	
	
	@Override
	public JSONObject toJSONObject() {
		
		JSONObject o = new JSONObject();
		o.putAll(jsonObject);
		return o;
	}
	
	
	/**
	 * Parses a verification spec from the specified JSON object
	 * representation.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The verification spec.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static MinimalVerificationSpec parse(final JSONObject jsonObject)
		throws ParseException {
		
		// Verify the trust_framework element
		if (! jsonObject.containsKey("trust_framework")) {
			throw new ParseException("Missing required trust_framework key");
		}
		
		if (jsonObject.get("trust_framework") != null) {
			
			JSONObject tfSpec = JSONObjectUtils.getJSONObject(jsonObject, "trust_framework");
			
			try {
				validateTrustFrameworkSpec(tfSpec);
			} catch (ParseException e) {
				throw new ParseException("Invalid trust_framework spec: " + e.getMessage(), e);
			}
		}
		
		return new MinimalVerificationSpec(jsonObject);
	}
	
	
	/**
	 * Validates the {@code trust_framework} JSON object.
	 *
	 * @param tfSpec The JSON object. Must be {@code null}.
	 *
	 * @throws ParseException If the JSON object is illegal.
	 */
	private static void validateTrustFrameworkSpec(final JSONObject tfSpec)
		throws ParseException {
		
		String value = null;
		if (tfSpec.containsKey("value")) {
			value = JSONObjectUtils.getNonBlankString(tfSpec, "value");
		}
		
		List<String> values = null;
		if (tfSpec.containsKey("values")) {
			values = JSONObjectUtils.getStringList(tfSpec, "values");
			if (values.isEmpty()) {
				// If set values must not be empty
				throw new ParseException("The values JSON array must not be empty");
			}
		}
		
		if (value != null && values != null) {
			// Value or values must not be set together
			throw new ParseException("Value and values must not be set together");
		}
	}
}
