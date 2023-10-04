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

package com.nimbusds.oauth2.sdk.cnf;


import java.util.Map;

import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Abstract confirmation.
 */
public abstract class AbstractConfirmation {
	
	
	
	/**
	 * Returns this confirmation as a JWT claim.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * "cnf" : { "x5t#S256" : "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2" }
	 * </pre>
	 *
	 * @return The JWT claim name / value.
	 */
	public abstract Map.Entry<String,JSONObject> toJWTClaim();
	
	
	
	/**
	 * Returns this X.509 certificate SHA-256 confirmation as a JSON
	 * object.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "cnf" : { "x5t#S256" : "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2" }
	 * }
	 * </pre>
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		
		JSONObject jsonObject = new JSONObject();
		Map.Entry<String, JSONObject> cnfClaim = toJWTClaim();
		jsonObject.put(cnfClaim.getKey(), cnfClaim.getValue());
		return jsonObject;
	}
	
	
	/**
	 * Merges this X.509 certificate SHA-256 confirmation into the
	 * specified JSON object. Any existing {@code cnf} JSON object values
	 * will be preserved.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "cnf" : { "x5t#S256" : "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2" }
	 * }
	 * </pre>
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 */
	public void mergeInto(final JSONObject jsonObject) {
		
		JSONObject cnf = new JSONObject();
		if (jsonObject.get("cnf") != null) {
			try {
				cnf = JSONObjectUtils.getJSONObject(jsonObject, "cnf");
			} catch (ParseException e) {
				// ignore
			}
		}
		Map.Entry<String, JSONObject> en = toJWTClaim();
		cnf.putAll(en.getValue());
		jsonObject.put("cnf", cnf);
	}
	
	
	/**
	 * Applies this confirmation to the specified JWT claims set.
	 *
	 * @param jwtClaimsSet The JWT claims set.
	 *
	 * @return The modified JWT claims set.
	 */
	public JWTClaimsSet applyTo(final JWTClaimsSet jwtClaimsSet) {
		
		Map.Entry<String, JSONObject> cnfClaim = toJWTClaim();
		
		return new JWTClaimsSet.Builder(jwtClaimsSet)
			.claim(cnfClaim.getKey(), cnfClaim.getValue())
			.build();
	}
	
	
	@Override
	public String toString() {
		return toJSONObject().toJSONString();
	}
	
	
	/**
	 * Parses a confirmation JSON object from the specified JWT claims set.
	 *
	 * @param jwtClaimsSet The JWT claims set.
	 *
	 * @return The confirmation JSON object, {@code null} if none.
	 */
	protected static JSONObject parseConfirmationJSONObject(final JWTClaimsSet jwtClaimsSet) {
		
		Map<String, Object> jsonObjectClaim;
		try {
			jsonObjectClaim = jwtClaimsSet.getJSONObjectClaim("cnf");
		} catch (java.text.ParseException e) {
			return null;
		}
		
		if (jsonObjectClaim == null) {
			return null;
		}
		
		return new JSONObject(jsonObjectClaim);
	}
}
