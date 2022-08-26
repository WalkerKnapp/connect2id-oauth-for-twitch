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

package com.nimbusds.oauth2.sdk.util;


import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;


/**
 * JSON Web Token (JWT) claims set utilities.
 */
public final class JWTClaimsSetUtils {
	
	
	/**
	 * Creates a JWT claims set from the specified multi-valued parameters.
	 * Single-valued parameters are mapped to a string claim. Multi-valued
	 * parameters are mapped to a string array claim.
	 *
	 * @param params The multi-valued parameters. Must not be {@code null}.
	 *
	 * @return The JWT claims set.
	 */
	public static JWTClaimsSet toJWTClaimsSet(final Map<String, List<String>> params) {
		
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
		
		for (Map.Entry<String, List<String>> en: params.entrySet()) {
			
			if (en.getValue().size() == 1) {
				
				String singleValue = en.getValue().get(0);
				builder.claim(en.getKey(), singleValue);
				
			} else if (en.getValue().size() > 0) {
				
				List<String> multiValue = en.getValue();
				builder.claim(en.getKey(), multiValue);
			}
		}
		
		return builder.build();
	}
	
	
	/**
	 * Creates a multi-valued string parameters map from the specified JWT
	 * claims set. {@link JWTClaimsSet#getRegisteredNames() registered JWT
	 * claims} and {@code null} valued claims are not included in the
	 * returned parameters.
	 *
	 * @param claimsSet The JWT claims set. Must not be {@code null}.
	 *
	 * @return The string parameters map.
	 */
	public static Map<String,List<String>> toMultiValuedParameters(final JWTClaimsSet claimsSet) {
		
		Map<String,List<String>> params = new HashMap<>();
		
		for (Map.Entry<String,Object> entry: claimsSet.toJSONObject().entrySet()) {
			
			if (JWTClaimsSet.getRegisteredNames().contains(entry.getKey()))
				continue; // skip sub, aud, iat, etc...
			
			if (entry.getValue() == null)
				continue; // skip null value
			
			String value;
			if (entry.getValue() instanceof Map) {
				value = JSONObjectUtils.toJSONString((Map<String, ?>) entry.getValue());
			} else {
				value = entry.getValue().toString();
			}
			
			params.put(entry.getKey(), Collections.singletonList(value));
		}
		
		return params;
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private JWTClaimsSetUtils() {}
}
