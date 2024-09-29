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

package com.nimbusds.oauth2.sdk.token;


import com.nimbusds.oauth2.sdk.id.Identifier;
import net.minidev.json.JSONObject;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;


/**
 * The base abstract class for access, refresh and other tokens. Concrete
 * extending classes should be immutable.
 * 
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749)
 * </ul>
 */
public abstract class Token extends Identifier {
	
	
	private static final long serialVersionUID = 1797025947209047077L;


	/**
	 * Additional custom parameters.
	 */
	private Map<String, Object> customParams;
	
	
	/**
	 * Creates a new token with the specified value.
	 *
	 * @param value The token value. Must not be {@code null} or empty 
	 *              string.
	 */
	protected Token(final String value) {

		super(value);
	}


	/**
	 * Creates a new token with a randomly generated value of the specified 
	 * byte length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	protected Token(final int byteLength) {
	
		super(byteLength);
	}
	
	
	/**
	 * Creates a new token with a randomly generated 256-bit (32-byte) 
	 * value, Base64URL-encoded.
	 */
	protected Token() {
	
		super();
	}


	/**
	 * Returns the token parameter names included in the JSON object, as
	 * required for the composition of an access token response. See OAuth
	 * 2.0 (RFC 6749), section 5.1.
	 *
	 * @return The token parameter names.
	 */
	public abstract Set<String> getParameterNames();


	/**
	 * Returns the token parameters as a JSON object, as required for the
	 * composition of an access token response. See OAuth 2.0 (RFC 6749), 
	 * section 5.1.
	 *
	 * <p>Note that JSONObject implements {@literal Map&lt;String,Object&gt;}.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "access_token"      : "2YotnFZFEjr1zCsicMWpAA",
	 *   "token_type"        : "example",
	 *   "expires_in"        : 3600,
	 *   "example_parameter" : "example_value"
	 * }
	 * </pre>
	 *
	 * @return The token parameters as a JSON object.
	 */
	public abstract JSONObject toJSONObject();


	/**
	 * Returns the additional custom parameters.
	 *
	 * @return The custom parameters, empty map if none.
	 */
	public Map<String, Object> getCustomParameters() {

		if (customParams == null) {
			// Lazy init
			customParams = new HashMap<>();
		}

		return customParams;
	}
}
