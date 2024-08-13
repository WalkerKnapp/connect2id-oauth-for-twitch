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


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import java.util.HashSet;
import java.util.Set;


/**
 * Refresh token.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749)
 * </ul>
 */
@Immutable
public final class RefreshToken extends Token {
	
	
	private static final long serialVersionUID = 1482806259791531877L;
	
	
	/**
	 * Creates a new refresh token with a randomly generated 256-bit 
	 * (32-byte) value, Base64URL-encoded.
	 */
	public RefreshToken() {
	
		this(32);
	}	


	/**
	 * Creates a new refresh token with a randomly generated value of the 
	 * specified length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	public RefreshToken(final int byteLength) {
	
		super(byteLength);
	}


	/**
	 * Creates a new refresh token with the specified value.
	 *
	 * @param value The refresh token value. Must not be {@code null} or 
	 *              empty string.
	 */
	public RefreshToken(final String value) {
	
		super(value);
	}


	@Override
	public Set<String> getParameterNames() {

		Set<String> paramNames = new HashSet<>(getCustomParameters().keySet());
		paramNames.add("refresh_token");
		return paramNames;
	}


	@Override
	public JSONObject toJSONObject() {

		JSONObject o = new JSONObject();
		o.putAll(getCustomParameters());
		o.put("refresh_token", getValue());
		return o;
	}


	/**
	 * Parses a refresh token from a JSON object access token response.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The refresh token, {@code null} if not found.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        refresh token.
	 */
	public static RefreshToken parse(final JSONObject jsonObject)
		throws ParseException {

		String value = JSONObjectUtils.getString(jsonObject, "refresh_token", null);
		
		if (value == null) return null;

		return new RefreshToken(value);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof RefreshToken &&
		       this.toString().equals(object.toString());
	}
}
