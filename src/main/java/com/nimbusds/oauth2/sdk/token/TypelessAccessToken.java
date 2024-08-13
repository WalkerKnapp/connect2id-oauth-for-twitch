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


import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;


/**
 * Typeless access token, cannot be serialised. Intended to represent parsed
 * access tokens which type cannot be inferred.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749)
 * </ul>
 */
@Immutable
public class TypelessAccessToken extends AccessToken {
	
	
	private static final long serialVersionUID = 2520352130331160789L;
	
	
	/**
	 * Creates a new minimal typeless access token with the specified 
	 * value. The optional lifetime and scope are left undefined.
	 *
	 * @param value The access token value. Must not be {@code null} or
	 *              empty string.
	 */
	public TypelessAccessToken(final String value) {
	
		super(AccessTokenType.UNKNOWN, value);
	}


	/**
	 * Operation not supported.
	 * 
	 * @throws UnsupportedOperationException Serialisation is not 
	 *                                       supported.
	 */
	@Override
	public JSONObject toJSONObject() {

		throw new UnsupportedOperationException("Serialization not supported");
	}
	
	
	/**
	 * Operation not supported.
	 * 
	 * @throws UnsupportedOperationException Serialisation is not 
	 *                                       supported.
	 */
	@Override
	public String toAuthorizationHeader() {

		throw new UnsupportedOperationException("Serialization not supported");
	}
	
	
	@Override
	public boolean equals(final Object object) {
	
		return object instanceof AccessToken &&
		       this.toString().equals(object.toString());
	}
}
