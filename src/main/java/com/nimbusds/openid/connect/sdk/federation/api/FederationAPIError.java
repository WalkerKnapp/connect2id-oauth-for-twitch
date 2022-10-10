/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.federation.api;


import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * Federation API error.
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 7.5.
 * </ul>
 */
@Immutable
public class FederationAPIError extends ErrorObject {
	
	
	private static final long serialVersionUID = 2116693118039606386L;
	
	
	/**
	 * Creates a new federation API error.
	 *
	 * @param code        The error code, {@code null} if not specified.
	 * @param description The error description, {@code null} if not
	 *                    specified.
	 */
	public FederationAPIError(final String code, final String description) {
		this(code, description, 0);
	}
	
	
	/**
	 * Creates a new federation API error.
	 *
	 * @param code           The error code, {@code null} if not specified.
	 * @param description    The error description, {@code null} if not
	 *                       specified.
	 * @param httpStatusCode The HTTP status code, zero if not specified.
	 */
	public FederationAPIError(final String code,
				  final String description,
				  final int httpStatusCode) {
		super(code, description, httpStatusCode);
	}
	
	
	/**
	 * Returns a copy of this federation API error with the specified HTTP
	 * status code.
	 *
	 * @param httpStatusCode The HTTP status code, zero if not specified.
	 *
	 * @return The new federation API error.
	 */
	public FederationAPIError withStatusCode(final int httpStatusCode) {
		return new FederationAPIError(getCode(), getDescription(), httpStatusCode);
	}
	
	
	/**
	 * Parses a federation API error object from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The federation API error object.
	 */
	public static FederationAPIError parse(final JSONObject jsonObject) {
		ErrorObject errorObject = ErrorObject.parse(jsonObject);
		return new FederationAPIError(errorObject.getCode(), errorObject.getDescription());
	}
	
	
	/**
	 * Parses a federation API error object from the specified HTTP
	 * response.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be
	 *                     {@code null}.
	 *
	 * @return The federation API error object.
	 */
	public static FederationAPIError parse(final HTTPResponse httpResponse) {
		JSONObject jsonObject;
		try {
			jsonObject = httpResponse.getContentAsJSONObject();
		} catch (ParseException e) {
			jsonObject = new JSONObject();
		}
		return FederationAPIError.parse(jsonObject).withStatusCode(httpResponse.getStatusCode());
	}
}
