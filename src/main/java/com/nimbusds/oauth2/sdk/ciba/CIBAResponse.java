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

package com.nimbusds.oauth2.sdk.ciba;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import net.minidev.json.JSONObject;

/**
 * CIBA response from an OpenID provider / OAuth 2.0 authorisation server
 * backend authentication endpoint.
 *
 * <p>Related specifications:
 *
 * <ul>
 *      <li>OpenID Connect CIBA Flow - Core 1.0
 * </ul>
 */
public abstract class CIBAResponse implements Response {

	
	/**
	 * Casts this response to a successful CIBA request acknowledgement.
	 *
	 * @return The CIBA request acknowledgement.
	 */
	public CIBARequestAcknowledgement toRequestAcknowledgement() {

		return (CIBARequestAcknowledgement) this;
	}
	

	/**
	 * Casts this response to a CIBA error response.
	 *
	 * @return The CIBA error response.
	 */
	public CIBAErrorResponse toErrorResponse() {

		return (CIBAErrorResponse) this;
	}
	

	/**
	 * Parses a CIBA response from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The CIBA response.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static CIBAResponse parse(final JSONObject jsonObject)
		throws ParseException {
		
		if (jsonObject.containsKey("auth_req_id")) {
			return CIBARequestAcknowledgement.parse(jsonObject);
		} else {
			return CIBAErrorResponse.parse(jsonObject);
		}
	}

	
	/**
	 * Parses a CIBA response from the specified HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The CIBA response.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static CIBAResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		if (httpResponse.getStatusCode() == HTTPResponse.SC_OK)
			return CIBARequestAcknowledgement.parse(httpResponse);
		else
			return CIBAErrorResponse.parse(httpResponse);
	}
}