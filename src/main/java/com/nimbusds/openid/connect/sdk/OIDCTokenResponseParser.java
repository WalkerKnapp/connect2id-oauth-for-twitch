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

package com.nimbusds.openid.connect.sdk;


import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * Parser of OpenID Connect token endpoint response messages.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 * </ul>
 */
public class OIDCTokenResponseParser { 


	/**
	 * Parses an OpenID Connect token response or token error response from
	 * the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The OpenID Connect token response or token error response.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        token response.
	 */
	public static TokenResponse parse(final JSONObject jsonObject)
		throws ParseException {

		if (jsonObject.containsKey("error"))
			return TokenErrorResponse.parse(jsonObject);
		else
			return OIDCTokenResponse.parse(jsonObject);
	}


	/**
	 * Parses an OpenID Connect token response or token error response from
	 * the specified HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The OpenID Connect token response or token error response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a
	 *                        token response.
	 */
	public static TokenResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		if (httpResponse.getStatusCode() == HTTPResponse.SC_OK)
			return OIDCTokenResponse.parse(httpResponse);
		else
			return TokenErrorResponse.parse(httpResponse);
	}


	/**
	 * Prevents public instantiation.
	 */
	private OIDCTokenResponseParser() { }
}
