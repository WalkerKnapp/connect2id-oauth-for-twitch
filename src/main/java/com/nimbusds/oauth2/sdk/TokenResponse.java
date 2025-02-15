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

package com.nimbusds.oauth2.sdk;


import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import net.minidev.json.JSONObject;


/**
 * Token endpoint response. This is the base abstract class for access token
 * (success) and token error responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749)
 * </ul>
 */
public abstract class TokenResponse implements Response {
	
	
	/**
	 * Casts this response to an access token response.
	 *
	 * @return The access token response.
	 */
	public AccessTokenResponse toSuccessResponse() {
		
		return (AccessTokenResponse) this;
	}
	
	
	/**
	 * Casts this response to a token error response.
	 *
	 * @return The token error response.
	 */
	public TokenErrorResponse toErrorResponse() {
		
		return (TokenErrorResponse) this;
	}


	/**
	 * Parses a token response from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The access token or token error response.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        token response.
	 */
	public static TokenResponse parse(final JSONObject jsonObject)
		throws ParseException{

		if (jsonObject.containsKey("access_token"))
			return AccessTokenResponse.parse(jsonObject);
		else
			return TokenErrorResponse.parse(jsonObject);
	}


	/**
	 * Parses a token response from the specified HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The access token or token error response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a 
	 *                        token response.
	 */
	public static TokenResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		if (httpResponse.getStatusCode() ==  HTTPResponse.SC_OK)
			return AccessTokenResponse.parse(httpResponse);
		else
			return TokenErrorResponse.parse(httpResponse);
	}
}