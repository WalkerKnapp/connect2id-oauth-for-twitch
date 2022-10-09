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

package com.nimbusds.openid.connect.sdk.federation.config;


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * Federation entity configuration response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 6.2.
 * </ul>
 */
public abstract class FederationEntityConfigurationResponse implements Response {
	
	
	/**
	 * Casts this response to a federation entity configuration success
	 * response.
	 *
	 * @return The federation entity configuration success response.
	 */
	public FederationEntityConfigurationSuccessResponse toSuccessResponse() {
		
		return (FederationEntityConfigurationSuccessResponse) this;
	}
	
	
	/**
	 * Casts this response to a federation entity configuration error
	 * response.
	 *
	 * @return The federation entity configuration error response.
	 */
	public FederationEntityConfigurationErrorResponse toErrorResponse() {
		
		return (FederationEntityConfigurationErrorResponse) this;
	}
	
	
	/**
	 * Parses a federation entity configuration response from the specified
	 * HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The federation entity configuration success or error
	 *         response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a
	 *                        federation entity configuration response.
	 */
	public static FederationEntityConfigurationResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		if (httpResponse.getStatusCode() == HTTPResponse.SC_OK) {
			return FederationEntityConfigurationSuccessResponse.parse(httpResponse);
		} else {
			return FederationEntityConfigurationErrorResponse.parse(httpResponse);
		}
	}
}
