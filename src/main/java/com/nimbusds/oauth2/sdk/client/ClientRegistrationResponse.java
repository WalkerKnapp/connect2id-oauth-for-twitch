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

package com.nimbusds.oauth2.sdk.client;


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * The base abstract for client registration responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)
 * </ul>
 */
public abstract class ClientRegistrationResponse implements Response {
	
	
	/**
	 * Casts this response to a client information response.
	 *
	 * @return The client information response.
	 */
	public ClientInformationResponse toSuccessResponse() {
		
		return (ClientInformationResponse) this;
	}
	
	
	/**
	 * Casts this response to a client registration error response.
	 *
	 * @return The client registration error response.
	 */
	public ClientRegistrationErrorResponse toErrorResponse() {
		
		return (ClientRegistrationErrorResponse) this;
	}


	/**
	 * Parses a client registration response from the specified HTTP 
	 * response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The client registration response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a
	 *                        client registration response.
	 */
	public static ClientRegistrationResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		if (httpResponse.getStatusCode() == HTTPResponse.SC_CREATED ||
		    httpResponse.getStatusCode() == HTTPResponse.SC_OK) {

			return ClientInformationResponse.parse(httpResponse);

		} else {

			return ClientRegistrationErrorResponse.parse(httpResponse);
		}
	}
}