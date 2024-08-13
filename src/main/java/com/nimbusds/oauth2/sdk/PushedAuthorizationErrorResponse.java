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


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import net.jcip.annotations.Immutable;

import java.util.Objects;


/**
 * Pushed authorisation error response.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 400 Bad Request
 * Content-Type: application/json
 * Cache-Control: no-cache, no-store
 *
 * {
 *  "error ": "invalid_request",
 *  "error_description" : "The redirect_uri is not valid for the given client"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Pushed Authorization Requests (RFC 9126)
 * </ul>
 */
@Immutable
public class PushedAuthorizationErrorResponse extends PushedAuthorizationResponse implements ErrorResponse {
	
	
	/**
	 * The error.
	 */
	private final ErrorObject error;
	
	
	/**
	 * Creates a new pushed authorisation error response.
	 *
	 * @param error The error. Must not be {@code null}.
	 */
	public PushedAuthorizationErrorResponse(final ErrorObject error) {
		this.error = Objects.requireNonNull(error);
	}
	
	
	@Override
	public boolean indicatesSuccess() {
		return false;
	}
	
	
	@Override
	public ErrorObject getErrorObject() {
		return error;
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse() {
		return getErrorObject().toHTTPResponse();
	}
	
	
	/**
	 * Parses a pushed authorisation error response from the specified HTTP
	 * response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The pushed authorisation error response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a
	 *                        pushed authorisation error response.
	 */
	public static PushedAuthorizationErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		int statusCode = httpResponse.getStatusCode();
		
		if (statusCode == HTTPResponse.SC_CREATED || statusCode == HTTPResponse.SC_OK) {
			throw new ParseException("The HTTP status code must be other than 201 and 200");
		}
		
		ErrorObject errorObject;
		if (httpResponse.getEntityContentType() != null && ContentType.APPLICATION_JSON.matches(httpResponse.getEntityContentType())) {
			errorObject = ErrorObject.parse(httpResponse.getContentAsJSONObject());
		} else {
			errorObject = new ErrorObject(null);
		}
		
		return new PushedAuthorizationErrorResponse(errorObject.setHTTPStatusCode(statusCode));
	}
}
