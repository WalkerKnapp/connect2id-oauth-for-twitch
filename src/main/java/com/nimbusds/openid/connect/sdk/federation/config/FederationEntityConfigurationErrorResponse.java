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


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * Federation entity configuration error response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 6.2.
 * </ul>
 */
public class FederationEntityConfigurationErrorResponse extends FederationEntityConfigurationResponse implements ErrorResponse {
	
	
	/**
	 * The error.
	 */
	private final ErrorObject error;
	
	
	/**
	 * Creates a new federation entity configuration error response.
	 *
	 * @param error The error. Must not be {@code null}.
	 */
	public FederationEntityConfigurationErrorResponse(final ErrorObject error) {
		if (error == null) {
			throw new IllegalArgumentException("The error must not be null");
		}
		this.error = error;
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
	 * Parses a federation entity configuration error response from the
	 * specified HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The federation entity configuration error response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a
	 *                        federation entity configuration error
	 *                        response.
	 */
	public static FederationEntityConfigurationErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCodeNotOK();
		
		ErrorObject errorObject;
		if (httpResponse.getEntityContentType() != null && ContentType.APPLICATION_JSON.matches(httpResponse.getEntityContentType())) {
			errorObject = ErrorObject.parse(httpResponse.getContentAsJSONObject());
		} else {
			errorObject = new ErrorObject(null);
		}
		
		errorObject = errorObject.setHTTPStatusCode(httpResponse.getStatusCode());
		
		return new FederationEntityConfigurationErrorResponse(errorObject);
	}
}
