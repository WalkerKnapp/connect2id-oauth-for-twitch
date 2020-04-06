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

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * Trust negotiation error response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, sections 6.2.2 and 6.4.
 * </ul>
 */
@Immutable
public class TrustNegotiationErrorResponse extends TrustNegotiationResponse {
	
	
	/**
	 * The federation API error.
	 */
	private final FederationAPIError error;
	
	
	/**
	 * Creates a new trust negotiation error response.
	 *
	 * @param error The federation API error. Must not be {@code null}.
	 */
	public TrustNegotiationErrorResponse(final FederationAPIError error) {
		if (error == null) {
			throw new IllegalArgumentException("The error object must not be null");
		}
		this.error = error;
	}
	
	
	/**
	 * Returns the federation API error.
	 *
	 * @return The federation API error.
	 */
	public FederationAPIError getErrorObject() {
		return error;
	}
	
	
	@Override
	public boolean indicatesSuccess() {
		return false;
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse() {
		return error.toHTTPResponse();
	}
	
	
	/**
	 * Parses a trust negotiation error response from the specified HTTP
	 * response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The trust negotiation error response.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static TrustNegotiationErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		httpResponse.ensureStatusCodeNotOK();
		return new TrustNegotiationErrorResponse(FederationAPIError.parse(httpResponse));
	}
}
