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


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * Trust mark status response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, sections 7.4.2 and 7.5.
 * </ul>
 */
public abstract class TrustMarkStatusResponse implements Response {
	
	
	/**
	 * Casts this response to a trust mark status success response.
	 *
	 * @return The trust mark status success response.
	 */
	public TrustMarkStatusSuccessResponse toSuccessResponse() {
		return (TrustMarkStatusSuccessResponse) this;
	}
	
	
	/**
	 * Casts this response to a trust mark status error response.
	 *
	 * @return The trust mark status error response.
	 */
	public TrustMarkStatusErrorResponse toErrorResponse() {
		return (TrustMarkStatusErrorResponse) this;
	}
	
	
	/**
	 * Parses a trust mark status response from the specified HTTP
	 * response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The trust mark status response.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static TrustMarkStatusResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		if (httpResponse.indicatesSuccess()) {
			return TrustMarkStatusSuccessResponse.parse(httpResponse);
		} else {
			return TrustMarkStatusErrorResponse.parse(httpResponse);
		}
	}
}
