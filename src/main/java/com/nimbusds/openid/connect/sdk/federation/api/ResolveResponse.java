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
 * Resolve entity statement response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, sections 7.5.
 * </ul>
 */
public abstract class ResolveResponse implements Response {
	
	
	/**
	 * Casts this response to a resolve entity statement success response.
	 *
	 * @return The resolve entity statement success response.
	 */
	public ResolveSuccessResponse toSuccessResponse() {
		return (ResolveSuccessResponse)this;
	}
	
	
	/**
	 * Casts this response to a resolve entity statement error response.
	 *
	 * @return The resolve entity statement error response.
	 */
	public ResolveErrorResponse toErrorResponse() {
		return (ResolveErrorResponse)this;
	}
	
	
	/**
	 * Parses a resolve entity statement response from the specified HTTP
	 * response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The resolve entity statement response.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ResolveResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		if (httpResponse.indicatesSuccess()) {
			return ResolveSuccessResponse.parse(httpResponse);
		} else {
			return ResolveErrorResponse.parse(httpResponse);
		}
	}
}
