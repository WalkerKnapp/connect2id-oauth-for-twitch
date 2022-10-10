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
 * Fetch entity statement response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, sections 7.1.2 and 7.5.
 * </ul>
 */
public abstract class FetchEntityStatementResponse implements Response {
	
	
	/**
	 * Casts this response to a fetch entity statement success response.
	 *
	 * @return The fetch entity success response.
	 */
	public FetchEntityStatementSuccessResponse toSuccessResponse() {
		return (FetchEntityStatementSuccessResponse)this;
	}
	
	
	/**
	 * Casts this response to a fetch entity statement error response.
	 *
	 * @return The fetch entity error response.
	 */
	public FetchEntityStatementErrorResponse toErrorResponse() {
		return (FetchEntityStatementErrorResponse)this;
	}
	
	
	/**
	 * Parses a fetch entity statement response from the specified HTTP
	 * response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The fetch entity statement response.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static FetchEntityStatementResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		if (httpResponse.indicatesSuccess()) {
			return FetchEntityStatementSuccessResponse.parse(httpResponse);
		} else {
			return FetchEntityStatementErrorResponse.parse(httpResponse);
		}
	}
}
