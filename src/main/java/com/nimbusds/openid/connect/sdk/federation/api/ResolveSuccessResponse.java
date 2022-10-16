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
 * Resolve entity statement success response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 7.2.2.
 * </ul>
 */
@Immutable
public class ResolveSuccessResponse extends ResolveResponse {
	
	
	/**
	 * The resolve statement.
	 */
	private final ResolveStatement resolveStatement;
	
	
	/**
	 * Creates a new trust negotiation success response.
	 *
	 * @param resolveStatement The resolve statement. Must not be
	 *                         {@code null}.
	 */
	public ResolveSuccessResponse(final ResolveStatement resolveStatement) {
		if (resolveStatement == null) {
			throw new IllegalArgumentException("The resolve statement must not be null");
		}
		this.resolveStatement = resolveStatement;
	}
	
	
	/**
	 * Returns the resolve statement. No signature or expiration validation
	 * is performed.
	 *
	 * @return The resolve statement.
	 */
	public ResolveStatement getResolveStatement() {
		return resolveStatement;
	}
	
	
	@Override
	public boolean indicatesSuccess() {
		return true;
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse() {
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		httpResponse.setEntityContentType(ResolveStatement.CONTENT_TYPE);
		httpResponse.setContent(getResolveStatement().getSignedStatement().serialize());
		return httpResponse;
	}
	
	
	/**
	 * Parses a resolve success response from the specified HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The resolve success response.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ResolveSuccessResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
		httpResponse.ensureEntityContentType(ResolveStatement.CONTENT_TYPE);
		return new ResolveSuccessResponse(ResolveStatement.parse(httpResponse.getContent()));
	}
}
