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
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;


/**
 * Fetch entity statement success response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 7.1.2.
 * </ul>
 */
@Immutable
public class FetchEntityStatementSuccessResponse extends FetchEntityStatementResponse {
	
	
	/**
	 * The entity statement.
	 */
	private final EntityStatement entityStatement;
	
	
	/**
	 * Creates a new fetch entity statement success response.
	 *
	 * @param entityStatement The entity statement. Must not be
	 *                        {@code null}.
	 */
	public FetchEntityStatementSuccessResponse(final EntityStatement entityStatement) {
		if (entityStatement == null) {
			throw new IllegalArgumentException("The federation entity statement must not be null");
		}
		this.entityStatement = entityStatement;
	}
	
	
	/**
	 * Returns the entity statement. No signature or expiration validation
	 * is performed.
	 *
	 * @return The entity statement.
	 */
	public EntityStatement getEntityStatement() {
		
		return entityStatement;
	}
	
	
	@Override
	public boolean indicatesSuccess() {
		return true;
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse() {
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		httpResponse.setEntityContentType(EntityStatement.CONTENT_TYPE);
		httpResponse.setContent(getEntityStatement().getSignedStatement().serialize());
		return httpResponse;
	}
	
	
	/**
	 * Parses a fetch entity statement success response from the specified
	 * HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The fetch entity statement success response.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static FetchEntityStatementSuccessResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
		httpResponse.ensureEntityContentType(EntityStatement.CONTENT_TYPE);
		return new FetchEntityStatementSuccessResponse(EntityStatement.parse(httpResponse.getContent()));
	}
}
