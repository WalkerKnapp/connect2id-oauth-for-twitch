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


import java.nio.charset.StandardCharsets;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;


/**
 * Federation entity configuration success response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 6.2.
 * </ul>
 */
public class FederationEntityConfigurationSuccessResponse extends FederationEntityConfigurationResponse {
	
	
	/**
	 * The content type.
	 */
	private static final ContentType CONTENT_TYPE = new ContentType("application", "jose", StandardCharsets.UTF_8);
	
	
	/**
	 * The entity statement.
	 */
	private final EntityStatement entityStatement;
	
	
	/**
	 * Creates a new federation entity configuration success response.
	 *
	 * @param entityStatement The entity statement. Must not be
	 *                        {@code null}.
	 */
	public FederationEntityConfigurationSuccessResponse(final EntityStatement entityStatement) {
		
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
		httpResponse.setEntityContentType(CONTENT_TYPE);
		httpResponse.setContent(entityStatement.getSignedStatement().serialize());
		return httpResponse;
	}
	
	
	/**
	 * Parses a federation entity configuration success response from the
	 * specified HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The federation entity configuration success response.
	 *
	 * @throws ParseException If HTTP response couldn't be parsed to a
	 *                        federation entity configuration success
	 *                        response.
	 */
	public static FederationEntityConfigurationSuccessResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
		httpResponse.ensureEntityContentType(CONTENT_TYPE);
		
		String content = httpResponse.getContent();
		
		if (StringUtils.isBlank(content)) {
			throw new ParseException("Empty HTTP entity body");
		}
		
		SignedJWT signedJWT;
		try {
			signedJWT = SignedJWT.parse(httpResponse.getContent());
		} catch (java.text.ParseException e) {
			throw new ParseException(e.getMessage(), e);
		}
		
		return new FederationEntityConfigurationSuccessResponse(EntityStatement.parse(signedJWT));
	}
}
