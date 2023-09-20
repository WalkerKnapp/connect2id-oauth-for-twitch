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

package com.nimbusds.openid.connect.sdk.federation.registration;


import java.net.URI;

import net.jcip.annotations.Immutable;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;


/**
 * Explicit client registration request for a federation entity.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 9.2.
 * </ul>
 */
@Immutable
public class ExplicitClientRegistrationRequest extends AbstractRequest {
	
	
	/**
	 * The entity statement.
	 */
	private final EntityStatement entityStatement;
	
	
	/**
	 * Creates a new explicit client registration request for a federation
	 * entity.
	 *
	 * @param uri             The URI of the federation registration
	 *                        endpoint. May be {@code null} if the
	 *                        {@link #toHTTPRequest} method will not be
	 *                        used.
	 * @param entityStatement The entity statement of the client. Must not
	 *                        be {@code null}.
	 */
	public ExplicitClientRegistrationRequest(final URI uri, final EntityStatement entityStatement) {
		super(uri);
		this.entityStatement = entityStatement;
	}
	
	
	/**
	 * Returns the entity statement.
	 *
	 * @return The entity statement.
	 */
	public EntityStatement getEntityStatement() {
		return entityStatement;
	}
	
	
	@Override
	public HTTPRequest toHTTPRequest() {
		
		if (getEndpointURI() == null) {
			throw new SerializeException("The endpoint URI is not specified");
		}
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, getEndpointURI());
		httpRequest.setEntityContentType(ContentType.APPLICATION_JOSE);
		httpRequest.setBody(getEntityStatement().getSignedStatement().serialize());
		return httpRequest;
	}
	
	
	/**
	 * Parses an explicit client registration request from the specified
	 * HTTP request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The explicit client registration request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an
	 *                        explicit client registration request.
	 */
	public static ExplicitClientRegistrationRequest parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		// Only HTTP POST accepted
		URI uri = httpRequest.getURI();
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureEntityContentType(ContentType.APPLICATION_JOSE);
		
		String jwtString = httpRequest.getQuery();
		if (StringUtils.isBlank(jwtString)) {
			throw new ParseException("Missing entity body");
		}
		
		SignedJWT signedJWT;
		try {
			signedJWT = SignedJWT.parse(jwtString);
		} catch (java.text.ParseException e) {
			throw new ParseException("Invalid entity statement: " + e.getMessage(), e);
		}
		
		return new ExplicitClientRegistrationRequest(uri, EntityStatement.parse(signedJWT));
	}
}
