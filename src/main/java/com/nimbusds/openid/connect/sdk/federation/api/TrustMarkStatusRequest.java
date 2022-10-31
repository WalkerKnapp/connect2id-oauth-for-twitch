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


import java.net.URI;
import java.util.*;

import net.jcip.annotations.Immutable;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;


/**
 * Trust mark status request.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 7.4.1.
 * </ul>
 */
@Immutable
public class TrustMarkStatusRequest extends FederationAPIRequest {
	
	
	/**
	 * The trust mark subject.
	 */
	private final Subject subject;
	
	
	/**
	 * The trust mark identifier.
	 */
	private final Identifier id;
	
	
	/**
	 * The trust mark issue time.
	 */
	private final Date iat;
	
	
	/**
	 * The trust mark.
	 */
	private final SignedJWT trustMark;
	
	
	/**
	 * Creates a new trust mark status request.
	 *
	 * @param endpoint The trust mark status endpoint. Must not be
	 *                 {@code null}.
	 * @param subject  The subject. Must not be {@code null}.
	 * @param id       The trust mark identifier. Must not be {@code null}.
	 * @param iat      The trust mark issue time, {@code null} if not
	 *                 specified.
	 */
	public TrustMarkStatusRequest(final URI endpoint,
				      final Subject subject,
				      final Identifier id,
				      final Date iat) {
		
		super(endpoint);
		
		if (subject == null) {
			throw new IllegalArgumentException("The subject must not be null");
		}
		this.subject = subject;
		
		if (id == null) {
			throw new IllegalArgumentException("The ID must not be null");
		}
		this.id = id;
		
		this.iat = iat;
		
		trustMark = null;
	}
	
	
	/**
	 * Creates a new trust mark status request.
	 *
	 * @param endpoint  The trust mark status endpoint. Must not be
	 *                  {@code null}.
	 * @param trustMark The trust mark. Must not be {@code null}.
	 */
	public TrustMarkStatusRequest(final URI endpoint,
				      final SignedJWT trustMark) {
		super(endpoint);
		
		if (trustMark == null) {
			throw new IllegalArgumentException("The trust mark must not be null");
		}
		this.trustMark = trustMark;
		
		subject = null;
		id = null;
		iat = null;
	}
	
	
	/**
	 * Returns the trust mark subject.
	 *
	 * @return The trust mark subject, {@code null} if not specified.
	 */
	public Subject getSubject() {
		return subject;
	}
	
	
	/**
	 * Returns the trust mark subject entity ID.
	 *
	 * @return The trust mark subject entity ID, {@code null} if not
	 *         specified.
	 */
	public EntityID getSubjectEntityID() {
		return subject != null ? new EntityID(subject) : null;
	}
	
	
	/**
	 * Returns the trust mark ID.
	 *
	 * @return The trust mark ID, {@code null} if not specified.
	 */
	public Identifier getID() {
		return id;
	}
	
	
	/**
	 * Returns the trust mark issue time.
	 *
	 * @return The trust mark issue time, {@code null} if not specified.
	 */
	public Date getIssueTime() {
		return iat;
	}
	
	
	/**
	 * Returns the trust mark.
	 *
	 * @return The trust mark, {@code null} if not specified.
	 */
	public SignedJWT getTrustMark() {
		return trustMark;
	}
	
	
	@Override
	public Map<String, List<String>> toParameters() {
		Map<String, List<String>> params = new LinkedHashMap<>();
		if (getSubject() != null) {
			params.put("sub", Collections.singletonList(getSubject().getValue()));
		}
		if (getID() != null) {
			params.put("id", Collections.singletonList(getID().getValue()));
		}
		if (getIssueTime() != null) {
			params.put("iat", Collections.singletonList(DateUtils.toSecondsSinceEpoch(getIssueTime()) + ""));
		}
		if (getTrustMark() != null) {
			params.put("trust_mark", Collections.singletonList(getTrustMark().serialize()));
		}
		return params;
	}
	
	
	@Override
	public HTTPRequest toHTTPRequest() {
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, getEndpointURI());
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setQuery(URLUtils.serializeParameters(toParameters()));
		return httpRequest;
	}
	
	
	/**
	 * Parses a trust mark status request from the specified request
	 * parameters.
	 *
	 * @param params The request parameters. Must not be {@code null}.
	 *
	 * @return The trust mark status request.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static TrustMarkStatusRequest parse(final Map<String, List<String>> params)
		throws ParseException {
		
		Subject subject = null;
		String value = MultivaluedMapUtils.getFirstValue(params, "sub");
		if (StringUtils.isNotBlank(value)) {
			subject = new Subject(value);
		}
		
		Identifier id = null;
		value = MultivaluedMapUtils.getFirstValue(params, "id");
		if (StringUtils.isNotBlank(value)) {
			id = new Identifier(value);
		}
		
		Date iat = null;
		value = MultivaluedMapUtils.getFirstValue(params, "iat");
		if (StringUtils.isNotBlank(value)) {
			try {
				iat = DateUtils.fromSecondsSinceEpoch(Long.parseLong(value));
			} catch (NumberFormatException e) {
				throw new ParseException("Illegal iat");
			}
		}
		
		SignedJWT trustMark = null;
		value = MultivaluedMapUtils.getFirstValue(params, "trust_mark");
		if (StringUtils.isNotBlank(value)) {
			try {
				trustMark = SignedJWT.parse(value);
			} catch (java.text.ParseException e) {
				throw new ParseException("Invalid trust mark: " + e.getMessage(), e);
			}
		}
		
		if (trustMark != null) {
			return new TrustMarkStatusRequest(null, trustMark);
		}
		
		try {
			return new TrustMarkStatusRequest(null, subject, id, iat);
		} catch (IllegalArgumentException e) {
			throw new ParseException("Invalid request: " + e.getMessage());
		}
	}
	
	
	/**
	 * Parses a trust mark status request from the specified HTTP request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The trust negotiation request.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static TrustMarkStatusRequest parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureEntityContentType(ContentType.APPLICATION_URLENCODED);
		
		TrustMarkStatusRequest request = TrustMarkStatusRequest.parse(httpRequest.getQueryParameters());
		
		if (request.getTrustMark() != null) {
			return new TrustMarkStatusRequest(
				httpRequest.getURI(),
				request.trustMark
			);
		} else {
			return new TrustMarkStatusRequest(
				httpRequest.getURI(),
				request.getSubject(),
				request.getID(),
				request.getIssueTime()
			);
		}
	}
}
