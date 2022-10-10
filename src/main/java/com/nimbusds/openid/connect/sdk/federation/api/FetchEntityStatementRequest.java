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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;


/**
 * Fetch entity statement request.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 7.1.1.
 * </ul>
 */
@Immutable
public class FetchEntityStatementRequest extends FederationAPIRequest {
	
	
	/**
	 * The optional issuer.
	 */
	private final Issuer issuer;
	
	
	/**
	 * The optional subject.
	 */
	private final Subject subject;
	
	
	/**
	 * Creates a new fetch entity request.
	 *
	 * @param endpoint The federation fetch endpoint. Must not be
	 *                 {@code null}.
	 * @param issuer   The issuer entity identifier, {@code null} if not
	 *                 specified.
	 * @param subject  The subject entity identifier, {@code null} if not
	 *                 specified.
	 */
	public FetchEntityStatementRequest(final URI endpoint, final Issuer issuer, final Subject subject) {
		super(endpoint);
		this.issuer = issuer;
		this.subject = subject;
	}
	
	
	/**
	 * Creates a new entity fetch request.
	 *
	 * @param endpoint The federation fetch endpoint. Must not be
	 *                 {@code null}.
	 * @param issuer   The issuer entity identifier, {@code null} if not
	 *                 specified.
	 * @param subject  The subject entity identifier, {@code null} if not
	 *                 specified.
	 */
	public FetchEntityStatementRequest(final URI endpoint, final EntityID issuer, final EntityID subject) {
		this(
			endpoint,
			issuer != null ? new Issuer(issuer.getValue()) : null,
			subject != null ? new Subject(subject.getValue()) : null
		);
	}
	
	
	/**
	 * Returns the issuer.
	 *
	 * @return The issuer, {@code null} if not specified.
	 */
	public Issuer getIssuer() {
		return issuer;
	}
	
	
	/**
	 * Returns the issuer entity ID.
	 *
	 * @return The issuer entity ID, {@code null} if not specified.
	 */
	public EntityID getIssuerEntityID() {
		return getIssuer() != null ? new EntityID(getIssuer().getValue()) : null;
	}
	
	
	/**
	 * Returns the optional subject.
	 *
	 * @return The subject, {@code null} if not specified.
	 */
	public Subject getSubject() {
		return subject;
	}
	
	
	/**
	 * Returns the optional subject entity ID.
	 *
	 * @return The subject entity ID, {@code null} if not specified.
	 */
	public EntityID getSubjectEntityID() {
		return getSubject() != null ? new EntityID(getSubject().getValue()) : null;
	}
	
	
	@Override
	public Map<String, List<String>> toParameters() {
		
		Map<String, List<String>> params = new HashMap<>();
		if (getIssuer() != null) {
			params.put("iss", Collections.singletonList(getIssuer().getValue()));
		}
		if (getSubject() != null) {
			params.put("sub", Collections.singletonList(getSubject().getValue()));
		}
		return params;
	}
	
	
	/**
	 * Parses a fetch entity statement request from the specified query
	 * string parameters.
	 *
	 * @param params The query string parameters. Must not be {@code null}.
	 *
	 * @return The fetch entity statement request.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static FetchEntityStatementRequest parse(final Map<String, List<String>> params)
		throws ParseException {
		
		String value = MultivaluedMapUtils.getFirstValue(params, "iss");
		Issuer issuer = null;
		if (value != null) {
			issuer = new Issuer(value);
		}
		
		value = MultivaluedMapUtils.getFirstValue(params, "sub");
		Subject subject = null;
		if (value != null) {
			subject = new Subject(value);
		}
		
		return new FetchEntityStatementRequest(null, issuer, subject);
	}
	
	
	/**
	 * Parses a fetch entity statement request from the specified HTTP
	 * request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The fetch entity statement request.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static FetchEntityStatementRequest parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		httpRequest.ensureMethod(HTTPRequest.Method.GET);
		FetchEntityStatementRequest request = parse(httpRequest.getQueryParameters());
		return new FetchEntityStatementRequest(
			httpRequest.getURI(),
			request.getIssuer(),
			request.getSubject());
	}
}
