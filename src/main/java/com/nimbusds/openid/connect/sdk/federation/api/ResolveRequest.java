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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;


/**
 * Resolve entity statement request.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 7.2.1.
 * </ul>
 */
@Immutable
public class ResolveRequest extends FederationAPIRequest {
	
	
	/**
	 * The subject.
	 */
	private final Subject subject;
	
	
	/**
	 * The trust anchor.
	 */
	private final EntityID anchor;
	
	
	/**
	 * The entity type to resolve.
	 */
	private final EntityType entityType;
	
	
	/**
	 * Creates a new resolve entity statement request.
	 *
	 * @param endpoint   The federation resolve endpoint. Must not be
	 *                   {@code null}.
	 * @param subject    The subject. Must not be {@code null}.
	 * @param anchor     The trust anchor. Must not be {@code null}.
	 * @param entityType The entity type to resolve, {@code null} if not
	 *                   specified.
	 */
	public ResolveRequest(final URI endpoint,
			      final Subject subject,
			      final EntityID anchor,
			      final EntityType entityType) {
		
		super(endpoint);
		
		if (subject == null) {
			throw new IllegalArgumentException("The subject must not be null");
		}
		this.subject = subject;
		
		if (anchor == null) {
			throw new IllegalArgumentException("The anchor must not be null");
		}
		this.anchor = anchor;
		
		this.entityType = entityType;
	}
	
	
	/**
	 * Returns the subject.
	 *
	 * @return The subject.
	 */
	public Subject getSubject() {
		return subject;
	}
	
	
	/**
	 * Returns the subject entity ID.
	 *
	 * @return The subject entity ID.
	 */
	public EntityID getSubjectEntityID() {
		return new EntityID(subject);
	}
	
	
	/**
	 * Returns the trust anchor.
	 *
	 * @return The trust anchor.
	 */
	public EntityID getTrustAnchor() {
		return anchor;
	}
	
	
	/**
	 * Returns the metadata type to resolve.
	 *
	 * @return The metadata type to resolve.
	 */
	public EntityType getEntityType() {
		return entityType;
	}
	
	
	@Override
	public Map<String, List<String>> toParameters() {
		Map<String, List<String>> params = new LinkedHashMap<>();
		params.put("sub", Collections.singletonList(getSubject().getValue()));
		params.put("anchor", Collections.singletonList(getTrustAnchor().getValue()));
		if (getEntityType() != null) {
			params.put("type", Collections.singletonList(getEntityType().getValue()));
		}
		return params;
	}
	
	
	/**
	 * Parses a resolve entity statement request from the specified query
	 * string parameters.
	 *
	 * @param params The query string parameters. Must not be {@code null}.
	 *
	 * @return The resolve entity statement request.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ResolveRequest parse(final Map<String, List<String>> params)
		throws ParseException {
		
		String value = MultivaluedMapUtils.getFirstValue(params, "sub");
		if (StringUtils.isBlank(value)) {
			throw new ParseException("Missing sub");
		}
		Subject subject = new Subject(value);
		
		value = MultivaluedMapUtils.getFirstValue(params, "anchor");
		if (StringUtils.isBlank(value)) {
			throw new ParseException("Missing anchor");
		}
		EntityID anchor = new EntityID(value);
		
		EntityType entityType = null;
		value = MultivaluedMapUtils.getFirstValue(params, "type");
		if (StringUtils.isNotBlank(value)) {
			entityType = new EntityType(value);
		}
		
		return new ResolveRequest(null, subject, anchor, entityType);
	}
	
	
	/**
	 * Parses a trust negotiation request from the specified HTTP request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The trust negotiation request.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ResolveRequest parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		httpRequest.ensureMethod(HTTPRequest.Method.GET);
		
		ResolveRequest request = ResolveRequest.parse(httpRequest.getQueryParameters());
		
		return new ResolveRequest(
			httpRequest.getURI(),
			request.getSubject(),
			request.getTrustAnchor(),
			request.getEntityType());
	}
}
