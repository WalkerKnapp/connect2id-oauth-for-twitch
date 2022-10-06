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
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;


/**
 * Trust negotiation request.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 6.2.1.
 * </ul>
 */
@Immutable
public class TrustNegotiationRequest extends FederationAPIRequest {
	
	
	/**
	 * The respondent.
	 */
	private final EntityID respondent;
	
	
	/**
	 * The peer.
	 */
	private final EntityID peer;
	
	
	/**
	 * The entity type.
	 */
	private final EntityType metadataType;
	
	
	/**
	 * The trust anchor.
	 */
	private final EntityID anchor;
	
	
	/**
	 * Creates a new trust negotiation request.
	 *
	 * @param endpoint   The federation API endpoint. Must not be
	 *                   {@code null}.
	 * @param respondent he respondent. Must not be {@code null}.
	 * @param peer       The peer. Must not be {@code null}.
	 * @param entityType The entity type to resolve. Must not be
	 *                   {@code null}.
	 * @param anchor     The trust anchor. Must not be {@code null}.
	 */
	public TrustNegotiationRequest(final URI endpoint,
				       final EntityID respondent,
				       final EntityID peer,
				       final EntityType entityType,
				       final EntityID anchor) {
		
		super(endpoint, OperationType.RESOLVE_METADATA);
		
		if (respondent == null) {
			throw new IllegalArgumentException("The respondent must not be null");
		}
		this.respondent = respondent;
		
		if (peer == null) {
			throw new IllegalArgumentException("The peer must not be null");
		}
		this.peer = peer;
		
		if (entityType == null) {
			throw new IllegalArgumentException("The metadata type must not be null");
		}
		this.metadataType = entityType;
		
		if (anchor == null) {
			throw new IllegalArgumentException("The anchor must not be null");
		}
		this.anchor = anchor;
	}
	
	
	/**
	 * Returns the respondent.
	 *
	 * @return The respondent.
	 */
	public EntityID getRespondent() {
		return respondent;
	}
	
	
	/**
	 * Returns the peer.
	 *
	 * @return The peer.
	 */
	public EntityID getPeer() {
		return peer;
	}
	
	
	/**
	 * Returns the metadata type.
	 *
	 * @return The metadata type to resolve.
	 */
	public EntityType getMetadataType() {
		return metadataType;
	}
	
	
	/**
	 * Returns the trust anchor.
	 *
	 * @return The trust anchor.
	 */
	public EntityID getTrustAnchor() {
		return anchor;
	}
	
	
	@Override
	public Map<String, List<String>> toParameters() {
		Map<String, List<String>> params = new LinkedHashMap<>();
		params.put("operation", Collections.singletonList(getOperationType().getValue()));
		params.put("respondent", Collections.singletonList(getRespondent().getValue()));
		params.put("peer", Collections.singletonList(getPeer().getValue()));
		params.put("type", Collections.singletonList(getMetadataType().getValue()));
		params.put("anchor", Collections.singletonList(getTrustAnchor().getValue()));
		return params;
	}
	
	
	/**
	 * Parses a trust negotiation request from the specified query string
	 * parameters.
	 *
	 * @param params The query string parameters. Must not be {@code null}.
	 *
	 * @return The trust negotiation request.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static TrustNegotiationRequest parse(final Map<String, List<String>> params)
		throws ParseException {
		
		String value = MultivaluedMapUtils.getFirstValue(params, "operation");
		if (StringUtils.isBlank(value)) {
			throw new ParseException("Missing operation type");
		}
		if (! OperationType.RESOLVE_METADATA.getValue().equals(value)) {
			throw new ParseException("The operation type must be " + OperationType.RESOLVE_METADATA);
		}
		
		value = MultivaluedMapUtils.getFirstValue(params, "respondent");
		if (StringUtils.isBlank(value)) {
			throw new ParseException("Missing respondent");
		}
		EntityID respondent = new EntityID(value);
		
		value = MultivaluedMapUtils.getFirstValue(params, "peer");
		if (StringUtils.isBlank(value)) {
			throw new ParseException("Missing peer");
		}
		EntityID peer = new EntityID(value);
		
		value = MultivaluedMapUtils.getFirstValue(params, "type");
		if (StringUtils.isBlank(value)) {
			throw new ParseException("Missing metadata type");
		}
		EntityType metadataType = new EntityType(value);
		
		value = MultivaluedMapUtils.getFirstValue(params, "anchor");
		if (StringUtils.isBlank(value)) {
			throw new ParseException("Missing anchor");
		}
		EntityID anchor = new EntityID(value);
		
		return new TrustNegotiationRequest(null, respondent, peer, metadataType, anchor);
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
	public static TrustNegotiationRequest parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		httpRequest.ensureMethod(HTTPRequest.Method.GET);
		
		TrustNegotiationRequest request = TrustNegotiationRequest.parse(httpRequest.getQueryParameters());
		
		return new TrustNegotiationRequest(
			httpRequest.getURI(),
			request.respondent,
			request.getPeer(),
			request.getMetadataType(),
			request.getTrustAnchor());
	}
}
