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

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;


/**
 * Entity listing request.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 7.3.1.
 * </ul>
 */
@Immutable
public class EntityListingRequest extends FederationAPIRequest {
	
	
	/**
	 * Optional entity type.
	 */
	private final EntityType entityType;
	
	
	/**
	 * Creates a new entity listing request.
	 *
	 * @param endpoint The federation list endpoint. Must not be
	 *                 {@code null}.
	 */
	public EntityListingRequest(final URI endpoint) {
		this(endpoint, null);
	}
	
	
	/**
	 * Creates a new entity listing request.
	 *
	 * @param endpoint   The federation list endpoint. Must not be
	 *                   {@code null}.
	 * @param entityType The type of the entities to list, {@code null} for
	 *                   all.
	 */
	public EntityListingRequest(final URI endpoint, final EntityType entityType) {
		super(endpoint);
		this.entityType = entityType;
	}
	
	
	/**
	 * Returns the type of the entities to list.
	 *
	 * @return The type of the entities to list, {@code null} for all.
	 */
	public EntityType getEntityType() {
		return entityType;
	}
	
	
	@Override
	public Map<String, List<String>> toParameters() {
		Map<String, List<String>> params = new HashMap<>();
		if (entityType != null) {
			params.put("entity_type", Collections.singletonList(entityType.getValue()));
		}
		return Collections.unmodifiableMap(params);
	}
	
	
	@Override
	public HTTPRequest toHTTPRequest() {
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, getEndpointURI());
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setQuery(URLUtils.serializeParameters(toParameters()));
		return httpRequest;
	}
	
	
	/**
	 * Parses an entity listing request from the specified HTTP request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The entity listing request.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static EntityListingRequest parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		httpRequest.ensureMethod(HTTPRequest.Method.GET);
		
		EntityType entityType = null;
		Map<String, List<String>> params = httpRequest.getQueryParameters();
		String value = MultivaluedMapUtils.getFirstValue(params, "entity_type");
		if (StringUtils.isNotBlank(value)) {
			entityType = new EntityType(value);
		}
		return new EntityListingRequest(httpRequest.getURI(), entityType);
	}
}
