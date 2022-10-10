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


import java.util.LinkedList;
import java.util.List;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONArray;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;


/**
 * Entity listing success response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 7.3.2.
 * </ul>
 */
@Immutable
public class EntityListingSuccessResponse extends EntityListingResponse {
	
	
	/**
	 * The entity IDs.
	 */
	private final List<EntityID> entityIDS;
	
	
	/**
	 * Creates a new entity listing success response.
	 *
	 * @param entityIDS The entity IDs. Must not be {@code null}.
	 */
	public EntityListingSuccessResponse(final List<EntityID> entityIDS) {
		if (entityIDS == null) {
			throw new IllegalArgumentException("The entity listing must not be null");
		}
		this.entityIDS = entityIDS;
	}
	
	
	/**
	 * Returns the entity IDs.
	 *
	 * @return The entity IDs.
	 */
	public List<EntityID> getEntityListing() {
		return entityIDS;
	}
	
	
	@Override
	public boolean indicatesSuccess() {
		return true;
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse() {
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		JSONArray jsonArray = new JSONArray();
		for (EntityID entityID: getEntityListing()) {
			jsonArray.add(entityID.getValue());
		}
		httpResponse.setContent(jsonArray.toJSONString());
		return httpResponse;
	}
	
	
	/**
	 * Parses an entity listing success response from the specified JSON
	 * array.
	 *
	 * @param jsonArray The JSON array. Must not be {@code null}.
	 *
	 * @return The entity listing success response.
	 */
	public static EntityListingSuccessResponse parse(final JSONArray jsonArray) {
		
		List<String> values = JSONArrayUtils.toStringList(jsonArray);
		
		List<EntityID> entityIDS = new LinkedList<>();
		for (String v: values) {
			entityIDS.add(new EntityID(v));
		}
		return new EntityListingSuccessResponse(entityIDS);
	}
	
	
	/**
	 * Parses an entity listing success response from the specified HTTP
	 * response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The entity listing success response.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static EntityListingSuccessResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
		return EntityListingSuccessResponse.parse(httpResponse.getContentAsJSONArray());
	}
}
