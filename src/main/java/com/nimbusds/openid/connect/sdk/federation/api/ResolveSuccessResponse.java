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
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;


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
	 * The metadata JSON object.
	 */
	private final JSONObject metadata;
	
	
	/**
	 * Creates a new trust negotiation success response.
	 *
	 * @param metadata The metadata JSON object for the requested {@link
	 *                 EntityType entity type}. Must not be {@code null}.
	 */
	public ResolveSuccessResponse(final JSONObject metadata) {
		if (metadata == null) {
			throw new IllegalArgumentException("The metadata JSON object must not be null");
		}
		this.metadata = metadata;
	}
	
	
	/**
	 * Returns metadata JSON object for the requested {@link
	 * EntityType
	 * metadata type}.
	 *
	 * @return The metadata JSON object.
	 */
	public JSONObject getMetadataJSONObject() {
		return metadata;
	}
	
	
	@Override
	public boolean indicatesSuccess() {
		return true;
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse() {
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		httpResponse.setContent(getMetadataJSONObject().toJSONString());
		return httpResponse;
	}
	
	
	/**
	 * Parses a trust negotiation success response from the specified HTTP
	 * response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The trust negotiation success response.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ResolveSuccessResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
		JSONObject jsonObject = httpResponse.getContentAsJSONObject();
		return new ResolveSuccessResponse(jsonObject);
	}
}
