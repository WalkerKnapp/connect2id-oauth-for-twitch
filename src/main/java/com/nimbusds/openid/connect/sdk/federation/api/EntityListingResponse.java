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


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * Entity listing response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, sections 7.3.2 and 7.5.
 * </ul>
 */
public abstract class EntityListingResponse implements Response {
	
	
	/**
	 * Casts this response to an entity listing success response.
	 *
	 * @return The entity listing success response.
	 */
	public EntityListingSuccessResponse toSuccessResponse() {
		return (EntityListingSuccessResponse)this;
	}
	
	
	/**
	 * Casts this response to an entity listing error response.
	 *
	 * @return The entity listing error response.
	 */
	public EntityListingErrorResponse toErrorResponse() {
		return (EntityListingErrorResponse)this;
	}
	
	
	/**
	 * Parses an entity listing response from the specified HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The entity listing response.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static EntityListingResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		if (httpResponse.indicatesSuccess()) {
			return EntityListingSuccessResponse.parse(httpResponse);
		} else {
			return EntityListingErrorResponse.parse(httpResponse);
		}
	}
}
