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
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Trust mark status success response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 7.4.2.
 * </ul>
 */
@Immutable
public class TrustMarkStatusSuccessResponse extends TrustMarkStatusResponse {
	
	
	/**
	 * The trust mark active status.
	 */
	private final boolean active;
	
	
	/**
	 * Creates a new trust mark status success response.
	 *
	 * @param active {@code true} if the trust mark is active,
	 *               {@code false} if invalid.
	 */
	public TrustMarkStatusSuccessResponse(final boolean active) {
		this.active = active;
	}
	
	
	/**
	 * Returns the trust mark active status.
	 *
	 * @return {@code true} if the trust mark is active, {@code false} if
	 *         invalid.
	 */
	public boolean isActive() {
		return active;
	}
	
	
	@Override
	public boolean indicatesSuccess() {
		return true;
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse() {
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("active", isActive());
		httpResponse.setContent(jsonObject.toJSONString());
		return httpResponse;
	}
	
	
	/**
	 * Parses a trust mark status success response from the specified HTTP
	 * response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The trust mark status success response.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static TrustMarkStatusSuccessResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
		JSONObject jsonObject = httpResponse.getContentAsJSONObject();
		boolean active = JSONObjectUtils.getBoolean(jsonObject, "active");
		return new TrustMarkStatusSuccessResponse(active);
	}
}
