/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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

package com.nimbusds.oauth2.sdk.ciba;


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ProtectedResourceRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import java.net.URI;
import java.util.Objects;


/**
 * <p>CIBA ping callback to a client notification endpoint.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * POST /cb HTTP/1.1
 * Host: client.example.com
 * Authorization: Bearer 8d67dc78-7faa-4d41-aabd-67707b374255
 * Content-Type: application/json
 *
 * {
 *   "auth_req_id": "1c266114-a1be-4252-8ad1-04986c5b9ac1"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *      <li>OpenID Connect CIBA Flow - Core 1.0
 * </ul>
 */
@Immutable
public class CIBAPingCallback extends ProtectedResourceRequest {
	
	
	/**
	 * The CIBA request ID.
	 */
	private final AuthRequestID authRequestID;
	
	
	/**
	 * Creates a new CIBA ping callback.
	 *
	 * @param endpoint      The client notification endpoint. Must not be
	 *                      {@code null}.
	 * @param accessToken   The client notification token. Must not be
	 *                      {@code null}.
	 * @param authRequestID The CIBA request ID. Must not be {@code null}.
	 */
	public CIBAPingCallback(final URI endpoint,
				final BearerAccessToken accessToken,
				final AuthRequestID authRequestID) {
		super(endpoint, accessToken);
		this.authRequestID = Objects.requireNonNull(authRequestID);
	}
	
	
	/**
	 * Returns the CIBA request ID.
	 *
	 * @return The CIBA request ID.
	 */
	public AuthRequestID getAuthRequestID() {
		return authRequestID;
	}
	
	
	@Override
	public HTTPRequest toHTTPRequest() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, getEndpointURI());
		httpRequest.setFollowRedirects(false);
		httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());
		httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("auth_req_id", getAuthRequestID().getValue());
		httpRequest.setBody(jsonObject.toJSONString());
		return httpRequest;
	}
	
	
	/**
	 * Parses a CIBA ping callback from the specified HTTP request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The CIBA ping callback.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static CIBAPingCallback parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		URI uri = httpRequest.getURI();
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureEntityContentType(ContentType.APPLICATION_JSON);
		
		BearerAccessToken accessToken = BearerAccessToken.parse(httpRequest);
		
		AuthRequestID authRequestID = new AuthRequestID(
			JSONObjectUtils.getString(
			httpRequest.getBodyAsJSONObject(),
			"auth_req_id")
		);
		
		return new CIBAPingCallback(uri, accessToken, authRequestID);
	}
}
