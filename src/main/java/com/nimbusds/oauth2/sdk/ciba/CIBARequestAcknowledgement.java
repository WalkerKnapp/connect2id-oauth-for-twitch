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
import com.nimbusds.oauth2.sdk.SuccessResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import java.util.Objects;


/**
 * Successful CIBA request acknowledgement from an OpenID provider / OAuth 2.0
 * authorisation server backend authentication endpoint.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * Cache-Control: no-store
 *
 * {
 *   "auth_req_id": "1c266114-a1be-4252-8ad1-04986c5b9ac1",
 *   "expires_in": 120,
 *   "interval": 2
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
public class CIBARequestAcknowledgement extends CIBAResponse implements SuccessResponse {
	
	
	/**
	 * The default minimal wait interval in seconds for polling the token
	 * endpoint for the poll and ping delivery modes.
	 */
	public static final int DEFAULT_MIN_WAIT_INTERVAL = 5;

	
	/**
	 * The CIBA request ID.
	 */
	private final AuthRequestID authRequestID;
	
	
	/**
	 * The expiration time of the CIBA request ID, in seconds.
	 */
	private final int expiresIn;
	
	
	/**
	 * The minimal wait interval in seconds for polling the token endpoint
	 * for the poll or ping delivery modes.
	 */
	private final Integer minWaitInterval;
	

	/**
	 * Creates a new successful CIBA request acknowledgement.
	 * 
	 * @param authRequestID   The CIBA request ID.
	 * @param expiresIn       The expiration time of the CIBA request ID,
	 *                        in seconds. Must be positive.
	 * @param minWaitInterval The minimal wait interval in seconds for
	 *                        polling the token endpoint for the poll or
	 *                        ping delivery modes, {@code null} if not
	 *                        specified.
	 */
	public CIBARequestAcknowledgement(final AuthRequestID authRequestID,
					  final int expiresIn,
					  final Integer minWaitInterval) {
		
		super();
		
		this.authRequestID = Objects.requireNonNull(authRequestID);
		
		if (expiresIn < 1) {
			throw new IllegalArgumentException("The expiration must be a positive integer");
		}
		this.expiresIn = expiresIn;

		if (minWaitInterval != null && minWaitInterval < 1) {
			throw new IllegalArgumentException("The interval must be a positive integer");
		}
		this.minWaitInterval = minWaitInterval;
	}
	

	@Override
	public boolean indicatesSuccess() {
		return true;
	}
	
	
	/**
	 * Returns the CIBA request ID.
	 *
	 * @return The CIBA request ID.
	 */
	public AuthRequestID getAuthRequestID() {
		return authRequestID;
	}
	
	
	/**
	 * Returns the expiration time of the CIBA request ID in seconds.
	 *
	 * @return The expiration time in seconds.
	 */
	public int getExpiresIn() {
		return expiresIn;
	}
	
	
	/**
	 * Returns the minimum wait interval in seconds for polling the token
	 * endpoint for the poll and ping delivery modes.
	 *
	 * @return The interval in seconds, {@code null} if not specified.
	 */
	public Integer getMinWaitInterval() {
		return minWaitInterval;
	}
	

	/**
	 * Returns a JSON object representation of this CIBA request
	 * acknowledgement.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {

		JSONObject o = new JSONObject();
		o.put("auth_req_id", authRequestID);
		o.put("expires_in", expiresIn);
		if (minWaitInterval != null) {
			o.put("interval", minWaitInterval);
		}
		return o;
	}

	
	@Override
	public HTTPResponse toHTTPResponse() {

		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");
		httpResponse.setBody(toJSONObject().toString());
		return httpResponse;
	}

	
	/**
	 * Parses a successful CIBA request acknowledgement from the specified
	 * JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The CIBA request acknowledgement.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static CIBARequestAcknowledgement parse(final JSONObject jsonObject)
		throws ParseException {

		AuthRequestID authRequestID = AuthRequestID.parse(JSONObjectUtils.getString(jsonObject, "auth_req_id"));
		
		int expiresIn = JSONObjectUtils.getInt(jsonObject, "expires_in");
		
		if (expiresIn < 1) {
			throw new ParseException("The expires_in parameter must be a positive integer");
		}
		
		Integer minWaitInterval = null;
		if (jsonObject.get("interval") != null) {
			minWaitInterval = JSONObjectUtils.getInt(jsonObject, "interval");
		}
		
		if (minWaitInterval != null && minWaitInterval < 1) {
			throw new ParseException("The interval parameter must be a positive integer");
		}
		
		return new CIBARequestAcknowledgement(authRequestID, expiresIn, minWaitInterval);
	}
	
	
	/**
	 * Parses a successful CIBA request acknowledgement from the specified
	 * HTTP response.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be
	 *                     {@code null}.
	 *
	 * @return The CIBA request acknowledgement.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static CIBARequestAcknowledgement parse(final HTTPResponse httpResponse)
		throws ParseException {

		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
		JSONObject jsonObject = httpResponse.getBodyAsJSONObject();
		return parse(jsonObject);
	}
}
