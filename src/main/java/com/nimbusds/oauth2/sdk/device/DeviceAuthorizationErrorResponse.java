/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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

package com.nimbusds.oauth2.sdk.device;


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import java.net.URI;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;


/**
 * OAuth 2.0 device authorization error response.
 *
 * <p>Standard authorization errors:
 *
 * <ul>
 *     <li>{@link OAuth2Error#INVALID_REQUEST}
 *     <li>{@link OAuth2Error#INVALID_CLIENT}
 *     <li>{@link OAuth2Error#INVALID_SCOPE}
 * </ul>
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 400 Bad Request
 * Content-Type: application/json
 * Cache-Control: no-store
 * Pragma: no-cache
 * 
 * {
 *  "error" : "invalid_request"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Device Authorization Grant (RFC 8628)
 * </ul>
 */
@Immutable
public class DeviceAuthorizationErrorResponse extends DeviceAuthorizationResponse implements ErrorResponse {

	
	/**
	 * The standard OAuth 2.0 errors for a device authorization error response.
	 */
	private static final Set<ErrorObject> STANDARD_ERRORS;

	static {
		Set<ErrorObject> errors = new HashSet<>();
		errors.add(OAuth2Error.INVALID_REQUEST);
		errors.add(OAuth2Error.INVALID_CLIENT);
		errors.add(OAuth2Error.INVALID_SCOPE);
		STANDARD_ERRORS = Collections.unmodifiableSet(errors);
	}


	/**
	 * Gets the standard OAuth 2.0 errors for a device authorization error
	 * response.
	 *
	 * @return The standard errors, as a read-only set.
	 */
	public static Set<ErrorObject> getStandardErrors() {

		return STANDARD_ERRORS;
	}


	/**
	 * The error.
	 */
	private final ErrorObject error;


	/**
	 * Creates a new OAuth 2.0 device authorization error response. No
	 * OAuth 2.0 error is specified.
	 */
	protected DeviceAuthorizationErrorResponse() {

		error = null;
	}


	/**
	 * Creates a new OAuth 2.0 device authorization error response.
	 *
	 * @param error The error. Should match one of the
	 *              {@link #getStandardErrors standard errors} for a token
	 *              error response. Must not be {@code null}.
	 */
	public DeviceAuthorizationErrorResponse(final ErrorObject error) {

		if (error == null)
			throw new IllegalArgumentException("The error must not be null");

		this.error = error;
	}


	@Override
	public boolean indicatesSuccess() {

		return false;
	}


	@Override
	public ErrorObject getErrorObject() {

		return error;
	}


	/**
	 * Returns the JSON object for this token error response.
	 *
	 * @return The JSON object for this token error response.
	 */
	public JSONObject toJSONObject() {

		JSONObject o = new JSONObject();

		// No error?
		if (error == null)
			return o;

		o.put("error", error.getCode());

		if (error.getDescription() != null)
			o.put("error_description", error.getDescription());

		if (error.getURI() != null)
			o.put("error_uri", error.getURI().toString());

		return o;
	}


	@Override
	public HTTPResponse toHTTPResponse() {

		int statusCode = (error != null && error.getHTTPStatusCode() > 0) ? error.getHTTPStatusCode()
		                : HTTPResponse.SC_BAD_REQUEST;

		HTTPResponse httpResponse = new HTTPResponse(statusCode);

		if (error == null)
			return httpResponse;

		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");

		httpResponse.setBody(toJSONObject().toString());

		return httpResponse;
	}


	/**
	 * Parses an OAuth 2.0 device authorization response from the specified
	 * JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Its status code must not
	 *                   be 200 (OK). Must not be {@code null}.
	 *
	 * @return The token error response.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OAuth 2.0 device authorization error
	 *                        response.
	 */
	public static DeviceAuthorizationErrorResponse parse(final JSONObject jsonObject) throws ParseException {

		// No error code?
		if (!jsonObject.containsKey("error"))
			return new DeviceAuthorizationErrorResponse();

		ErrorObject error;

		try {
			// Parse code
			String code = JSONObjectUtils.getString(jsonObject, "error");
			String description = JSONObjectUtils.getString(jsonObject, "error_description", null);
			URI uri = JSONObjectUtils.getURI(jsonObject, "error_uri", null);

			error = new ErrorObject(code, description, HTTPResponse.SC_BAD_REQUEST, uri);

		} catch (ParseException e) {
			throw new ParseException("Missing or invalid token error response parameter: " + e.getMessage(),
			                e);
		}

		return new DeviceAuthorizationErrorResponse(error);
	}


	/**
	 * Parses an OAuth 2.0 ciba authorization error, push error or token response -  from the
	 * specified HTTP response.
	 *
	 * @param httpResponse The HTTP response to parse. Its status code must
	 *                     not be 200 (OK). Must not be {@code null}.
	 *
	 * @return The device authorization error response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an
	 *                        OAuth 2.0 device authorization error
	 *                        response.
	 */
	public static DeviceAuthorizationErrorResponse parse(final HTTPResponse httpResponse) throws ParseException {

		httpResponse.ensureStatusCodeNotOK();
		return new DeviceAuthorizationErrorResponse(ErrorObject.parse(httpResponse));
	}
}
