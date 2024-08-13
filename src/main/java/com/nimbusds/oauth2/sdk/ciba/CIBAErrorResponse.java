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

package com.nimbusds.oauth2.sdk.ciba;


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;


/**
 * CIBA error response from an OpenID provider / OAuth 2.0 authorisation server
 * backend authentication endpoint.
 *
 * <p>Standard CIBA errors:
 *
 * <ul>
 * 	<li>{@link OAuth2Error#INVALID_REQUEST}
 * 	<li>{@link OAuth2Error#INVALID_SCOPE}
 * 	<li>{@link OAuth2Error#INVALID_CLIENT}
 * 	<li>{@link OAuth2Error#UNAUTHORIZED_CLIENT}
 * 	<li>{@link OAuth2Error#ACCESS_DENIED}
 * 	<li>{@link CIBAError#EXPIRED_LOGIN_HINT_TOKEN}
 * 	<li>{@link CIBAError#UNKNOWN_USER_ID}
 * 	<li>{@link CIBAError#MISSING_USER_CODE}
 * 	<li>{@link CIBAError#INVALID_USER_CODE}
 * 	<li>{@link CIBAError#INVALID_BINDING_MESSAGE}
 * </ul>
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 400 Bad Request
 * Content-Type: application/json
 *
 * {
 *   "error": "unauthorized_client",
 *   "error_description": "The client 'client.example.org' is not allowed to use CIBA"
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
public class CIBAErrorResponse extends CIBAResponse implements ErrorResponse {

	
	/**
	 * The standard OAuth 2.0 errors for a CIBA error response.
	 */
	private static final Set<ErrorObject> STANDARD_ERRORS;

	static {
		Set<ErrorObject> errors = new HashSet<>();
		errors.add(OAuth2Error.INVALID_REQUEST);
		errors.add(OAuth2Error.INVALID_SCOPE);
		errors.add(OAuth2Error.INVALID_CLIENT);
		errors.add(OAuth2Error.UNAUTHORIZED_CLIENT);
		errors.add(OAuth2Error.ACCESS_DENIED);
		errors.add(CIBAError.EXPIRED_LOGIN_HINT_TOKEN);
		errors.add(CIBAError.UNKNOWN_USER_ID);
		errors.add(CIBAError.MISSING_USER_CODE);
		errors.add(CIBAError.INVALID_USER_CODE);
		errors.add(CIBAError.INVALID_BINDING_MESSAGE);
		STANDARD_ERRORS = Collections.unmodifiableSet(errors);
	}

	
	/**
	 * Gets the standard OAuth 2.0 errors for a CIBA error response.
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
	 * Creates a new CIBA error response. No OAuth 2.0 error is specified.
	 */
	protected CIBAErrorResponse() {

		error = null;
	}

	
	/**
	 * Creates a new CIBA error response.
	 *
	 * @param error The error. Should match one of the
	 *              {@link #getStandardErrors standard errors} for a CIBA
	 *              error response. Must not be {@code null}.
	 */
	public CIBAErrorResponse(final ErrorObject error) {
		this.error = Objects.requireNonNull(error);
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
	 * Returns the JSON object for this CIBA error response.
	 *
	 * @return The JSON object for this CIBA error response.
	 */
	public JSONObject toJSONObject() {

		if (error != null) {
			return error.toJSONObject();
		} else {
			return new JSONObject();
		}
	}
	

	@Override
	public HTTPResponse toHTTPResponse() {

		int statusCode = (error != null && error.getHTTPStatusCode() > 0) ?
			error.getHTTPStatusCode() : HTTPResponse.SC_BAD_REQUEST;

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
	 * Parses a CIBA error response from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Its status code must not
	 *                   be 200 (OK). Must not be {@code null}.
	 *
	 * @return The CIBA error response.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static CIBAErrorResponse parse(final JSONObject jsonObject)
		throws ParseException {

		// No error code?
		if (! jsonObject.containsKey("error"))
			return new CIBAErrorResponse();

		return new CIBAErrorResponse(ErrorObject.parse(jsonObject));
	}
	

	/**
	 * Parses a CIBA error response from the specified HTTP response.
	 *
	 * @param httpResponse The HTTP response to parse. Its status code must
	 *                     not be 200 (OK). Must not be {@code null}.
	 *
	 * @return The CIBA error response.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static CIBAErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		httpResponse.ensureStatusCodeNotOK();
		return new CIBAErrorResponse(ErrorObject.parse(httpResponse));
	}
}
