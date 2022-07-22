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

package com.nimbusds.oauth2.sdk;


import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.MapUtils;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;


/**
 * Error object, used to encapsulate OAuth 2.0 and other errors. Supports
 * custom parameters.
 *
 * <p>Example error object as HTTP response:
 *
 * <pre>
 * HTTP/1.1 400 Bad Request
 * Content-Type: application/json;charset=UTF-8
 * Cache-Control: no-store
 * Pragma: no-cache
 *
 * {
 *   "error" : "invalid_request"
 * }
 * </pre>
 */
@Immutable
public class ErrorObject implements Serializable {
	
	
	private static final long serialVersionUID = -361808781364656206L;
	
	
	/**
	 * The error code, may not always be defined.
	 */
	private final String code;


	/**
	 * Optional error description.
	 */
	private final String description;


	/**
	 * Optional HTTP status code, 0 if not specified.
	 */
	private final int httpStatusCode;


	/**
	 * Optional URI of a web page that includes additional information 
	 * about the error.
	 */
	private final URI uri;
	
	
	/**
	 * Optional custom parameters, empty or {@code null} if none.
	 */
	private final Map<String,String> customParams;


	/**
	 * Creates a new error with the specified code. The code must be within
	 * the {@link #isLegal(String) legal} character range.
	 *
	 * @param code The error code, {@code null} if not specified.
	 */
	public ErrorObject(final String code) {
	
		this(code, null, 0, null);
	}
	
	
	/**
	 * Creates a new error with the specified code and description. The
	 * code and the description must be within the {@link #isLegal(String)
	 * legal} character range.
	 *
	 * @param code        The error code, {@code null} if not specified.
	 * @param description The error description, {@code null} if not
	 *                    specified.
	 */
	public ErrorObject(final String code, final String description) {
	
		this(code, description, 0, null);
	}


	/**
	 * Creates a new error with the specified code, description and HTTP 
	 * status code. The code and the description must be within the
	 * {@link #isLegal(String) legal} character range.
	 *
	 * @param code           The error code, {@code null} if not specified.
	 * @param description    The error description, {@code null} if not
	 *                       specified.
	 * @param httpStatusCode The HTTP status code, zero if not specified.
	 */
	public ErrorObject(final String code, final String description, final int httpStatusCode) {
	
		this(code, description, httpStatusCode, null);
	}


	/**
	 * Creates a new error with the specified code, description, HTTP 
	 * status code and page URI. The code and the description must be
	 * within the {@link #isLegal(String) legal} character range.
	 *
	 * @param code           The error code, {@code null} if not specified.
	 * @param description    The error description, {@code null} if not
	 *                       specified.
	 * @param httpStatusCode The HTTP status code, zero if not specified.
	 * @param uri            The error page URI, {@code null} if not
	 *                       specified.
	 */
	public ErrorObject(final String code,
			   final String description,
		           final int httpStatusCode,
			   final URI uri) {
	
		this(code, description, httpStatusCode, uri, null);
	}


	/**
	 * Creates a new error with the specified code, description, HTTP
	 * status code and page URI. The code and the description must be
	 * within the {@link #isLegal(String) legal} character range.
	 *
	 * @param code           The error code, {@code null} if not specified.
	 * @param description    The error description, {@code null} if not
	 *                       specified.
	 * @param httpStatusCode The HTTP status code, zero if not specified.
	 * @param uri            The error page URI, {@code null} if not
	 *                       specified.
	 * @param customParams   Custom parameters, {@code null} if none.
	 */
	public ErrorObject(final String code,
			   final String description,
		           final int httpStatusCode,
			   final URI uri,
			   final Map<String,String> customParams) {
	
		if (! isLegal(code)) {
			throw new IllegalArgumentException("Illegal char(s) in code, see RFC 6749, section 5.2");
		}
		this.code = code;
		
		if (! isLegal(description)) {
			throw new IllegalArgumentException("Illegal char(s) in description, see RFC 6749, section 5.2");
		}
		this.description = description;
		
		this.httpStatusCode = httpStatusCode;
		this.uri = uri;
		
		this.customParams = customParams;
	}


	/**
	 * Returns the error code.
	 *
	 * @return The error code, {@code null} if not specified.
	 */
	public String getCode() {

		return code;
	}
	
	
	/**
	 * Returns the error description.
	 *
	 * @return The error description, {@code null} if not specified.
	 */
	public String getDescription() {
	
		return description;
	}


	/**
	 * Sets the error description.
	 *
	 * @param description The error description, {@code null} if not 
	 *                    specified.
	 *
	 * @return A copy of this error with the specified description.
	 */
	public ErrorObject setDescription(final String description) {

		return new ErrorObject(getCode(), description, getHTTPStatusCode(), getURI(), getCustomParams());
	}


	/**
	 * Appends the specified text to the error description.
	 *
	 * @param text The text to append to the error description, 
	 *             {@code null} if not specified.
	 *
	 * @return A copy of this error with the specified appended 
	 *         description.
	 */
	public ErrorObject appendDescription(final String text) {

		String newDescription;

		if (getDescription() != null)
			newDescription = getDescription() + text;
		else
			newDescription = text;

		return new ErrorObject(getCode(), newDescription, getHTTPStatusCode(), getURI(), getCustomParams());
	}


	/**
	 * Returns the HTTP status code.
	 *
	 * @return The HTTP status code, zero if not specified.
	 */
	public int getHTTPStatusCode() {

		return httpStatusCode;
	}


	/**
	 * Sets the HTTP status code.
	 *
	 * @param httpStatusCode  The HTTP status code, zero if not specified.
	 *
	 * @return A copy of this error with the specified HTTP status code.
	 */
	public ErrorObject setHTTPStatusCode(final int httpStatusCode) {

		return new ErrorObject(getCode(), getDescription(), httpStatusCode, getURI(), getCustomParams());
	}


	/**
	 * Returns the error page URI.
	 *
	 * @return The error page URI, {@code null} if not specified.
	 */
	public URI getURI() {

		return uri;
	}


	/**
	 * Sets the error page URI.
	 *
	 * @param uri The error page URI, {@code null} if not specified.
	 *
	 * @return A copy of this error with the specified page URI.
	 */
	public ErrorObject setURI(final URI uri) {

		return new ErrorObject(getCode(), getDescription(), getHTTPStatusCode(), uri, getCustomParams());
	}
	
	
	/**
	 * Returns the custom parameters.
	 *
	 * @return The custom parameters, empty map if none.
	 */
	public Map<String,String> getCustomParams() {
		if (MapUtils.isNotEmpty(customParams)) {
			return Collections.unmodifiableMap(customParams);
		} else {
			return Collections.emptyMap();
		}
	}
	
	
	/**
	 * Sets the custom parameters.
	 *
	 * @param customParams The custom parameters, {@code null} if none.
	 *
	 * @return A copy of this error with the specified custom parameters.
	 */
	public ErrorObject setCustomParams(final Map<String,String> customParams) {
		
		return new ErrorObject(getCode(), getDescription(), getHTTPStatusCode(), getURI(), customParams);
	}


	/**
	 * Returns a JSON object representation of this error object.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "error"             : "invalid_grant",
	 *   "error_description" : "Invalid resource owner credentials"
	 * }
	 * </pre>
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {

		JSONObject o = new JSONObject();

		if (getCode() != null) {
			o.put("error", getCode());
		}

		if (getDescription() != null) {
			o.put("error_description", getDescription());
		}

		if (getURI() != null) {
			o.put("error_uri", getURI().toString());
		}
		
		if (! getCustomParams().isEmpty()) {
			o.putAll(getCustomParams());
		}

		return o;
	}
	
	
	/**
	 * Returns a parameters representation of this error object. Suitable
	 * for URL-encoded error responses.
	 *
	 * @return The parameters.
	 */
	public Map<String, List<String>> toParameters() {
		
		Map<String,List<String>> params = new HashMap<>();
		
		if (getCode() != null) {
			params.put("error", Collections.singletonList(getCode()));
		}
		
		if (getDescription() != null) {
			params.put("error_description", Collections.singletonList(getDescription()));
		}
		
		if (getURI() != null) {
			params.put("error_uri", Collections.singletonList(getURI().toString()));
		}
		
		if (! getCustomParams().isEmpty()) {
			for (Map.Entry<String, String> en: getCustomParams().entrySet()) {
				params.put(en.getKey(), Collections.singletonList(en.getValue()));
			}
		}
		
		return params;
	}
	
	
	/**
	 * Returns an HTTP response for this error object. If no HTTP status
	 * code is specified it will be set to 400 (Bad Request). If an error
	 * code is specified the {@code Content-Type} header will be set to
	 * {@link ContentType#APPLICATION_JSON application/json; charset=UTF-8}
	 * and the error JSON object will be put in the entity body.
	 *
	 * @return The HTTP response.
	 */
	public HTTPResponse toHTTPResponse() {
		
		int statusCode = (getHTTPStatusCode() > 0) ? getHTTPStatusCode() : HTTPResponse.SC_BAD_REQUEST;
		HTTPResponse httpResponse = new HTTPResponse(statusCode);
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");
		
		if (getCode() != null) {
			httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
			httpResponse.setContent(toJSONObject().toJSONString());
		}
		
		return httpResponse;
	}


	/**
	 * @see #getCode
	 */
	@Override
	public String toString() {

		return code != null ? code : "null";
	}


	@Override
	public int hashCode() {

		return code != null ? code.hashCode() : "null".hashCode();
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof ErrorObject &&
		       this.toString().equals(object.toString());
	}


	/**
	 * Parses an error object from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The error object.
	 */
	public static ErrorObject parse(final JSONObject jsonObject) {

		String code = null;
		try {
			code = JSONObjectUtils.getString(jsonObject, "error", null);
		} catch (ParseException e) {
			// ignore and continue
		}
		
		if (! isLegal(code)) {
			code = null;
		}
		
		String description = null;
		try {
			description = JSONObjectUtils.getString(jsonObject, "error_description", null);
		} catch (ParseException e) {
			// ignore and continue
		}
		
		URI uri = null;
		try {
			uri = JSONObjectUtils.getURI(jsonObject, "error_uri", null);
		} catch (ParseException e) {
			// ignore and continue
		}
		
		Map<String, String> customParams = null;
		for (Map.Entry<String, Object> en: jsonObject.entrySet()) {
			if (!"error".equals(en.getKey()) && !"error_description".equals(en.getKey()) && !"error_uri".equals(en.getKey())) {
				if (en.getValue() == null || en.getValue() instanceof String) {
					if (customParams == null) {
						customParams = new HashMap<>();
					}
					customParams.put(en.getKey(), (String)en.getValue());
				}
			}
		}

		return new ErrorObject(code, removeIllegalChars(description), 0, uri, customParams);
	}
	
	
	/**
	 * Parses an error object from the specified parameters representation.
	 * Suitable for URL-encoded error responses.
	 *
	 * @param params The parameters. Must not be {@code null}.
	 *
	 * @return The error object.
	 */
	public static ErrorObject parse(final Map<String, List<String>> params) {
		
		String code = MultivaluedMapUtils.getFirstValue(params, "error");
		String description = MultivaluedMapUtils.getFirstValue(params, "error_description");
		String uriString = MultivaluedMapUtils.getFirstValue(params, "error_uri");
		
		if (! isLegal(code)) {
			code = null;
		}
		
		URI uri = null;
		if (uriString != null) {
			try {
				uri = new URI(uriString);
			} catch (URISyntaxException e) {
				// ignore
			}
		}
		
		Map<String, String> customParams = null;
		for (Map.Entry<String, List<String>> en: params.entrySet()) {
			if (!"error".equals(en.getKey()) && !"error_description".equals(en.getKey()) && !"error_uri".equals(en.getKey())) {
			
				if (customParams == null) {
					customParams = new HashMap<>();
				}
				
				if (en.getValue() == null) {
					customParams.put(en.getKey(), null);
				} else if (! en.getValue().isEmpty()) {
					customParams.put(en.getKey(), en.getValue().get(0));
				}
			}
		}
		
		return new ErrorObject(code, removeIllegalChars(description), 0, uri, customParams);
	}


	/**
	 * Parses an error object from the specified HTTP response.
	 *
	 * @param httpResponse The HTTP response to parse. Must not be
	 *                     {@code null}.
	 *
	 * @return The error object.
	 */
	public static ErrorObject parse(final HTTPResponse httpResponse) {

		JSONObject jsonObject;
		try {
			jsonObject = httpResponse.getContentAsJSONObject();
		} catch (ParseException e) {
			return new ErrorObject(null, null, httpResponse.getStatusCode());
		}

		ErrorObject intermediary = parse(jsonObject);

		return new ErrorObject(
			intermediary.getCode(),
			intermediary.description,
			httpResponse.getStatusCode(),
			intermediary.getURI(),
			intermediary.getCustomParams());
	}
	
	
	/**
	 * Removes any characters from the specified string that are not
	 * within the {@link #isLegal(char) legal range} for OAuth 2.0 error
	 * codes and messages.
	 *
	 * <p>See RFC 6749, section 5.2.
	 *
	 * @param s The string to check. May be {@code null}.
	 *
	 * @return The string with removed illegal characters, {@code null} if
	 *         the original string was {@code null}.
	 */
	public static String removeIllegalChars(final String s) {
		
		if (s == null) {
			return null;
		}
		
		StringBuilder sb = new StringBuilder();
		
		for (char c: s.toCharArray()) {
			if (isLegal(c)) {
				sb.append(c);
			}
		}
		
		return sb.toString();
	}
	
	
	/**
	 * Returns {@code true} if the characters in the specified string are
	 * within the {@link #isLegal(char) legal ranges} for OAuth 2.0 error
	 * codes and messages.
	 *
	 * <p>See RFC 6749, section 5.2.
	 *
	 * @param s The string to check. May be {@code null}.
	 *
	 * @return {@code true} if the string is legal, else {@code false}.
	 */
	public static boolean isLegal(final String s) {
	
		if (s == null) {
			return true;
		}
		
		for (char c: s.toCharArray()) {
			if (! isLegal(c)) {
				return false;
			}
		}
		
		return true;
	}
	
	
	/**
	 * Returns {@code true} if the specified char is within the legal
	 * ranges [0x20, 0x21] | [0x23 - 0x5B] | [0x5D - 0x7E] for OAuth 2.0
	 * error codes and messages.
	 *
	 * <p>See RFC 6749, section 5.2.
	 *
	 * @param c The character to check. Must not be {@code null}.
	 *
	 * @return {@code true} if the character is legal, else {@code false}.
	 */
	public static boolean isLegal(final char c) {
		
		// https://tools.ietf.org/html/rfc6749#section-5.2
		//
		// Values for the "error" parameter MUST NOT include characters outside the
		// set %x20-21 / %x23-5B / %x5D-7E.
		//
		// Values for the "error_description" parameter MUST NOT include characters
		// outside the set %x20-21 / %x23-5B / %x5D-7E.
		
		if (c > 0x7f) {
			// Not ASCII
			return false;
		}
		
		return c >= 0x20 && c <= 0x21 || c >= 0x23 && c <=0x5b || c >= 0x5d && c <= 0x7e;
	}
}
