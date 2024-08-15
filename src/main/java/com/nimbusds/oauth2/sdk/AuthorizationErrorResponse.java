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


import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import net.jcip.annotations.Immutable;

import java.net.URI;
import java.util.*;


/**
 * Authorisation error response. Intended only for errors which are allowed to
 * be communicated back to the requesting OAuth 2.0 client, such as
 * {@code access_denied}.
 *
 * <p>If the authorisation request fails due to a missing, invalid, or
 * mismatching {@code redirect_uri}, or if the {@code client_id} is missing or
 * invalid, a response <strong>must not</strong> be sent back to the requesting
 * client. Instead, the authorisation server should simply display the error
 * to the resource owner.
 *
 * <p>Standard authorisation errors:
 *
 * <ul>
 *     <li>{@link OAuth2Error#INVALID_REQUEST}
 *     <li>{@link OAuth2Error#UNAUTHORIZED_CLIENT}
 *     <li>{@link OAuth2Error#ACCESS_DENIED}
 *     <li>{@link OAuth2Error#UNSUPPORTED_RESPONSE_TYPE}
 *     <li>{@link OAuth2Error#INVALID_SCOPE}
 *     <li>{@link OAuth2Error#SERVER_ERROR}
 *     <li>{@link OAuth2Error#TEMPORARILY_UNAVAILABLE}
 * </ul>
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 302 Found
 * Location: https://client.example.com/cb?
 * error=invalid_request
 * &amp;error_description=the%20request%20is%20not%20valid%20or%20malformed
 * &amp;state=af0ifjsldkj
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749)
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices 1.0
 *     <li>OAuth 2.0 Form Post Response Mode 1.0
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM)
 *     <li>OAuth 2.0 Authorization Server Issuer Identification (RFC 9207)
 * </ul>
 */
@Immutable
public class AuthorizationErrorResponse
	extends AuthorizationResponse
	implements ErrorResponse {


	/**
	 * The standard OAuth 2.0 errors for an Authorisation error response.
	 */
	private static final Set<ErrorObject> stdErrors = new HashSet<>();
	
	
	static {
		stdErrors.add(OAuth2Error.INVALID_REQUEST);
		stdErrors.add(OAuth2Error.UNAUTHORIZED_CLIENT);
		stdErrors.add(OAuth2Error.ACCESS_DENIED);
		stdErrors.add(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE);
		stdErrors.add(OAuth2Error.INVALID_SCOPE);
		stdErrors.add(OAuth2Error.SERVER_ERROR);
		stdErrors.add(OAuth2Error.TEMPORARILY_UNAVAILABLE);
	}
	
	
	/**
	 * Gets the standard OAuth 2.0 errors for an Authorisation error 
	 * response.
	 *
	 * @return The standard errors, as a read-only set.
	 */
	public static Set<ErrorObject> getStandardErrors() {
	
		return Collections.unmodifiableSet(stdErrors);
	}
	
	
	/**
	 * The error.
	 */
	private final ErrorObject error;


	/**
	 * Creates a new authorisation error response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param error       The error. Should match one of the
	 *                    {@link #getStandardErrors standard errors} for an
	 *                    authorisation error response. Must not be
	 *                    {@code null}.
	 * @param state       The state, {@code null} if not requested.
	 * @param rm          The implied response mode, {@code null} if
	 *                    unknown.
	 */
	public AuthorizationErrorResponse(final URI redirectURI,
					  final ErrorObject error,
					  final State state,
					  final ResponseMode rm) {

		this(redirectURI, error, state, null, rm);
	}


	/**
	 * Creates a new authorisation error response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param error       The error. Should match one of the
	 *                    {@link #getStandardErrors standard errors} for an
	 *                    authorisation error response. Must not be
	 *                    {@code null}.
	 * @param state       The state, {@code null} if not requested.
	 * @param issuer      The issuer, {@code null} if not specified.
	 * @param rm          The implied response mode, {@code null} if
	 *                    unknown.
	 */
	public AuthorizationErrorResponse(final URI redirectURI,
					  final ErrorObject error,
					  final State state,
					  final Issuer issuer,
					  final ResponseMode rm) {

		super(redirectURI, state, issuer, rm);

		if (error == null)
			throw new IllegalArgumentException("The error must not be null");

		this.error = error;
	}


	/**
	 * Creates a new JSON Web Token (JWT) secured authorisation error
	 * response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param jwtResponse The JWT-secured response. Must not be
	 *                    {@code null}.
	 * @param rm          The implied response mode, {@code null} if
	 *                    unknown.
	 */
	public AuthorizationErrorResponse(final URI redirectURI,
					  final JWT jwtResponse,
					  final ResponseMode rm) {

		super(redirectURI, jwtResponse, rm);

		error = null;
	}


	@Override
	public boolean indicatesSuccess() {

		return false;
	}
	

	@Override
	public ErrorObject getErrorObject() {
	
		return error;
	}


	@Override
	public ResponseMode impliedResponseMode() {

		// Return "query" if not known, assumed the most frequent case
		return getResponseMode() != null ? getResponseMode() : ResponseMode.QUERY;
	}


	@Override
	public Map<String,List<String>> toParameters() {

		Map<String,List<String>> params = new HashMap<>();
		
		if (getJWTResponse() != null) {
			// JARM, no other top-level parameters
			params.put("response", Collections.singletonList(getJWTResponse().serialize()));
			return params;
		}

		params.putAll(getErrorObject().toParameters());

		if (getState() != null)
			params.put("state", Collections.singletonList(getState().getValue()));
		
		if (getIssuer() != null)
			params.put("iss", Collections.singletonList(getIssuer().getValue()));

		return params;
	}


	/**
	 * Parses an authorisation error response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param params      The response parameters to parse. Must not be 
	 *                    {@code null}.
	 *
	 * @return The authorisation error response.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        authorisation error response.
	 */
	public static AuthorizationErrorResponse parse(final URI redirectURI,
		                                       final Map<String,List<String>> params)
		throws ParseException {
		
		// JARM, ignore other top level params
		String responseString = MultivaluedMapUtils.getFirstValue(params, "response");
		if (responseString != null) {
			JWT jwtResponse;
			try {
				jwtResponse = JWTParser.parse(responseString);
			} catch (java.text.ParseException e) {
				throw new ParseException("Invalid JWT response: " + e.getMessage(), e);
			}
			
			return new AuthorizationErrorResponse(redirectURI, jwtResponse, ResponseMode.JWT);
		}

		// Parse the error
		ErrorObject error = ErrorObject.parse(params);
		
		if (StringUtils.isBlank(error.getCode())) {
			throw new ParseException("Missing error code");
		}
		error = error.setHTTPStatusCode(HTTPResponse.SC_FOUND); // need a status code
		
		// State
		State state = State.parse(MultivaluedMapUtils.getFirstValue(params, "state"));
		
		// Parse optional issuer, OAuth 2.0 Authorization Server Issuer Identification (RFC 9207)
		Issuer issuer = Issuer.parse(MultivaluedMapUtils.getFirstValue(params, "iss"));
		
		return new AuthorizationErrorResponse(redirectURI, error, state, issuer, null);
	}
	
	
	/**
	 * Parses an authorisation error response.
	 *
	 * <p>Use a relative URI if the host, port and path details are not
	 * known:
	 *
	 * <pre>
	 * URI relUrl = new URI("https:///?error=invalid_request");
	 * </pre>
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * https://client.example.com/cb?
	 * error=invalid_request
	 * &amp;error_description=the%20request%20is%20not%20valid%20or%20malformed
	 * &amp;state=af0ifjsldkj
	 * </pre>
	 *
	 * @param uri The URI to parse. Can be absolute or relative, with a
	 *            fragment or query string containing the authorisation
	 *            response parameters. Must not be {@code null}.
	 *
	 * @return The authorisation error response.
	 *
	 * @throws ParseException If the URI couldn't be parsed to an
	 *                        authorisation error response.
	 */
	public static AuthorizationErrorResponse parse(final URI uri)
		throws ParseException {
		
		return parse(URIUtils.getBaseURI(uri), parseResponseParameters(uri));
	}
	
	
	/**
	 * Parses an authorisation error response from the specified initial
	 * HTTP 302 redirect response generated at the authorisation endpoint.
	 *
	 * <p>Example HTTP response:
	 *
	 * <pre>
	 * HTTP/1.1 302 Found
	 * Location: https://client.example.com/cb?error=invalid_request&amp;state=af0ifjsldkj
	 * </pre>
	 *
	 * @see #parse(HTTPRequest)
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @return The authorisation error response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an 
	 *                        authorisation error response.
	 */
	public static AuthorizationErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		URI location = httpResponse.getLocation();

		if (location == null) {
			throw new ParseException("Missing redirection URL / HTTP Location header");
		}

		return parse(location);
	}


	/**
	 * Parses an authorisation error response from the specified HTTP
	 * request at the client redirection (callback) URI. Applies to
	 * {@code query}, {@code fragment} and {@code form_post} response
	 * modes.
	 *
	 * <p>Example HTTP request (authorisation success):
	 *
	 * <pre>
	 * GET /cb?error=invalid_request&amp;state=af0ifjsldkj HTTP/1.1
	 * Host: client.example.com
	 * </pre>
	 *
	 * @see #parse(HTTPResponse)
	 *
	 * @param httpRequest The HTTP request to parse. Must not be
	 *                    {@code null}.
	 *
	 * @return The authorisation error response.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an
	 *                        authorisation error response.
	 */
	public static AuthorizationErrorResponse parse(final HTTPRequest httpRequest)
		throws ParseException {

		return parse(URIUtils.getBaseURI(httpRequest.getURI()), parseResponseParameters(httpRequest));
	}
}
