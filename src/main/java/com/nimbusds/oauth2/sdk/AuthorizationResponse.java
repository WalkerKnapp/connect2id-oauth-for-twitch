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


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.jarm.JARMUtils;
import com.nimbusds.oauth2.sdk.jarm.JARMValidator;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;


/**
 * The base abstract class for authorisation success and error responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 3.1
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices 1.0
 *     <li>OAuth 2.0 Form Post Response Mode 1.0
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM)
 *     <li>OAuth 2.0 Authorization Server Issuer Identification (RFC 9207)
 * </ul>
 */
public abstract class AuthorizationResponse implements Response {


	/**
	 * The base redirection URI.
	 */
	private final URI redirectURI;


	/**
	 * The optional state parameter to be echoed back to the client.
	 */
	private final State state;
	
	
	/**
	 * Optional issuer.
	 */
	private final Issuer issuer;
	
	
	/**
	 * For a JWT-secured response.
	 */
	private final JWT jwtResponse;


	/**
	 * The optional explicit response mode.
	 */
	private final ResponseMode rm;


	/**
	 * Creates a new authorisation response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param state       The state, {@code null} if not requested.
	 * @param issuer      The issuer, {@code null} if not specified.
	 * @param rm          The response mode, {@code null} if not specified.
	 */
	protected AuthorizationResponse(final URI redirectURI,
					final State state,
					final Issuer issuer,
					final ResponseMode rm) {

		if (redirectURI == null) {
			throw new IllegalArgumentException("The redirection URI must not be null");
		}

		this.redirectURI = redirectURI;
		
		jwtResponse = null;

		this.state = state;
		
		this.issuer = issuer;

		this.rm = rm;
	}


	/**
	 * Creates a new JSON Web Token (JWT) secured authorisation response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param jwtResponse The JWT response. Must not be {@code null}.
	 * @param rm          The response mode, {@code null} if not specified.
	 */
	protected AuthorizationResponse(final URI redirectURI, final JWT jwtResponse, final ResponseMode rm) {

		if (redirectURI == null) {
			throw new IllegalArgumentException("The redirection URI must not be null");
		}

		this.redirectURI = redirectURI;

		if (jwtResponse == null) {
			throw new IllegalArgumentException("The JWT response must not be null");
		}
		
		this.jwtResponse = jwtResponse;
		
		this.state = null;
		
		this.issuer = null;

		this.rm = rm;
	}


	/**
	 * Returns the base redirection URI.
	 *
	 * @return The base redirection URI (without the appended error
	 *         response parameters).
	 */
	public URI getRedirectionURI() {

		return redirectURI;
	}


	/**
	 * Returns the optional state.
	 *
	 * @return The state, {@code null} if not requested or if the response
	 *         is JWT-secured in which case the state parameter may be
	 *         included as a JWT claim.
	 */
	public State getState() {

		return state;
	}
	
	
	/**
	 * Returns the optional issuer.
	 *
	 * @return The issuer, {@code null} if not specified.
	 */
	public Issuer getIssuer() {
		
		return issuer;
	}
	
	
	/**
	 * Returns the JSON Web Token (JWT) secured response.
	 *
	 * @return The JWT-secured response, {@code null} for a regular
	 *         authorisation response.
	 */
	public JWT getJWTResponse() {
		
		return jwtResponse;
	}
	
	
	/**
	 * Returns the optional explicit response mode.
	 *
	 * @return The response mode, {@code null} if not specified.
	 */
	public ResponseMode getResponseMode() {

		return rm;
	}


	/**
	 * Determines the implied response mode.
	 *
	 * @return The implied response mode.
	 */
	public abstract ResponseMode impliedResponseMode();


	/**
	 * Returns the parameters of this authorisation response.
	 *
	 * <p>Example parameters (authorisation success):
	 *
	 * <pre>
	 * access_token = 2YotnFZFEjr1zCsicMWpAA
	 * state = xyz
	 * token_type = example
	 * expires_in = 3600
	 * </pre>
	 *
	 * @return The parameters as a map.
	 */
	public abstract Map<String,List<String>> toParameters();


	/**
	 * Returns a URI representation (redirection URI + fragment / query
	 * string) of this authorisation response.
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
	 * &amp;state=xyz
	 * &amp;token_type=example
	 * &amp;expires_in=3600
	 * </pre>
	 *
	 * @return A URI representation of this authorisation response.
	 */
	public URI toURI() {

		final ResponseMode rm = impliedResponseMode();

		StringBuilder sb = new StringBuilder(getRedirectionURI().toString());

		String serializedParameters = URLUtils.serializeParameters(toParameters());
		
		if (StringUtils.isNotBlank(serializedParameters)) {
			
			if (ResponseMode.QUERY.equals(rm) || ResponseMode.QUERY_JWT.equals(rm)) {
				if (getRedirectionURI().toString().endsWith("?")) {
					// '?' present
				} else if (StringUtils.isBlank(getRedirectionURI().getRawQuery())) {
					sb.append('?');
				} else {
					// The original redirect_uri may contain query params,
					// see http://tools.ietf.org/html/rfc6749#section-3.1.2
					sb.append('&');
				}
			} else if (ResponseMode.FRAGMENT.equals(rm) || ResponseMode.FRAGMENT_JWT.equals(rm)) {
				sb.append('#');
			} else {
				throw new SerializeException("The (implied) response mode must be query or fragment");
			}
			
			sb.append(serializedParameters);
		}

		try {
			return new URI(sb.toString());
		} catch (URISyntaxException e) {
			throw new SerializeException("Couldn't serialize response: " + e.getMessage(), e);
		}
	}


	/**
	 * Returns an HTTP response for this authorisation response. Applies to
	 * the {@code query} or {@code fragment} response mode using HTTP 302
	 * redirection.
	 *
	 * <p>Example HTTP response (authorisation success):
	 *
	 * <pre>
	 * HTTP/1.1 302 Found
	 * Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
	 * &amp;state=xyz
	 * &amp;token_type=example
	 * &amp;expires_in=3600
	 * </pre>
	 *
	 * @see #toHTTPRequest()
	 *
	 * @return An HTTP response for this authorisation response.
	 */
	@Override
	public HTTPResponse toHTTPResponse() {

		if (ResponseMode.FORM_POST.equals(rm)) {
			throw new SerializeException("The response mode must not be form_post");
		}

		HTTPResponse response= new HTTPResponse(HTTPResponse.SC_FOUND);
		response.setLocation(toURI());
		return response;
	}


	/**
	 * Returns an HTTP request for this authorisation response. Applies to
	 * the {@code form_post} response mode.
	 *
	 * <p>Example HTTP request (authorisation success):
	 *
	 * <pre>
	 * GET /cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz HTTP/1.1
	 * Host: client.example.com
	 * </pre>
	 *
	 * @see #toHTTPResponse()
	 *
	 * @return An HTTP request for this authorisation response.
	 */
	public HTTPRequest toHTTPRequest() {

		if (! ResponseMode.FORM_POST.equals(rm) && ! ResponseMode.FORM_POST_JWT.equals(rm)) {
			throw new SerializeException("The response mode must be form_post or form_post.jwt");
		}

		// Use HTTP POST
		HTTPRequest request = new HTTPRequest(HTTPRequest.Method.POST, getRedirectionURI());
		request.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		request.appendQueryParameters(toParameters());
		return request;
	}
	
	
	/**
	 * Casts this response to an authorisation success response.
	 *
	 * @return The authorisation success response.
	 */
	public AuthorizationSuccessResponse toSuccessResponse() {
		
		return (AuthorizationSuccessResponse) this;
	}
	
	
	/**
	 * Casts this response to an authorisation error response.
	 *
	 * @return The authorisation error response.
	 */
	public AuthorizationErrorResponse toErrorResponse() {
		
		return (AuthorizationErrorResponse) this;
	}


	/**
	 * Parses an authorisation response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param params      The response parameters to parse. Must not be
	 *                    {@code null}.
	 *
	 * @return The authorisation success or error response.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        authorisation success or error response.
	 */
	public static AuthorizationResponse parse(final URI redirectURI, final Map<String,List<String>> params)
		throws ParseException {

		return parse(redirectURI, params, null);
	}


	/**
	 * Parses an authorisation response which may be JSON Web Token (JWT)
	 * secured.
	 *
	 * @param redirectURI   The base redirection URI. Must not be
	 *                      {@code null}.
	 * @param params        The response parameters to parse. Must not be
	 *                      {@code null}.
	 * @param jarmValidator The validator of JSON Web Token (JWT) secured
	 *                      authorisation responses (JARM), {@code null} if
	 *                      a plain response is expected.
	 *
	 * @return The authorisation success or error response.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        authorisation success or error response, or
	 *                        if validation of the JWT secured response
	 *                        failed.
	 */
	public static AuthorizationResponse parse(final URI redirectURI,
						  final Map<String,List<String>> params,
						  final JARMValidator jarmValidator)
		throws ParseException {
		
		Map<String,List<String>> workParams = params;
		
		String jwtResponseString = MultivaluedMapUtils.getFirstValue(params, "response");
		
		if (jarmValidator != null) {
			if (StringUtils.isBlank(jwtResponseString)) {
				throw new ParseException("Missing JWT-secured (JARM) authorization response parameter");
			}
			try {
				JWTClaimsSet jwtClaimsSet = jarmValidator.validate(jwtResponseString);
				workParams = JARMUtils.toMultiValuedStringParameters(jwtClaimsSet);
			} catch (Exception e) {
				throw new ParseException("Invalid JWT-secured (JARM) authorization response: " + e.getMessage());
			}
		}

		if (StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(workParams, "error"))) {
			return AuthorizationErrorResponse.parse(redirectURI, workParams);
		} else if (StringUtils.isNotBlank(jwtResponseString)) {
			// JARM that wasn't validated, peek into JWT if signed only
			boolean likelyError = JARMUtils.impliesAuthorizationErrorResponse(jwtResponseString);
			if (likelyError) {
				return AuthorizationErrorResponse.parse(redirectURI, workParams);
			} else {
				return AuthorizationSuccessResponse.parse(redirectURI, workParams);
			}
			
		} else {
			return AuthorizationSuccessResponse.parse(redirectURI, workParams);
		}
	}


	/**
	 * Parses an authorisation response.
	 *
	 * <p>Use a relative URI if the host, port and path details are not
	 * known:
	 *
	 * <pre>
	 * URI relUrl = new URI("https:///?code=Qcb0Orv1...&amp;state=af0ifjsldkj");
	 * </pre>
	 *
	 * @param uri The URI to parse. Can be absolute or relative, with a
	 *            fragment or query string containing the authorisation
	 *            response parameters. Must not be {@code null}.
	 *
	 * @return The authorisation success or error response.
	 *
	 * @throws ParseException If no authorisation response parameters were
	 *                        found in the URL.
	 */
	public static AuthorizationResponse parse(final URI uri)
		throws ParseException {

		return parse(URIUtils.getBaseURI(uri), parseResponseParameters(uri));
	}


	/**
	 * Parses and validates a JSON Web Token (JWT) secured authorisation
	 * response.
	 *
	 * <p>Use a relative URI if the host, port and path details are not
	 * known:
	 *
	 * <pre>
	 * URI relUrl = new URI("https:///?response=eyJhbGciOiJSUzI1NiIsI...");
	 * </pre>
	 *
	 * @param uri           The URI to parse. Can be absolute or relative,
	 *                      with a fragment or query string containing the
	 *                      authorisation response parameters. Must not be
	 *                      {@code null}.
	 * @param jarmValidator The validator of JSON Web Token (JWT) secured
	 *                      authorisation responses (JARM). Must not be
	 *                      {@code null}.
	 *
	 * @return The authorisation success or error response.
	 *
	 * @throws ParseException If no authorisation response parameters were
	 *                        found in the URL of if validation of the JWT
	 *                        response failed.
	 */
	public static AuthorizationResponse parse(final URI uri, final JARMValidator jarmValidator)
		throws ParseException {
		
		if (jarmValidator == null) {
			throw new IllegalArgumentException("The JARM validator must not be null");
		}

		return parse(URIUtils.getBaseURI(uri), parseResponseParameters(uri), jarmValidator);
	}


	/**
	 * Parses an authorisation response from the specified initial HTTP 302
	 * redirect response output at the authorisation endpoint.
	 *
	 * <p>Example HTTP response (authorisation success):
	 *
	 * <pre>
	 * HTTP/1.1 302 Found
	 * Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
	 * </pre>
	 *
	 * @see #parse(HTTPRequest)
	 *
	 * @param httpResponse The HTTP response to parse. Must not be
	 *                     {@code null}.
	 *
	 * @return The authorisation response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an
	 *                        authorisation response.
	 */
	public static AuthorizationResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		URI location = httpResponse.getLocation();

		if (location == null) {
			throw new ParseException("Missing redirection URI / HTTP Location header");
		}

		return parse(location);
	}


	/**
	 * Parses and validates a JSON Web Token (JWT) secured authorisation
	 * response from the specified initial HTTP 302 redirect response
	 * output at the authorisation endpoint.
	 *
	 * <p>Example HTTP response (authorisation success):
	 *
	 * <pre>
	 * HTTP/1.1 302 Found
	 * Location: https://client.example.com/cb?response=eyJhbGciOiJSUzI1...
	 * </pre>
	 *
	 * @see #parse(HTTPRequest)
	 *
	 * @param httpResponse  The HTTP response to parse. Must not be
	 *                      {@code null}.
	 * @param jarmValidator The validator of JSON Web Token (JWT) secured
	 *                      authorisation responses (JARM). Must not be
	 *                      {@code null}.
	 *
	 * @return The authorisation response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an
	 *                        authorisation response or if validation of
	 *                        the JWT response failed.
	 */
	public static AuthorizationResponse parse(final HTTPResponse httpResponse,
						  final JARMValidator jarmValidator)
		throws ParseException {

		URI location = httpResponse.getLocation();

		if (location == null) {
			throw new ParseException("Missing redirection URI / HTTP Location header");
		}

		return parse(location, jarmValidator);
	}


	/**
	 * Parses an authorisation response from the specified HTTP request at
	 * the client redirection (callback) URI. Applies to the {@code query},
	 * {@code fragment} and {@code form_post} response modes.
	 *
	 * <p>Example HTTP request (authorisation success):
	 *
	 * <pre>
	 * GET /cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz HTTP/1.1
	 * Host: client.example.com
	 * </pre>
	 *
	 * @see #parse(HTTPResponse)
	 *
	 * @param httpRequest The HTTP request to parse. Must not be
	 *                    {@code null}.
	 *
	 * @return The authorisation response.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an
	 *                        authorisation response.
	 */
	public static AuthorizationResponse parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		return parse(httpRequest.getURI(), parseResponseParameters(httpRequest));
	}


	/**
	 * Parses and validates a JSON Web Token (JWT) secured authorisation
	 * response from the specified HTTP request at the client redirection
	 * (callback) URI. Applies to the {@code query.jwt},
	 * {@code fragment.jwt} and {@code form_post.jwt} response modes.
	 *
	 * <p>Example HTTP request (authorisation success):
	 *
	 * <pre>
	 * GET /cb?response=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... HTTP/1.1
	 * Host: client.example.com
	 * </pre>
	 *
	 * @see #parse(HTTPResponse)
	 *
	 * @param httpRequest   The HTTP request to parse. Must not be
	 *                      {@code null}.
	 * @param jarmValidator The validator of JSON Web Token (JWT) secured
	 *                      authorisation responses (JARM). Must not be
	 *                      {@code null}.
	 *
	 * @return The authorisation response.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an
	 *                        authorisation response or if validation of
	 *                        the JWT response failed.
	 */
	public static AuthorizationResponse parse(final HTTPRequest httpRequest,
						  final JARMValidator jarmValidator)
		throws ParseException {
		
		if (jarmValidator == null) {
			throw new IllegalArgumentException("The JARM validator must not be null");
		}

		return parse(httpRequest.getURI(), parseResponseParameters(httpRequest), jarmValidator);
	}
	
	
	/**
	 * Parses the relevant authorisation response parameters. This method
	 * is intended for internal SDK usage only.
	 *
	 * @param uri The URI to parse its query or fragment parameters. Must
	 *            not be {@code null}.
	 *
	 * @return The authorisation response parameters.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static Map<String,List<String>> parseResponseParameters(final URI uri)
		throws ParseException {
		
		if (uri.getRawFragment() != null) {
			return URLUtils.parseParameters(uri.getRawFragment());
		} else if (uri.getRawQuery() != null) {
			return URLUtils.parseParameters(uri.getRawQuery());
		} else {
			throw new ParseException("Missing URI fragment or query string");
		}
	}
	
	
	/**
	 * Parses the relevant authorisation response parameters. This method
	 * is intended for internal SDK usage only.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The authorisation response parameters.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static Map<String,List<String>> parseResponseParameters(final HTTPRequest httpRequest)
		throws ParseException {
		
		if (httpRequest.getQuery() != null) {
			// For query string and form_post response mode
			return URLUtils.parseParameters(httpRequest.getQuery());
		} else if (httpRequest.getFragment() != null) {
			// For fragment response mode (never available in actual HTTP request from browser)
			return URLUtils.parseParameters(httpRequest.getFragment());
		} else {
			throw new ParseException("Missing URI fragment, query string or post body");
		}
	}
}