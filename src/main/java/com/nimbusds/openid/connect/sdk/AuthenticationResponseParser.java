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

package com.nimbusds.openid.connect.sdk;


import java.net.URI;
import java.util.List;
import java.util.Map;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.jarm.JARMUtils;
import com.nimbusds.oauth2.sdk.jarm.JARMValidator;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URIUtils;


/**
 * Parser of OpenID Connect authentication response messages.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 *     <li>OAuth 2.0 (RFC 6749)
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices 1.0
 *     <li>OAuth 2.0 Form Post Response Mode 1.0
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM)
 * </ul>
 */
public class AuthenticationResponseParser {


	/**
	 * Parses an OpenID Connect authentication response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param params      The response parameters to parse. Must not be 
	 *                    {@code null}.
	 *
	 * @return The OpenID Connect authentication success or error response.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        OpenID Connect authentication response.
	 */
	public static AuthenticationResponse parse(final URI redirectURI,
						   final Map<String,List<String>> params)
		throws ParseException {
		
		return parse(redirectURI, params, null);
	}


	/**
	 * Parses an OpenID Connect authentication response which may be
	 * JSON Web Token (JWT) secured.
	 *
	 * @param redirectURI   The base redirection URI. Must not be
	 *                      {@code null}.
	 * @param params        The response parameters to parse. Must not be
	 *                      {@code null}.
	 * @param jarmValidator The validator of JSON Web Token (JWT) secured
	 *                      authorisation responses (JARM), {@code null} if
	 *                      a plain response is expected.
	 *
	 * @return The OpenID Connect authentication success or error response.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        OpenID Connect authentication response, or if
	 *                        validation of the JWT response failed.
	 */
	public static AuthenticationResponse parse(final URI redirectURI,
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
			return AuthenticationErrorResponse.parse(redirectURI, workParams);
		} else if (StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(workParams, "response"))) {
			// JARM that wasn't validated, peek into JWT if signed only
			boolean likelyError = JARMUtils.impliesAuthorizationErrorResponse(jwtResponseString);
			if (likelyError) {
				return AuthenticationErrorResponse.parse(redirectURI, workParams);
			} else {
				return AuthenticationSuccessResponse.parse(redirectURI, workParams);
			}
			
		} else {
			return AuthenticationSuccessResponse.parse(redirectURI, workParams);
		}
	}


	/**
	 * Parses an OpenID Connect authentication response.
	 *
	 * <p>Use a relative URI if the host, port and path details are not
	 * known:
	 *
	 * <pre>
	 * URI relUrl = new URI("https:///?code=Qcb0Orv1...&amp;state=af0ifjsldkj");
	 * </pre>
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
	 * </pre>
	 *
	 * @param uri The URI to parse. Can be absolute or relative, with a
	 *            fragment or query string containing the authentication
	 *            response parameters. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authentication success or error response.
	 *
	 * @throws ParseException If the redirection URI couldn't be parsed to
	 *                        an OpenID Connect authentication response.
	 */
	public static AuthenticationResponse parse(final URI uri)
		throws ParseException {

		return parse(URIUtils.getBaseURI(uri), AuthorizationResponse.parseResponseParameters(uri));
	}


	/**
	 * Parses and validates a JSON Web Token (JWT) secured OpenID Connect
	 * authentication response.
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
	 *                      authentication response parameters. Must not be
	 *                      {@code null}.
	 * @param jarmValidator The validator of JSON Web Token (JWT) secured
	 *                      authorisation responses (JARM). Must not be
	 *                      {@code null}.
	 *
	 * @return The OpenID Connect authentication success or error response.
	 *
	 * @throws ParseException If the redirection URI couldn't be parsed to
	 *                        an OpenID Connect authentication response or
	 *                        if validation of the JWT response failed.
	 */
	public static AuthenticationResponse parse(final URI uri,
						   final JARMValidator jarmValidator)
		throws ParseException {
		
		if (jarmValidator == null) {
			throw new IllegalArgumentException("The JARM validator must not be null");
		}

		return parse(URIUtils.getBaseURI(uri), AuthorizationResponse.parseResponseParameters(uri), jarmValidator);
	}
	
	
	/**
	 * Parses an OpenID Connect authentication response from the specified
	 * initial HTTP 302 redirect response output at the authorisation
	 * endpoint.
	 *
	 * <p>Example HTTP response (authorisation success):
	 *
	 * <pre>
	 * HTTP/1.1 302 Found
	 * Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
	 * </pre>
	 *
	 * @param httpResponse The HTTP response to parse. Must not be
	 *                     {@code null}.
	 *
	 * @return The OpenID Connect authentication response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an
	 *                        OpenID Connect authentication response.
	 */
	public static AuthenticationResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		URI location = httpResponse.getLocation();
		
		if (location == null)
			throw new ParseException("Missing redirection URI / HTTP Location header");

		return parse(location);
	}
	
	
	/**
	 * Parses and validates a JSON Web Token (JWT) secured OpenID Connect
	 * authentication response from the specified initial HTTP 302 redirect
	 * response output at the authorisation endpoint.
	 *
	 * <p>Example HTTP response (authorisation success):
	 *
	 * <pre>
	 * HTTP/1.1 302 Found
	 * Location: https://client.example.com/cb?response=eyJhbGciOiJSUzI1...
	 * </pre>
	 *
	 * @param httpResponse  The HTTP response to parse. Must not be
	 *                      {@code null}.
	 * @param jarmValidator The validator of JSON Web Token (JWT) secured
	 *                      authorisation responses (JARM). Must not be
	 *                      {@code null}.
	 *
	 * @return The OpenID Connect authentication response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an
	 *                        OpenID Connect authentication response or if
	 *                        validation of the JWT response failed.
	 */
	public static AuthenticationResponse parse(final HTTPResponse httpResponse,
						   final JARMValidator jarmValidator)
		throws ParseException {

		URI location = httpResponse.getLocation();
		
		if (location == null)
			throw new ParseException("Missing redirection URI / HTTP Location header");

		return parse(location, jarmValidator);
	}
	
	
	/**
	 * Parses an OpenID Connect authentication response from the specified
	 * HTTP request at the client redirection (callback) URI. Applies to
	 * the {@code query}, {@code fragment} and {@code form_post} response
	 * modes.
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
	 * @return The OpenID Connect authentication response.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an
	 *                        OpenID Connect authentication response.
	 */
	public static AuthenticationResponse parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		return parse(httpRequest.getURI(), AuthorizationResponse.parseResponseParameters(httpRequest));
	}
	
	
	/**
	 * Parses and validates a JSON Web Token (JWT) secured OpenID Connect
	 * authentication response from the specified HTTP request at the
	 * client redirection (callback) URI. Applies to the {@code query.jwt},
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
	 * @return The OpenID Connect authentication response.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an
	 *                        OpenID Connect authentication response or if
	 *                        validation of the JWT response failed.
	 */
	public static AuthenticationResponse parse(final HTTPRequest httpRequest,
						   final JARMValidator jarmValidator)
		throws ParseException {
		
		if (jarmValidator == null) {
			throw new IllegalArgumentException("The JARM validator must not be null");
		}
		
		return parse(httpRequest.getURI(), AuthorizationResponse.parseResponseParameters(httpRequest), jarmValidator);
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private AuthenticationResponseParser() { }
}
