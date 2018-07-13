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
import java.util.Map;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Parser of OpenID Connect authentication response messages.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, sections 3.1.2.5. and 3.1.2.6.
 *     <li>OAuth 2.0 (RFC 6749), section 3.1.
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices 1.0.
 *     <li>OAuth 2.0 Form Post Response Mode 1.0.
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
						   final Map<String,String> params)
		throws ParseException {

		if (params.containsKey("error"))
			return AuthenticationErrorResponse.parse(redirectURI, params);
		else
			return AuthenticationSuccessResponse.parse(redirectURI, params);
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

		String paramString;
		
		if (uri.getRawQuery() != null) {

			paramString = uri.getRawQuery();

		} else if (uri.getRawFragment() != null) {

			paramString = uri.getRawFragment();

		} else {

			throw new ParseException("Missing authorization response parameters");
		}
		
		Map<String,String> params = URLUtils.parseParameters(paramString);

		if (params == null)
			throw new ParseException("Missing or invalid authorization response parameters");

		return parse(URIUtils.getBaseURI(uri), params);
	}


	/**
	 * Parses an OpenID Connect authentication response.
	 *
	 * <p>Example HTTP response:
	 *
	 * <pre>
	 * HTTP/1.1 302 Found
	 * Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
	 * </pre>
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @return The OpenID Connect authentication success or error response.
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
	 * Prevents public instantiation.
	 */
	private AuthenticationResponseParser() { }
}
