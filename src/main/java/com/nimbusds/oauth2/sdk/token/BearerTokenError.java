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

package com.nimbusds.oauth2.sdk.token;


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import net.jcip.annotations.Immutable;

import java.net.URI;


/**
 * OAuth 2.0 bearer token error. Used to indicate that access to a resource 
 * protected by a Bearer access token is denied, due to the request or token 
 * being invalid, or due to the access token having insufficient scope.
 *
 * <p>Standard bearer access token errors:
 *
 * <ul>
 *     <li>{@link #MISSING_TOKEN}
 *     <li>{@link #INVALID_REQUEST}
 *     <li>{@link #INVALID_TOKEN}
 *     <li>{@link #INSUFFICIENT_SCOPE}
 * </ul>
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 401 Unauthorized
 * WWW-Authenticate: Bearer realm="example.com",
 *                   error="invalid_token",
 *                   error_description="The access token expired"
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Bearer Token Usage (RFC 6750)
 *     <li>Hypertext Transfer Protocol (HTTP/1.1): Authentication (RFC 7235)
 * </ul>
 */
@Immutable
public class BearerTokenError extends TokenSchemeError {
	
	
	private static final long serialVersionUID = -5209789923955060584L;
	
	/**
	 * The request does not contain an access token. No error code or
	 * description is specified for this error, just the HTTP status code
	 * is set to 401 (Unauthorized).
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * HTTP/1.1 401 Unauthorized
	 * WWW-Authenticate: Bearer
	 * </pre>
	 */
	public static final BearerTokenError MISSING_TOKEN =
		new BearerTokenError(null, null, HTTPResponse.SC_UNAUTHORIZED);
	
	
	/**
	 * The request is missing a required parameter, includes an unsupported
	 * parameter or parameter value, repeats the same parameter, uses more
	 * than one method for including an access token, or is otherwise
	 * malformed. The HTTP status code is set to 400 (Bad Request).
	 */
	public static final BearerTokenError INVALID_REQUEST =
		new BearerTokenError("invalid_request", "Invalid request",
			             HTTPResponse.SC_BAD_REQUEST);
	
	
	/**
	 * The access token provided is expired, revoked, malformed, or invalid
	 * for other reasons.  The HTTP status code is set to 401
	 * (Unauthorized).
	 */
	public static final BearerTokenError INVALID_TOKEN =
		new BearerTokenError("invalid_token", "Invalid access token",
			             HTTPResponse.SC_UNAUTHORIZED);
	
	
	/**
	 * The request requires higher privileges than provided by the access
	 * token. The HTTP status code is set to 403 (Forbidden).
	 */
	public static final BearerTokenError INSUFFICIENT_SCOPE =
		new BearerTokenError("insufficient_scope", "Insufficient scope",
			             HTTPResponse.SC_FORBIDDEN);
	
	
	/**
	 * Creates a new OAuth 2.0 bearer token error with the specified code
	 * and description.
	 *
	 * @param code        The error code, {@code null} if not specified.
	 * @param description The error description, {@code null} if not
	 *                    specified.
	 */
	public BearerTokenError(final String code, final String description) {
	
		this(code, description, 0, null, null, null);
	}


	/**
	 * Creates a new OAuth 2.0 bearer token error with the specified code,
	 * description and HTTP status code.
	 *
	 * @param code           The error code, {@code null} if not specified.
	 * @param description    The error description, {@code null} if not
	 *                       specified.
	 * @param httpStatusCode The HTTP status code, zero if not specified.
	 */
	public BearerTokenError(final String code, final String description, final int httpStatusCode) {
	
		this(code, description, httpStatusCode, null, null, null);
	}


	/**
	 * Creates a new OAuth 2.0 bearer token error with the specified code,
	 * description, HTTP status code, page URI, realm and scope.
	 *
	 * @param code           The error code, {@code null} if not specified.
	 * @param description    The error description, {@code null} if not
	 *                       specified.
	 * @param httpStatusCode The HTTP status code, zero if not specified.
	 * @param uri            The error page URI, {@code null} if not
	 *                       specified.
	 * @param realm          The realm, {@code null} if not specified.
	 * @param scope          The required scope, {@code null} if not 
	 *                       specified.
	 */
	public BearerTokenError(final String code, 
		                final String description, 
		                final int httpStatusCode, 
		                final URI uri,
		                final String realm,
		                final Scope scope) {
	
		super(AccessTokenType.BEARER, code, description, httpStatusCode, uri, realm, scope);
	}


	@Override
	public BearerTokenError setDescription(final String description) {

		return new BearerTokenError(super.getCode(), description, super.getHTTPStatusCode(), super.getURI(), getRealm(), getScope());
	}


	@Override
	public BearerTokenError appendDescription(final String text) {

		String newDescription;

		if (getDescription() != null)
			newDescription = getDescription() + text;
		else
			newDescription = text;

		return new BearerTokenError(super.getCode(), newDescription, super.getHTTPStatusCode(), super.getURI(), getRealm(), getScope());
	}


	@Override
	public BearerTokenError setHTTPStatusCode(final int httpStatusCode) {

		return new BearerTokenError(super.getCode(), super.getDescription(), httpStatusCode, super.getURI(), getRealm(), getScope());
	}


	@Override
	public BearerTokenError setURI(final URI uri) {

		return new BearerTokenError(super.getCode(), super.getDescription(), super.getHTTPStatusCode(), uri, getRealm(), getScope());
	}


	@Override
	public BearerTokenError setRealm(final String realm) {

		return new BearerTokenError(getCode(), 
			                    getDescription(), 
			                    getHTTPStatusCode(), 
			                    getURI(), 
			                    realm, 
			                    getScope());
	}


	@Override
	public BearerTokenError setScope(final Scope scope) {

		return new BearerTokenError(getCode(),
			                    getDescription(),
			                    getHTTPStatusCode(),
			                    getURI(),
			                    getRealm(),
			                    scope);
	}


	/**
	 * Parses an OAuth 2.0 bearer token error from the specified HTTP
	 * response {@code WWW-Authenticate} header.
	 *
	 * @param wwwAuth The {@code WWW-Authenticate} header value to parse. 
	 *                Must not be {@code null}.
	 *
	 * @return The bearer token error.
	 *
	 * @throws ParseException If the {@code WWW-Authenticate} header value 
	 *                        couldn't be parsed to a Bearer token error.
	 */
	public static BearerTokenError parse(final String wwwAuth)
		throws ParseException {
		
		TokenSchemeError genericError = TokenSchemeError.parse(wwwAuth, AccessTokenType.BEARER);
		
		return new BearerTokenError(
			genericError.getCode(),
			genericError.getDescription(),
			genericError.getHTTPStatusCode(),
			genericError.getURI(),
			genericError.getRealm(),
			genericError.getScope()
		);
	}
}
