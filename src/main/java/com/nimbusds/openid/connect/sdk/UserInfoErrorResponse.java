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


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ErrorResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.token.DPoPTokenError;
import com.nimbusds.oauth2.sdk.token.TokenSchemeError;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import net.jcip.annotations.Immutable;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;


/**
 * UserInfo error response.
 *
 * <p>Standard OAuth 2.0 Bearer Token errors:
 *
 * <ul>
 *     <li>{@link com.nimbusds.oauth2.sdk.token.BearerTokenError#MISSING_TOKEN}
 *     <li>{@link com.nimbusds.oauth2.sdk.token.BearerTokenError#INVALID_REQUEST}
 *     <li>{@link com.nimbusds.oauth2.sdk.token.BearerTokenError#INVALID_TOKEN}
 *     <li>{@link com.nimbusds.oauth2.sdk.token.BearerTokenError#INSUFFICIENT_SCOPE}
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
 *     <li>OpenID Connect Core 1.0
 *     <li>OAuth 2.0 Bearer Token Usage (RFC 6750)
 *     <li>OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer
 *         (DPoP) (RFC 9449)
 * </ul>
 */
@Immutable
public class UserInfoErrorResponse
	extends UserInfoResponse
	implements ErrorResponse {


	/**
	 * Gets the standard errors for a UserInfo error response.
	 *
	 * @return The standard errors, as a read-only set.
	 */
	public static Set<BearerTokenError> getStandardErrors() {
		
		Set<BearerTokenError> stdErrors = new HashSet<>();
		stdErrors.add(BearerTokenError.MISSING_TOKEN);
		stdErrors.add(BearerTokenError.INVALID_REQUEST);
		stdErrors.add(BearerTokenError.INVALID_TOKEN);
		stdErrors.add(BearerTokenError.INSUFFICIENT_SCOPE);

		return Collections.unmodifiableSet(stdErrors);
	}


	/**
	 * The underlying error.
	 */
	private final ErrorObject error;


	/**
	 * Creates a new UserInfo error response. No OAuth 2.0 token error /
	 * general error object is specified.
	 */
	private UserInfoErrorResponse() {

		error = null;
	}
	

	/**
	 * Creates a new UserInfo error response indicating a bearer token
	 * error.
	 *
	 * @param error The OAuth 2.0 bearer token error. Should match one of 
	 *              the {@link #getStandardErrors standard errors} for a 
	 *              UserInfo error response. Must not be {@code null}.
	 */
	public UserInfoErrorResponse(final BearerTokenError error) {

		this((ErrorObject) error);
	}
	

	/**
	 * Creates a new UserInfo error response indicating a DPoP token error.
	 *
	 * @param error The OAuth 2.0 DPoP token error. Should match one of
	 *              the {@link #getStandardErrors standard errors} for a
	 *              UserInfo error response. Must not be {@code null}.
	 */
	public UserInfoErrorResponse(final DPoPTokenError error) {

		this((ErrorObject) error);
	}
	
	
	/**
	 * Creates a new UserInfo error response indicating a general error.
	 *
	 * @param error The error. Must not be {@code null}.
	 */
	public UserInfoErrorResponse(final ErrorObject error) {
		
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
	 * Returns the HTTP response for this UserInfo error response.
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
	 * @return The HTTP response matching this UserInfo error response.
	 */
	@Override
	public HTTPResponse toHTTPResponse() {

		HTTPResponse httpResponse;

		if (error != null && error.getHTTPStatusCode() > 0) {
			httpResponse = new HTTPResponse(error.getHTTPStatusCode());
		} else {
			httpResponse = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST);
		}

		// Add the WWW-Authenticate header
		if (error instanceof TokenSchemeError) {
			httpResponse.setWWWAuthenticate(((TokenSchemeError) error).toWWWAuthenticateHeader());
		} else if (error != null){
			httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
			httpResponse.setBody(error.toJSONObject().toJSONString());
		}

		return httpResponse;
	}


	/**
	 * Parses a UserInfo error response from the specified HTTP response
	 * {@code WWW-Authenticate} header.
	 *
	 * @param wwwAuth The {@code WWW-Authenticate} header value to parse. 
	 *                Must not be {@code null}.
	 *
	 * @return The UserInfo error response.
	 *
	 * @throws ParseException If the {@code WWW-Authenticate} header value 
	 *                        couldn't be parsed to a UserInfo error 
	 *                        response.
	 */
	public static UserInfoErrorResponse parse(final String wwwAuth)
		throws ParseException {

		BearerTokenError error = BearerTokenError.parse(wwwAuth);

		return new UserInfoErrorResponse(error);
	}
	
	
	/**
	 * Parses a UserInfo error response from the specified HTTP response.
	 *
	 * <p>Note: The HTTP status code is not checked for matching the error
	 * code semantics.
	 *
	 * @param httpResponse The HTTP response to parse. Its status code must
	 *                     not be 200 (OK). Must not be {@code null}.
	 *
	 * @return The UserInfo error response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a 
	 *                        UserInfo error response.
	 */
	public static UserInfoErrorResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCodeNotOK();

		String wwwAuth = httpResponse.getWWWAuthenticate();
		
		if (StringUtils.isNotBlank(wwwAuth)) {
			
			if (wwwAuth.toLowerCase().startsWith(AccessTokenType.BEARER.getValue().toLowerCase())) {
				
				// Bearer token error?
				try {
					BearerTokenError bte = BearerTokenError.parse(wwwAuth);
					
					return new UserInfoErrorResponse(
						new BearerTokenError(
							bte.getCode(),
							bte.getDescription(),
							httpResponse.getStatusCode(), // override HTTP status code
							bte.getURI(),
							bte.getRealm(),
							bte.getScope()));
				} catch (ParseException e) {
					// Ignore parse exception for WWW-auth header and continue
				}
				
			} else if (wwwAuth.toLowerCase().startsWith(AccessTokenType.DPOP.getValue().toLowerCase())) {
				
				// Bearer token error?
				try {
					DPoPTokenError dte = DPoPTokenError.parse(wwwAuth);
					
					return new UserInfoErrorResponse(
						new DPoPTokenError(
							dte.getCode(),
							dte.getDescription(),
							httpResponse.getStatusCode(), // override HTTP status code
							dte.getURI(),
							dte.getRealm(),
							dte.getScope(),
							dte.getJWSAlgorithms()));
				} catch (ParseException e) {
					// Ignore parse exception for WWW-auth header and continue
				}
			}
		}
		
		// Other error?
		return new UserInfoErrorResponse(ErrorObject.parse(httpResponse));
	}
}
