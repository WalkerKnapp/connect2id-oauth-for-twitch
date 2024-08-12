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
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.*;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import net.jcip.annotations.Immutable;

import java.net.URI;
import java.util.*;


/**
 * Token revocation request. Used to revoke an issued access or refresh token.
 *
 * <p>Example token revocation request for a confidential client:
 *
 * <pre>
 * POST /revoke HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
 *
 * token=45ghiukldjahdnhzdauz&amp;token_type_hint=refresh_token
 * </pre>
 *
 * <p>Example token revocation request for a public client:
 *
 * <pre>
 * POST /revoke HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 *
 * token=45ghiukldjahdnhzdauz&amp;token_type_hint=refresh_token&amp;client_id=123456
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Token Revocation (RFC 7009), section 2.1.
 * </ul>
 */
@Immutable
public final class TokenRevocationRequest extends AbstractOptionallyIdentifiedRequest {


	/**
	 * The token to revoke.
	 */
	private final Token token;


	/**
	 * Creates a new token revocation request for a confidential client.
	 *
	 * @param endpoint   The URI of the token revocation endpoint. May be
	 *                   {@code null} if the {@link #toHTTPRequest} method
	 *                   is not going to be used.
	 * @param clientAuth The client authentication. Must not be
	 *                   {@code null}.
	 * @param token      The access or refresh token to revoke. Must not be
	 *                   {@code null}.
	 */
	public TokenRevocationRequest(final URI endpoint,
				      final ClientAuthentication clientAuth,
				      final Token token) {

		super(endpoint, Objects.requireNonNull(clientAuth));
		this.token = Objects.requireNonNull(token);
	}


	/**
	 * Creates a new token revocation request for a public client.
	 *
	 * @param endpoint The URI of the token revocation endpoint. May be
	 *                 {@code null} if the {@link #toHTTPRequest} method
	 *                 is not going to be used.
	 * @param clientID The client ID. Must not be {@code null}.
	 * @param token    The access or refresh token to revoke. Must not be
	 *                 {@code null}.
	 */
	public TokenRevocationRequest(final URI endpoint,
				      final ClientID clientID,
				      final Token token) {

		super(endpoint, Objects.requireNonNull(clientID));
		this.token = Objects.requireNonNull(token);
	}


	/**
	 * Returns the token to revoke. The {@code instanceof} operator can be
	 * used to infer the token type. If it's neither
	 * {@link com.nimbusds.oauth2.sdk.token.AccessToken} nor
	 * {@link com.nimbusds.oauth2.sdk.token.RefreshToken} the
	 * {@code token_type_hint} has not been provided as part of the token
	 * revocation request.
	 *
	 * @return The token.
	 */
	public Token getToken() {

		return token;
	}


	@Override
	public HTTPRequest toHTTPRequest() {

		if (getEndpointURI() == null)
			throw new SerializeException("The endpoint URI is not specified");

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, getEndpointURI());
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		Map<String,List<String>> params = new HashMap<>();

		if (getClientID() != null) {
			// public client
			params.put("client_id", Collections.singletonList(getClientID().getValue()));
		}

		params.put("token", Collections.singletonList(token.getValue()));

		if (token instanceof AccessToken) {
			params.put("token_type_hint", Collections.singletonList("access_token"));
		} else if (token instanceof RefreshToken) {
			params.put("token_type_hint", Collections.singletonList("refresh_token"));
		}

		httpRequest.setBody(URLUtils.serializeParameters(params));

		if (getClientAuthentication() != null) {
			// confidential client
			getClientAuthentication().applyTo(httpRequest);
		}

		return httpRequest;
	}


	/**
	 * Parses a token revocation request from the specified HTTP request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The token revocation request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a
	 *                        token revocation request.
	 */
	public static TokenRevocationRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		// Only HTTP POST accepted
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureEntityContentType(ContentType.APPLICATION_URLENCODED);

		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();

		final String tokenValue = MultivaluedMapUtils.getFirstValue(params,"token");

		if (StringUtils.isBlank(tokenValue)) {
			throw new ParseException("Missing required token parameter");
		}

		// Detect the token type
		final String tokenTypeHint = MultivaluedMapUtils.getFirstValue(params,"token_type_hint");

		Token token;
		if ("access_token".equals(tokenTypeHint)) {
			token = new TypelessAccessToken(tokenValue);
		} else if ("refresh_token".equals(tokenTypeHint)) {
			token = new RefreshToken(tokenValue);
		} else {
			// Can be both access or refresh token
			token = new TypelessToken(tokenValue);
		}

		URI uri = httpRequest.getURI();

		// Parse client auth
		ClientAuthentication clientAuth = ClientAuthentication.parse(httpRequest);

		if (clientAuth != null) {
			return new TokenRevocationRequest(uri, clientAuth, token);
		}

		// Public client
		final String clientIDString = MultivaluedMapUtils.getFirstValue(params, "client_id");

		if (StringUtils.isBlank(clientIDString)) {
			throw new ParseException("Invalid token revocation request: No client authentication or client_id parameter found");
		}

		return new TokenRevocationRequest(uri, new ClientID(clientIDString), token);
	}
}
