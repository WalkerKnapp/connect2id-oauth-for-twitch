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
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Token;
import com.nimbusds.oauth2.sdk.token.TypelessAccessToken;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import java.net.URI;
import java.util.*;


/**
 * Token introspection request. Used by a protected resource to obtain the
 * authorisation for a submitted access token. May also be used by clients to
 * query a refresh token.
 *
 * <p>The protected resource may be required to authenticate itself to the
 * token introspection endpoint with a standard client
 * {@link ClientAuthentication authentication method}, such as
 * {@link com.nimbusds.oauth2.sdk.auth.ClientSecretBasic client_secret_basic},
 * or with a dedicated {@link AccessToken access token}.
 *
 * <p>Example token introspection request, where the protected resource
 * authenticates itself with a secret (the token type is also hinted):
 *
 * <pre>
 * POST /introspect HTTP/1.1
 * Host: server.example.com
 * Accept: application/json
 * Content-Type: application/x-www-form-urlencoded
 * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
 *
 * token=mF_9.B5f-4.1JqM&amp;token_type_hint=access_token
 * </pre>
 *
 * <p>Example token introspection request, where the protected resource
 * authenticates itself with a bearer token:
 *
 * <pre>
 * POST /introspect HTTP/1.1
 * Host: server.example.com
 * Accept: application/json
 * Content-Type: application/x-www-form-urlencoded
 * Authorization: Bearer 23410913-abewfq.123483
 *
 * token=2YotnFZFEjr1zCsicMWpAA
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Token Introspection (RFC 7662).
 * </ul>
 */
@Immutable
public class TokenIntrospectionRequest extends AbstractOptionallyAuthenticatedRequest {


	/**
	 * The token to introspect.
	 */
	private final Token token;


	/**
	 * Optional access token to authorise the submitter.
	 */
	private final AccessToken clientAuthz;


	/**
	 * Optional additional parameters.
	 */
	private final Map<String,List<String>> customParams;


	/**
	 * Creates a new token introspection request. The request submitter is
	 * not authenticated.
	 *
	 * @param uri   The URI of the token introspection endpoint. May be
	 *              {@code null} if the {@link #toHTTPRequest} method will
	 *              not be used.
	 * @param token The access or refresh token to introspect. Must not be
	 *              {@code null}.
	 */
	public TokenIntrospectionRequest(final URI uri,
					 final Token token) {

		this(uri, token, null);
	}


	/**
	 * Creates a new token introspection request. The request submitter is
	 * not authenticated.
	 *
	 * @param uri          The URI of the token introspection endpoint. May
	 *                     be {@code null} if the {@link #toHTTPRequest}
	 *                     method will not be used.
	 * @param token        The access or refresh token to introspect. Must
	 *                     not be {@code null}.
	 * @param customParams Optional custom parameters, {@code null} if
	 *                     none.
	 */
	public TokenIntrospectionRequest(final URI uri,
					 final Token token,
					 final Map<String,List<String>> customParams) {

		super(uri, null);

		if (token == null)
			throw new IllegalArgumentException("The token must not be null");

		this.token = token;
		this.clientAuthz = null;
		this.customParams = customParams != null ? customParams : Collections.<String,List<String>>emptyMap();
	}


	/**
	 * Creates a new token introspection request. The request submitter may
	 * authenticate with a secret or private key JWT assertion.
	 *
	 * @param uri        The URI of the token introspection endpoint. May
	 *                   be {@code null} if the {@link #toHTTPRequest}
	 *                   method will not be used.
	 * @param clientAuth The client authentication, {@code null} if none.
	 * @param token      The access or refresh token to introspect. Must
	 *                   not be {@code null}.
	 */
	public TokenIntrospectionRequest(final URI uri,
					 final ClientAuthentication clientAuth,
					 final Token token) {

		this(uri, clientAuth, token, null);
	}


	/**
	 * Creates a new token introspection request. The request submitter may
	 * authenticate with a secret or private key JWT assertion.
	 *
	 * @param uri          The URI of the token introspection endpoint. May
	 *                     be {@code null} if the {@link #toHTTPRequest}
	 *                     method will not be used.
	 * @param clientAuth   The client authentication, {@code null} if none.
	 * @param token        The access or refresh token to introspect. Must
	 *                     not be {@code null}.
	 * @param customParams Optional custom parameters, {@code null} if
	 *                     none.
	 */
	public TokenIntrospectionRequest(final URI uri,
					 final ClientAuthentication clientAuth,
					 final Token token,
					 final Map<String,List<String>> customParams) {

		super(uri, clientAuth);

		if (token == null)
			throw new IllegalArgumentException("The token must not be null");

		this.token = token;
		this.clientAuthz = null;
		this.customParams = customParams != null ? customParams : Collections.<String,List<String>>emptyMap();
	}


	/**
	 * Creates a new token introspection request. The request submitter may
	 * authorise itself with an access token.
	 *
	 * @param uri         The URI of the token introspection endpoint. May
	 *                    be {@code null} if the {@link #toHTTPRequest}
	 *                    method will not be used.
	 * @param clientAuthz The client authorisation, {@code null} if none.
	 * @param token       The access or refresh token to introspect. Must
	 *                    not be {@code null}.
	 */
	public TokenIntrospectionRequest(final URI uri,
					 final AccessToken clientAuthz,
					 final Token token) {

		this(uri, clientAuthz, token, null);
	}


	/**
	 * Creates a new token introspection request. The request submitter may
	 * authorise itself with an access token.
	 *
	 * @param uri          The URI of the token introspection endpoint. May
	 *                     be {@code null} if the {@link #toHTTPRequest}
	 *                     method will not be used.
	 * @param clientAuthz  The client authorisation, {@code null} if none.
	 * @param token        The access or refresh token to introspect. Must
	 *                     not be {@code null}.
	 * @param customParams Optional custom parameters, {@code null} if
	 *                     none.
	 */
	public TokenIntrospectionRequest(final URI uri,
					 final AccessToken clientAuthz,
					 final Token token,
					 final Map<String,List<String>> customParams) {

		super(uri, null);

		if (token == null)
			throw new IllegalArgumentException("The token must not be null");

		this.token = token;
		this.clientAuthz = clientAuthz;
		this.customParams = customParams != null ? customParams : Collections.<String,List<String>>emptyMap();
	}


	/**
	 * Returns the client authorisation.
	 *
	 * @return The client authorisation as an access token, {@code null} if
	 *         none.
	 */
	public AccessToken getClientAuthorization() {

		return clientAuthz;
	}


	/**
	 * Returns the token to introspect. The {@code instanceof} operator can
	 * be used to infer the token type. If it's neither
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


	/**
	 * Returns the custom request parameters.
	 *
	 * @return The custom request parameters, empty map if none.
	 */
	public Map<String,List<String>> getCustomParameters() {

		return customParams;
	}
	

	@Override
	public HTTPRequest toHTTPRequest() {

		if (getEndpointURI() == null)
			throw new SerializeException("The endpoint URI is not specified");

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, getEndpointURI());
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);

		Map<String,List<String>> params = new HashMap<>();
		params.put("token", Collections.singletonList(token.getValue()));

		if (token instanceof AccessToken) {
			params.put("token_type_hint", Collections.singletonList("access_token"));
		} else if (token instanceof RefreshToken) {
			params.put("token_type_hint", Collections.singletonList("refresh_token"));
		}

		params.putAll(customParams);

		httpRequest.setBody(URLUtils.serializeParameters(params));

		if (getClientAuthentication() != null)
			getClientAuthentication().applyTo(httpRequest);

		if (clientAuthz != null)
			httpRequest.setAuthorization(clientAuthz.toAuthorizationHeader());

		return httpRequest;
	}


	/**
	 * Parses a token introspection request from the specified HTTP
	 * request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The token introspection request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a
	 *                        token introspection request.
	 */
	public static TokenIntrospectionRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		// Only HTTP POST accepted
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureEntityContentType(ContentType.APPLICATION_URLENCODED);

		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();

		final String tokenValue = MultivaluedMapUtils.removeAndReturnFirstValue(params, "token");

		if (tokenValue == null || tokenValue.isEmpty()) {
			throw new ParseException("Missing required token parameter");
		}

		// Detect the token type
		Token token = null;

		final String tokenTypeHint = MultivaluedMapUtils.removeAndReturnFirstValue(params, "token_type_hint");

		if (tokenTypeHint == null) {

			// Can be both access or refresh token
			token = new Token() {
				
				private static final long serialVersionUID = 8491102820261331059L;
				
				
				@Override
				public String getValue() {

					return tokenValue;
				}

				@Override
				public Set<String> getParameterNames() {

					return Collections.emptySet();
				}

				@Override
				public JSONObject toJSONObject() {

					return new JSONObject();
				}

				@Override
				public boolean equals(final Object other) {

					return other instanceof Token && other.toString().equals(tokenValue);
				}

				@Override
				public int hashCode() {
					return Objects.hashCode(tokenValue);
				}
			};

		} else if (tokenTypeHint.equals("access_token")) {

			token = new TypelessAccessToken(tokenValue);

		} else if (tokenTypeHint.equals("refresh_token")) {

			token = new RefreshToken(tokenValue);
		}

		// Important: auth methods mutually exclusive!

		// Parse optional client auth
		ClientAuthentication clientAuth = ClientAuthentication.parse(httpRequest);

		// Parse optional client authz (token)
		AccessToken clientAuthz = null;

		if (clientAuth == null && httpRequest.getAuthorization() != null) {
			clientAuthz = AccessToken.parse(httpRequest.getAuthorization());
		}

		URI uri = httpRequest.getURI();

		if (clientAuthz != null) {
			return new TokenIntrospectionRequest(uri, clientAuthz, token, params);
		} else {
			return new TokenIntrospectionRequest(uri, clientAuth, token, params);
		}
	}
}
