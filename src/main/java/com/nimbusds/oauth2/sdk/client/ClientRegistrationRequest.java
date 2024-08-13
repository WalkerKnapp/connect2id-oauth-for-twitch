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

package com.nimbusds.oauth2.sdk.client;


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ProtectedResourceRequest;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import java.net.URI;
import java.util.Objects;


/**
 * Client registration request.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * POST /register HTTP/1.1
 * Content-Type: application/json
 * Accept: application/json
 * Authorization: Bearer ey23f2.adfj230.af32-developer321
 * Host: server.example.com
 *
 * {
 *   "redirect_uris"              : [ "https://client.example.org/callback",
 *                                    "https://client.example.org/callback2" ],
 *   "client_name"                : "My Example Client",
 *   "client_name#ja-Jpan-JP"     : "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
 *   "token_endpoint_auth_method" : "client_secret_basic",
 *   "scope"                      : "read write dolphin",
 *   "logo_uri"                   : "https://client.example.org/logo.png",
 *   "jwks_uri"                   : "https://client.example.org/my_public_keys.jwks"
 * }
 * </pre>
 *
 * <p>Example HTTP request with a software statement:
 *
 * <pre>
 * POST /register HTTP/1.1
 * Content-Type: application/json
 * Accept: application/json
 * Host: server.example.com
 *
 * {
 *   "redirect_uris"               : [ "https://client.example.org/callback",
 *                                     "https://client.example.org/callback2" ],
 *   "software_statement"          : "eyJhbGciOiJFUzI1NiJ9.eyJpc3Mi[...omitted for brevity...]",
 *   "scope"                       : "read write",
 *   "example_extension_parameter" : "example_value"
 * }
 *
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)
 * </ul>
 */
@Immutable
public class ClientRegistrationRequest extends ProtectedResourceRequest {


	/**
	 * The client metadata.
	 */
	private final ClientMetadata metadata;


	/**
	 * The optional software statement.
	 */
	private final SignedJWT softwareStatement;


	/**
	 * Creates a new client registration request.
	 *
	 * @param endpoint    The URI of the client registration endpoint. May
	 *                    be {@code null} if the {@link #toHTTPRequest()}
	 *                    method is not going to be used.
	 * @param metadata    The client metadata. Must not be {@code null} and 
	 *                    must specify one or more redirection URIs.
	 * @param accessToken An OAuth 2.0 Bearer access token for the request, 
	 *                    {@code null} if none.
	 */
	public ClientRegistrationRequest(final URI endpoint,
		                         final ClientMetadata metadata, 
		                         final BearerAccessToken accessToken) {

		this(endpoint, metadata, null, accessToken);
	}


	/**
	 * Creates a new client registration request with an optional software
	 * statement.
	 *
	 * @param endpoint          The URI of the client registration
	 *                          endpoint. May be {@code null} if the
	 *                          {@link #toHTTPRequest()} method is not
	 *                          going to be used.
	 * @param metadata          The client metadata. Must not be
	 *                          {@code null} and must specify one or more
	 *                          redirection URIs.
	 * @param softwareStatement Optional software statement, as a signed
	 *                          JWT with an {@code iss} claim; {@code null}
	 *                          if not specified.
	 * @param accessToken       An OAuth 2.0 Bearer access token for the
	 *                          request, {@code null} if none.
	 */
	public ClientRegistrationRequest(final URI endpoint,
					 final ClientMetadata metadata,
					 final SignedJWT softwareStatement,
					 final BearerAccessToken accessToken) {

		super(endpoint, accessToken);
		this.metadata = Objects.requireNonNull(metadata);


		if (softwareStatement != null) {

			if (softwareStatement.getState() == JWSObject.State.UNSIGNED) {
				throw new IllegalArgumentException("The software statement JWT must be signed");
			}

			JWTClaimsSet claimsSet;

			try {
				claimsSet = softwareStatement.getJWTClaimsSet();

			} catch (java.text.ParseException e) {

				throw new IllegalArgumentException("The software statement is not a valid signed JWT: " + e.getMessage());
			}

			if (claimsSet.getIssuer() == null) {

				// http://tools.ietf.org/html/rfc7591#section-2.3
				throw new IllegalArgumentException("The software statement JWT must contain an 'iss' claim");
			}

		}

		this.softwareStatement = softwareStatement;
	}


	/**
	 * Gets the associated client metadata.
	 *
	 * @return The client metadata.
	 */
	public ClientMetadata getClientMetadata() {

		return metadata;
	}


	/**
	 * Gets the software statement.
	 *
	 * @return The software statement, as a signed JWT with an {@code iss}
	 *         claim; {@code null} if not specified.
	 */
	public SignedJWT getSoftwareStatement() {

		return softwareStatement;
	}


	@Override
	public HTTPRequest toHTTPRequest() {
		
		if (getEndpointURI() == null)
			throw new SerializeException("The endpoint URI is not specified");

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, getEndpointURI());

		if (getAccessToken() != null) {
			httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());
		}

		httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);

		JSONObject content = metadata.toJSONObject();

		if (softwareStatement != null) {

			// Signed state check done in constructor
			content.put("software_statement", softwareStatement.serialize());
		}

		httpRequest.setBody(content.toString());

		return httpRequest;
	}


	/**
	 * Parses a client registration request from the specified HTTP POST 
	 * request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The client registration request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        client registration request.
	 */
	public static ClientRegistrationRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		httpRequest.ensureMethod(HTTPRequest.Method.POST);

		// Get the JSON object content
		JSONObject jsonObject = httpRequest.getBodyAsJSONObject();

		// Extract the software statement if any
		SignedJWT stmt = null;

		if (jsonObject.containsKey("software_statement")) {

			try {
				stmt = SignedJWT.parse(JSONObjectUtils.getString(jsonObject, "software_statement"));

			} catch (java.text.ParseException e) {

				throw new ParseException("Invalid software statement JWT: " + e.getMessage());
			}

			// Prevent the JWT from appearing in the metadata
			jsonObject.remove("software_statement");
		}

		// Parse the client metadata
		ClientMetadata metadata = ClientMetadata.parse(jsonObject);

		// Parse the optional bearer access token
		BearerAccessToken accessToken = null;
		
		String authzHeaderValue = httpRequest.getAuthorization();
		
		if (StringUtils.isNotBlank(authzHeaderValue))
			accessToken = BearerAccessToken.parse(authzHeaderValue);
		
		try {
			return new ClientRegistrationRequest(httpRequest.getURI(), metadata, stmt, accessToken);
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage(), e);
		}
	}
}