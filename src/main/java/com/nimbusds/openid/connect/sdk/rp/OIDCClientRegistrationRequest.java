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

package com.nimbusds.openid.connect.sdk.rp;


import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import java.net.URI;


/**
 * OpenID Connect client registration request.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * POST /connect/register HTTP/1.1
 * Content-Type: application/json
 * Accept: application/json
 * Host: server.example.com
 * Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJ ...
 *
 * {
 *  "application_type"                : "web",
 *  "redirect_uris"                   : [ "https://client.example.org/callback",
 *                                        "https://client.example.org/callback2" ],
 *  "client_name"                     : "My Example",
 *  "client_name#ja-Jpan-JP"          : "クライアント名",
 *  "logo_uri"                        : "https://client.example.org/logo.png",
 *  "subject_type"                    : "pairwise",
 *  "sector_identifier_uri"           : "https://other.example.net/file_of_redirect_uris.json",
 *  "token_endpoint_auth_method"      : "client_secret_basic",
 *  "jwks_uri"                        : "https://client.example.org/my_public_keys.jwks",
 *  "userinfo_encrypted_response_alg" : "RSA1_5",
 *  "userinfo_encrypted_response_enc" : "A128CBC-HS256",
 *  "contacts"                        : [ "ve7jtb@example.org", "mary@example.org" ],
 *  "request_uris"                    : [ "https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA" ]
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)
 * </ul>
 */
@Immutable
public class OIDCClientRegistrationRequest extends ClientRegistrationRequest {
	
	
	/**
	 * Creates a new OpenID Connect client registration request.
	 *
	 * @param endpoint    The URI of the client registration endpoint. May
	 *                    be {@code null} if the {@link #toHTTPRequest()}
	 *                    method is not going to be used.
	 * @param metadata    The OpenID Connect client metadata. Must not be 
	 *                    {@code null} and must specify one or more
	 *                    redirection URIs.
	 * @param accessToken An OAuth 2.0 Bearer access token for the request, 
	 *                    {@code null} if none.
	 */
	public OIDCClientRegistrationRequest(final URI endpoint,
		                             final OIDCClientMetadata metadata, 
		                             final BearerAccessToken accessToken) {

		super(endpoint, metadata, accessToken);
	}


	/**
	 * Creates a new OpenID Connect client registration request with an
	 * optional software statement.
	 *
	 * @param endpoint          The URI of the client registration
	 *                          endpoint. May be {@code null} if the
	 *                          {@link #toHTTPRequest()} method is not
	 *                          going to be used.
	 * @param metadata          The OpenID Connect client metadata. Must
	 *                          not be {@code null} and must specify one or
	 *                          more redirection URIs.
	 * @param softwareStatement Optional software statement, as a signed
	 *                          JWT with an {@code iss} claim; {@code null}
	 *                          if not specified.
	 * @param accessToken       An OAuth 2.0 Bearer access token for the
	 *                          request, {@code null} if none.
	 */
	public OIDCClientRegistrationRequest(final URI endpoint,
					     final OIDCClientMetadata metadata,
					     final SignedJWT softwareStatement,
					     final BearerAccessToken accessToken) {

		super(endpoint, metadata, softwareStatement, accessToken);
	}
	
	
	/**
	 * Gets the associated OpenID Connect client metadata.
	 *
	 * @return The OpenID Connect client metadata.
	 */
	public OIDCClientMetadata getOIDCClientMetadata() {
		
		return (OIDCClientMetadata)getClientMetadata();
	}
	
	
	/**
	 * Parses an OpenID Connect client registration request from the 
	 * specified HTTP POST request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The OpenID Connect client registration request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an 
	 *                        OpenID Connect client registration request.
	 */
	public static OIDCClientRegistrationRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		httpRequest.ensureMethod(HTTPRequest.Method.POST);

		// Get the JSON object content
		JSONObject jsonObject = httpRequest.getBodyAsJSONObject();

		// Extract the software statement if any
		SignedJWT stmt = null;

		if (jsonObject.containsKey("software_statement")) {

			try {
				stmt = SignedJWT.parse(JSONObjectUtils.getNonBlankString(jsonObject, "software_statement"));

			} catch (java.text.ParseException e) {

				throw new ParseException("Invalid software statement JWT: " + e.getMessage());
			}

			// Prevent the JWT from appearing in the metadata
			jsonObject.remove("software_statement");
		}

		// Parse the client metadata
		OIDCClientMetadata metadata = OIDCClientMetadata.parse(jsonObject);

		// Parse the optional bearer access token
		BearerAccessToken accessToken = null;
		
		String authzHeaderValue = httpRequest.getAuthorization();
		
		if (StringUtils.isNotBlank(authzHeaderValue))
			accessToken = BearerAccessToken.parse(authzHeaderValue);
		
		URI endpointURI = httpRequest.getURI();
		
		try {
			return new OIDCClientRegistrationRequest(endpointURI, metadata, stmt, accessToken);
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage(), e);
		}
	}
}
