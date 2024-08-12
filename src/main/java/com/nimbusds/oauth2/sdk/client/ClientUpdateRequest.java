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
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ProtectedResourceRequest;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
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
 * PUT /register/s6BhdRkqt3 HTTP/1.1
 * Accept: application/json
 * Host: server.example.com
 * Authorization: Bearer reg-23410913-abewfq.123483
 *
 * {
 *  "client_id"                  :"s6BhdRkqt3",
 *  "client_secret"              : "cf136dc3c1fc93f31185e5885805d",
 *  "redirect_uris"              : [ "https://client.example.org/callback",
 *                                   "https://client.example.org/alt" ],
 *  "scope"                      : "read write dolphin",
 *  "grant_types"                : [ "authorization_code", "refresh_token" ]
 *  "token_endpoint_auth_method" : "client_secret_basic",
 *  "jwks_uri"                   : "https://client.example.org/my_public_keys.jwks"
 *  "client_name"                : "My New Example",
 *  "client_name#fr"             : "Mon Nouvel Exemple",
 *  "logo_uri"                   : "https://client.example.org/newlogo.png"
 *  "logo_uri#fr"                : "https://client.example.org/fr/newlogo.png"
 * }
 *
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Management Protocol (RFC
 *         7592), section 2.2.
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591), section
 *         2.
 * </ul>
 */
@Immutable
public class ClientUpdateRequest extends ProtectedResourceRequest {
	
	
	/**
	 * The registered client ID.
	 */
	private final ClientID id;
	
	
	/**
	 * The client metadata.
	 */
	private final ClientMetadata metadata;
	
	
	/**
	 * The optional client secret.
	 */
	private final Secret secret;
	
	
	/**
	 * Creates a new client update request.
	 *
	 * @param endpoint    The URI of the client update endpoint. May be
	 *                    {@code null} if the {@link #toHTTPRequest()}
	 *                    method is not going to be used.
	 * @param id          The client ID. Must not be {@code null}.
	 * @param accessToken The client registration access token. Must not be
	 *                    {@code null}.
	 * @param metadata    The client metadata. Must not be {@code null} and 
	 *                    must specify one or more redirection URIs.
	 * @param secret      The optional client secret, {@code null} if not
	 *                    specified.
	 */
	public ClientUpdateRequest(final URI endpoint,
		                   final ClientID id,
		                   final BearerAccessToken accessToken,
				   final ClientMetadata metadata, 
				   final Secret secret) {

		super(endpoint, accessToken);
		this.id = Objects.requireNonNull(id);
		this.metadata = Objects.requireNonNull(metadata);
		this.secret = secret;
	}
	
	
	/**
	 * Gets the client ID. Corresponds to the {@code client_id} client
	 * registration parameter.
	 *
	 * @return The client ID, {@code null} if not specified.
	 */
	public ClientID getClientID() {

		return id;
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
	 * Gets the client secret. Corresponds to the {@code client_secret} 
	 * registration parameters.
	 *
	 * @return The client secret, {@code null} if not specified.
	 */
	public Secret getClientSecret() {

		return secret;
	}
	
	
	@Override
	public HTTPRequest toHTTPRequest() {
		
		if (getEndpointURI() == null)
			throw new SerializeException("The endpoint URI is not specified");

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.PUT, getEndpointURI());

		httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());

		httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);
		
		JSONObject jsonObject = metadata.toJSONObject();
		
		jsonObject.put("client_id", id.getValue());
		
		if (secret != null)
			jsonObject.put("client_secret", secret.getValue());

		httpRequest.setBody(jsonObject.toString());

		return httpRequest;
	}
	
	
	/**
	 * Parses a client update request from the specified HTTP PUT request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The client update request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        client update request.
	 */
	public static ClientUpdateRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		httpRequest.ensureMethod(HTTPRequest.Method.PUT);
		
		BearerAccessToken accessToken = BearerAccessToken.parse(httpRequest.getAuthorization());
		
		JSONObject jsonObject = httpRequest.getBodyAsJSONObject();
		
		ClientID id = new ClientID(JSONObjectUtils.getString(jsonObject, "client_id"));

		ClientMetadata metadata = ClientMetadata.parse(jsonObject);
		
		Secret clientSecret = null;
		
		if (jsonObject.get("client_secret") != null)
			clientSecret = new Secret(JSONObjectUtils.getString(jsonObject, "client_secret"));
			
		return new ClientUpdateRequest(httpRequest.getURI(), id, accessToken, metadata, clientSecret);
	}
}
