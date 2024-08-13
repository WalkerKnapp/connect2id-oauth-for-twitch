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
import com.nimbusds.oauth2.sdk.SuccessResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import net.jcip.annotations.Immutable;

import java.util.Objects;


/**
 * Client information response.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * Cache-Control: no-store
 * Pragma: no-cache
 *
 * {
 *  "registration_access_token"  : "reg-23410913-abewfq.123483",
 *  "registration_client_uri"    : "https://server.example.com/register/s6BhdRkqt3",
 *  "client_id"                  : "s6BhdRkqt3",
 *  "client_secret"              : "cf136dc3c1fc93f31185e5885805d",
 *  "client_id_issued_at"        : 2893256800
 *  "client_secret_expires_at"   : 2893276800
 *  "client_name"                : "My Example Client",
 *  "client_name#ja-Jpan-JP"     : "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
 *  "redirect_uris"              : [ "https://client.example.org/callback",
 *                                   "https://client.example.org/callback2" ]
 *  "scope"                      : "read write dolphin",
 *  "grant_types"                : [ "authorization_code", "refresh_token" ]
 *  "token_endpoint_auth_method" : "client_secret_basic",
 *  "logo_uri"                   : "https://client.example.org/logo.png",
 *  "jwks_uri"                   : "https://client.example.org/my_public_keys.jwks"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Management Protocol (RFC 7592)
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)
 * </ul>
 */
@Immutable
public class ClientInformationResponse 
	extends ClientRegistrationResponse
	implements SuccessResponse {


	/**
	 * The client information.
	 */
	private final ClientInformation clientInfo;
	
	
	/**
	 * {@code true} for a newly registered client.
	 */
	private final boolean forNewClient;


	/**
	 * Creates a new client information response.
	 *
	 * @param clientInfo   The client information. Must not be
	 *                     {@code null}.
	 * @param forNewClient {@code true} for a newly registered client,
	 *                     {@code false} for a retrieved or updated client.
	 */
	public ClientInformationResponse(final ClientInformation clientInfo,
					 final boolean forNewClient) {

		this.clientInfo = Objects.requireNonNull(clientInfo);
		this.forNewClient = forNewClient;
	}


	@Override
	public boolean indicatesSuccess() {

		return true;
	}


	/**
	 * Gets the client information.
	 *
	 * @return The client information.
	 */
	public ClientInformation getClientInformation() {

		return clientInfo;
	}
	
	
	/**
	 * Checks if the client information response is for a new client.
	 *
	 * @return {@code true} for a newly registered client, {@code false}
	 *         for a retrieved or updated client.
	 */
	public boolean isForNewClient() {
		
		return forNewClient;
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse() {
	
		// 201 for POST, 200 for GET or PUT
		HTTPResponse httpResponse = new HTTPResponse(forNewClient ? HTTPResponse.SC_CREATED : HTTPResponse.SC_OK);
		httpResponse.setEntityContentType(ContentType.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");
		httpResponse.setPragma("no-cache");
		httpResponse.setBody(clientInfo.toJSONObject().toString());
		return httpResponse;
	}


	/**
	 * Parses a client information response from the specified 
	 * HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The client information response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a
	 *                        client information response.
	 */
	public static ClientInformationResponse parse(final HTTPResponse httpResponse)
		throws ParseException {

		httpResponse.ensureStatusCode(HTTPResponse.SC_OK, HTTPResponse.SC_CREATED);
		ClientInformation clientInfo = ClientInformation.parse(httpResponse.getBodyAsJSONObject());
		boolean forNewClient = HTTPResponse.SC_CREATED == httpResponse.getStatusCode();
		return new ClientInformationResponse(clientInfo, forNewClient);
	}
}