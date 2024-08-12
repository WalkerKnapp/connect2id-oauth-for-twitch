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


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ProtectedResourceRequest;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import net.jcip.annotations.Immutable;

import java.net.URI;
import java.util.Objects;


/**
 * Client delete request.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * DELETE /register/s6BhdRkqt3 HTTP/1.1
 * Accept: application/json
 * Host: server.example.com
 * Authorization: Bearer reg-23410913-abewfq.123483
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Management Protocol (RFC
 *         7592), section 2.3.
 * </ul>
 */
@Immutable
public class ClientDeleteRequest extends ProtectedResourceRequest {


	/**
	 * Creates a new client delete request.
	 *
	 * @param endpoint    The URI of the client configuration endpoint. May
	 *                    be {@code null} if the {@link #toHTTPRequest()}
	 *                    method is not going to be used.
	 * @param accessToken An OAuth 2.0 Bearer access token for the request, 
	 *                    {@code null} if none.
	 */
	public ClientDeleteRequest(final URI endpoint, final BearerAccessToken accessToken) {

		super(endpoint, Objects.requireNonNull(accessToken));
	}


	@Override
	public HTTPRequest toHTTPRequest() {
		
		if (getEndpointURI() == null)
			throw new SerializeException("The endpoint URI is not specified");

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.DELETE, getEndpointURI());
		httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());
		return httpRequest;
	}


	/**
	 * Parses a client delete request from the specified HTTP DELETE 
	 * request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The client add (register) request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        client delete request.
	 */
	public static ClientDeleteRequest parse(final HTTPRequest httpRequest)
		throws ParseException {

		httpRequest.ensureMethod(HTTPRequest.Method.DELETE);
		return new ClientDeleteRequest(
			httpRequest.getURI(),
			BearerAccessToken.parse(httpRequest.getAuthorization())
		);
	}
}