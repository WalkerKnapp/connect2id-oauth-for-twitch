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
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ProtectedResourceRequest;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import net.jcip.annotations.Immutable;

import java.net.URI;
import java.util.*;


/**
 * UserInfo request. Used to retrieve the consented claims about the end-user.
 *
 * <p>Example HTTP GET request with a Bearer token:
 *
 * <pre>
 * GET /userinfo HTTP/1.1
 * Host: server.example.com
 * Authorization: Bearer Eabeeduphee3aiviehahreacaoNg2thu
 * </pre>
 *
 * <p>Example HTTP GET request with a DPoP token and proof:
 *
 * <pre>
 * GET /userinfo HTTP/1.1
 * Host: server.example.com
 * Authorization: DPoP jo4kahphoh1ath4INaochohLeeshaiyo
 * DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik...
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 5.3.1.
 *     <li>OAuth 2.0 Bearer Token Usage (RFC6750), section 2.
 *     <li>OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer
 *         (DPoP) (RFC 9449), section 7.
 * </ul>
 */
@Immutable
public class UserInfoRequest extends ProtectedResourceRequest {


	/**
	 * The HTTP method.
	 */
	private final HTTPRequest.Method httpMethod;
	
	
	/**
	 * Creates a new UserInfo HTTP GET request.
	 *
	 * @param endpoint    The URI of the UserInfo endpoint. May be
	 *                    {@code null} if the {@link #toHTTPRequest} method
	 *                    is not going to be used.
	 * @param accessToken An access token for the request. Must not be
	 *                    {@code null}.
	 */
	public UserInfoRequest(final URI endpoint, final AccessToken accessToken) {
	
		this(endpoint, HTTPRequest.Method.GET, accessToken);
	}
	
	
	/**
	 * Creates a new UserInfo request.
	 *
	 * @param endpoint    The URI of the UserInfo endpoint. May be
	 *                    {@code null} if the {@link #toHTTPRequest} method
	 *                    is not going to be used.
	 * @param httpMethod  The HTTP method. Must be HTTP GET or POST and not 
	 *                    {@code null}.
	 * @param accessToken An access token for the request. Must not be
	 *                    {@code null}.
	 */
	public UserInfoRequest(final URI endpoint, final HTTPRequest.Method httpMethod, final AccessToken accessToken) {
	
		super(endpoint, Objects.requireNonNull(accessToken));
		this.httpMethod = Objects.requireNonNull(httpMethod);
	}
	
	
	/**
	 * Gets the HTTP method for this UserInfo request.
	 *
	 * @return The HTTP method.
	 */
	public HTTPRequest.Method getMethod() {
	
		return httpMethod;
	}
	
	
	@Override
	public HTTPRequest toHTTPRequest() {
		
		if (getEndpointURI() == null)
			throw new SerializeException("The endpoint URI is not specified");

		HTTPRequest httpRequest = new HTTPRequest(httpMethod, getEndpointURI());
		
		switch (httpMethod) {
		
			case GET:
				httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());
				break;
				
			case POST:
				httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
				Map<String, List<String>> params = new HashMap<>();
				params.put("access_token", Collections.singletonList(getAccessToken().getValue()));
				httpRequest.setBody(URLUtils.serializeParameters(params));
				break;
			
			default:
				throw new SerializeException("Unexpected HTTP method: " + httpMethod);
		}
		
		return httpRequest;
	}
	
	
	/**
	 * Parses the specified HTTP request for a UserInfo request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The UserInfo request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a 
	 *                        UserInfo request.
	 */
	public static UserInfoRequest parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		return new UserInfoRequest(
			httpRequest.getURI(),
			httpRequest.getMethod(),
			AccessToken.parse(httpRequest)
		);
	}
}
