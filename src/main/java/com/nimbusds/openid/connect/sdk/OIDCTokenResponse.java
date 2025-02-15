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


import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import java.util.HashMap;
import java.util.Map;


/**
 * OpenID Connect token response from the Token endpoint.
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
 *   "access_token"  : "SlAV32hkKG",
 *   "token_type"    : "Bearer",
 *   "refresh_token" : "8xLOxBtZp8",
 *   "expires_in"    : 3600,
 *   "id_token"      : "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC9zZXJ2Z
 *    XIuZXhhbXBsZS5jb20iLCJ1c2VyX2lkIjoiMjQ4Mjg5NzYxMDAxIiwiYXVkIjoic
 *    zZCaGRSa3F0MyIsIm5vbmNlIjoibi0wUzZfV3pBMk1qIiwiZXhwIjoxMzExMjgxO
 *    TcwLCJpYXQiOjEzMTEyODA5NzB9.RgXxzppVvn1EjUiV3LIZ19SyhdyREe_2jJjW
 *    5EC8XjNuJfe7Dte8YxRXxssJ67N8MT9mvOI3HOHm4whNx5FCyemyCGyTLHODCeAr
 *    _id029-4JP0KWySoan1jmT7vbGHhu89-l9MTdaEvu7pNZO7DHGwqnMWRe8hdG7jU
 *    ES4w4ReQTygKwXVVOaiGoeUrv6cZdbyOnpGlRlHaiOsv_xMunNVJtn5dLz-0zZwV
 *    ftKVpFuc1pGaVsyZsOtkT32E4c6MDHeCvIDlR5ESC0ct8BLvGJDB5954MjCR4_X2
 *    GAEHonKw4NF8wTmUFvhslYXmjRNFs21Byjn3jNb7lSa3MBfVsw"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 *     <li>OAuth 2.0 (RFC 6749)
 * </ul>
 */
@Immutable
public class OIDCTokenResponse extends AccessTokenResponse {


	/**
	 * The OpenID Connect tokens.
	 */
	private final OIDCTokens tokens;


	/**
	 * Creates a new OpenID Connect access token response.
	 *
	 * @param tokens The OpenID Connect tokens. Must not be {@code null}.
	 */
	public OIDCTokenResponse(final OIDCTokens tokens) {
				   
		this(tokens, null);
	}


	/**
	 * Creates a new OpenID Connect access token response.
	 *
	 * @param tokens       The OpenID Connect tokens. Must not be
	 *                     {@code null}.
	 * @param customParams Optional custom parameters, {@code null} if
	 *                     none.
	 */
	public OIDCTokenResponse(final OIDCTokens tokens,
				 final Map<String, Object> customParams) {

		super(tokens, customParams);

		this.tokens = tokens;
	}


	/**
	 * Gets the OpenID Connect tokens.
	 *
	 * @return The OpenID Connect tokens.
	 */
	public OIDCTokens getOIDCTokens() {

		return tokens;
	}
	
	
	/**
	 * Returns a JSON object representation of this OpenID Connect token
	 * response.
	 *
	 * <p>Example JSON object:
	 *
	 * <pre>
	 * {
	 *   "access_token" : "SlAV32hkKG",
	 *   "token_type"   : "Bearer",
	 *   "refresh_token": "8xLOxBtZp8",
	 *   "expires_in"   : 3600,
	 *   "id_token"     : "eyJ0 ... NiJ9.eyJ1c ... I6IjIifX0.DeWt4Qu ... ZXso"
	 * }
	 * </pre>
	 *
	 * @return The JSON object.
	 */
	@Override
	public JSONObject toJSONObject() {
	
		JSONObject o = super.toJSONObject();
		o.putAll(getOIDCTokens().toJSONObject());
		return o;
	}
	
	
	@Override
	public OIDCTokenResponse toSuccessResponse() {
		return this;
	}
	
	
	/**
	 * Parses an OpenID Connect token response from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The OpenID Connect token response.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OpenID Connect token response.
	 */
	public static OIDCTokenResponse parse(final JSONObject jsonObject)
		throws ParseException {

		OIDCTokens tokens = OIDCTokens.parse(jsonObject);

		// Parse the custom parameters
		Map<String, Object> customParams = new HashMap<>(jsonObject);
		for (String tokenParam: tokens.getParameterNames()) {
			customParams.remove(tokenParam);
		}

		if (customParams.isEmpty()) {
			return new OIDCTokenResponse(tokens);
		}
		
		return new OIDCTokenResponse(tokens, customParams);
	}
	
	
	/**
	 * Parses an OpenID Connect access token response from the specified 
	 * HTTP response.
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The OpenID Connect access token response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an 
	 *                        OpenID Connect access token response.
	 */
	public static OIDCTokenResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
		JSONObject jsonObject = httpResponse.getBodyAsJSONObject();
		return parse(jsonObject);
	}
}
