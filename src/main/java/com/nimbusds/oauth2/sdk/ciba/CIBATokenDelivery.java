/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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

package com.nimbusds.oauth2.sdk.ciba;


import java.net.URI;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;


/**
 * CIBA token push delivery to the client notification endpoint.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * POST /cb HTTP/1.1
 * Host: client.example.com
 * Authorization: Bearer 8d67dc78-7faa-4d41-aabd-67707b374255
 * Content-Type: application/json
 *
 * {
 *   "auth_req_id": "1c266114-a1be-4252-8ad1-04986c5b9ac1",
 *   "access_token": "G5kXH2wHvUra0sHlDy1iTkDJgsgUO1bN",
 *   "token_type": "Bearer",
 *   "refresh_token": "4bwc0ESC_IAhflf-ACC_vjD_ltc11ne-8gFPfA2Kx16",
 *   "expires_in": 120,
 *   "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE2NzcyNiJ9.eyJpc3MiOiJ
 *     odHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsInN1YiI6IjI0ODI4OTc2MTAwMS
 *     IsImF1ZCI6InM2QmhkUmtxdDMiLCJlbWFpbCI6ImphbmVkb2VAZXhhbXBsZS5jb
 *     20iLCJleHAiOjE1Mzc4MTk4MDMsImlhdCI6MTUzNzgxOTUwMywiYXRfaGFzaCI6
 *     Ild0MGtWRlhNYWNxdm5IZXlVMDAwMXciLCJ1cm46b3BlbmlkOnBhcmFtczpqd3Q
 *     6Y2xhaW06cnRfaGFzaCI6InNIYWhDdVNwWENSZzVta0REdnZyNHciLCJ1cm46b3
 *     BlbmlkOnBhcmFtczpqd3Q6Y2xhaW06YXV0aF9yZXFfaWQiOiIxYzI2NjExNC1hM
 *     WJlLTQyNTItOGFkMS0wNDk4NmM1YjlhYzEifQ.SGB5_a8E7GjwtoYrkFyqOhLK6
 *     L8-Wh1nLeREwWj30gNYOZW_ZB2mOeQ5yiXqeKJeNpDPssGUrNo-3N-CqNrbmVCb
 *     XYTwmNB7IvwE6ZPRcfxFV22oou-NS4-3rEa2ghG44Fi9D9fVURwxrRqgyezeD3H
 *     HVIFUnCxHUou3OOpj6aOgDqKI4Xl2xJ0-kKAxNR8LljUp64OHgoS-UO3qyfOwIk
 *     IAR7o4OTK_3Oy78rJNT0Y0RebAWyA81UDCSf_gWVBp-EUTI5CdZ1_odYhwB9OWD
 *     W1A22Sf6rmjhMHGbQW4A9Z822yiZZveuT_AFZ2hi7yNp8iFPZ8fgPQJ5pPpjA7u
 *     dg"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *      <li>OpenID Connect CIBA Flow - Core 1.0, section 10.3.1.
 * </ul>
 */
@Immutable
public class CIBATokenDelivery extends CIBAPushCallback {
	
	
	/**
	 * The tokens.
	 */
	private final Tokens tokens;
	
	
	/**
	 * Creates a new CIBA push token delivery for OAuth 2.0.
	 *
	 * @param endpoint      The client notification endpoint. Must not be
	 *                      {@code null}.
	 * @param accessToken   The client notification token. Must not be
	 *                      {@code null}.
	 * @param authRequestID The CIBA request ID. Must not be {@code null}.
	 * @param tokens        The OAuth 2.0 tokens to deliver. Must not be
	 *                      {@code null}.
	 */
	public CIBATokenDelivery(final URI endpoint,
				 final BearerAccessToken accessToken,
				 final AuthRequestID authRequestID,
				 final Tokens tokens) {
		
		super(endpoint, accessToken, authRequestID);
		
		if (tokens == null) {
			throw new IllegalArgumentException("The tokens must not be null");
		}
		this.tokens = tokens;
	}
	
	
	/**
	 * Creates a new CIBA push token delivery for OpenID Connect.
	 *
	 * @param endpoint      The client notification endpoint. Must not be
	 *                      {@code null}.
	 * @param accessToken   The client notification token. Must not be
	 *                      {@code null}.
	 * @param authRequestID The CIBA request ID. Must not be {@code null}.
	 * @param oidcTokens    The OpenID Connect tokens to deliver. Must not
	 *                      be {@code null}.
	 */
	public CIBATokenDelivery(final URI endpoint,
				 final BearerAccessToken accessToken,
				 final AuthRequestID authRequestID,
				 final OIDCTokens oidcTokens) {
		
		super(endpoint, accessToken, authRequestID);
		
		if (oidcTokens == null) {
			throw new IllegalArgumentException("The OpenID Connect tokens must not be null");
		}
		this.tokens = oidcTokens;
	}
	
	
	@Override
	public boolean indicatesSuccess() {
		
		return true;
	}
	
	
	/**
	 * Returns the OAuth 2.0 tokens.
	 *
	 * @return The tokens.
	 */
	public Tokens getTokens() {
		
		return tokens;
	}
	
	
	/**
	 * Returns the OpenID Connect tokens if present.
	 *
	 * @return The OpenID Connect tokens, {@code null} if none.
	 */
	public OIDCTokens getOIDCTokens() {
		
		return getTokens() instanceof OIDCTokens ? getTokens().toOIDCTokens() : null;
	}
	
	
	@Override
	public HTTPRequest toHTTPRequest() {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, getEndpointURI());
		httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());
		httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("auth_req_id", getAuthRequestID().getValue());
		jsonObject.putAll(getTokens().toJSONObject());
		httpRequest.setBody(jsonObject.toJSONString());
		return httpRequest;
	}
	
	
	/**
	 * Parses a CIBA push token delivery from the specified HTTP request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The CIBA push token delivery.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static CIBATokenDelivery parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		URI uri = httpRequest.getURI();
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureEntityContentType(ContentType.APPLICATION_JSON);
		
		BearerAccessToken clientNotificationToken = BearerAccessToken.parse(httpRequest);
		
		AuthRequestID authRequestID = new AuthRequestID(
			JSONObjectUtils.getString(
				httpRequest.getQueryAsJSONObject(),
				"auth_req_id"));
		
		JSONObject jsonObject = httpRequest.getQueryAsJSONObject();
		
		if (jsonObject.get("id_token") != null) {
			return new CIBATokenDelivery(
				uri,
				clientNotificationToken,
				authRequestID,
				OIDCTokens.parse(jsonObject));
		} else {
			return new CIBATokenDelivery(
				uri,
				clientNotificationToken,
				authRequestID,
				Tokens.parse(jsonObject));
		}
	}
}
