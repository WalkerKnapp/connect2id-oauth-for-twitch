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

package com.nimbusds.openid.connect.sdk.token;


import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * ID token, access token and optional refresh token.
 */
public final class OIDCTokens extends Tokens {


	/**
	 * The ID token serialised to a JWT, {@code null} if not specified.
	 */
	private final JWT idToken;


	/**
	 * The ID token as raw string (for more efficient serialisation),
	 * {@code null} if not specified.
	 */
	private final String idTokenString;
	
	
	/**
	 * Creates a new OpenID Connect tokens instance.
	 *
	 * @param idToken      The ID token. Must not be {@code null}.
	 * @param accessToken  The access token. Must not be {@code null}.
	 * @param refreshToken The refresh token. If none {@code null}.
	 */
	public OIDCTokens(final JWT idToken, final AccessToken accessToken, final RefreshToken refreshToken) {
		super(accessToken, refreshToken);
		this.idToken = Objects.requireNonNull(idToken);
		idTokenString = null;
	}
	
	
	/**
	 * Creates a new OpenID Connect tokens instance.
	 *
	 * @param idTokenString The ID token string. Must not be {@code null}.
	 * @param accessToken   The access token. Must not be {@code null}.
	 * @param refreshToken  The refresh token. If none {@code null}.
	 */
	public OIDCTokens(final String idTokenString, final AccessToken accessToken, final RefreshToken refreshToken) {
		super(accessToken, refreshToken);
		this.idTokenString = Objects.requireNonNull(idTokenString);
		idToken = null;
	}
	
	
	/**
	 * Creates a new OpenID Connect tokens instance without an ID token.
	 * Intended for token responses from a refresh token grant where the ID
	 * token is optional.
	 *
	 * @param accessToken  The access token. Must not be {@code null}.
	 * @param refreshToken The refresh token. If none {@code null}.
	 */
	public OIDCTokens(final AccessToken accessToken, final RefreshToken refreshToken) {
		
		super(accessToken, refreshToken);
		this.idToken = null;
		this.idTokenString = null;
	}


	/**
	 * Gets the ID token.
	 *
	 * @return The ID token, {@code null} if none or if parsing to a JWT
	 *         failed.
	 */
	public JWT getIDToken() {

		if (idToken != null)
			return idToken;

		if (idTokenString != null) {

			try {
				return JWTParser.parse(idTokenString);

			} catch (java.text.ParseException e) {

				return null;
			}
		}

		return null;
	}


	/**
	 * Gets the ID token string.
	 *
	 * @return The ID token string, {@code null} if none or if
	 *         serialisation to a string failed.
	 */
	public String getIDTokenString() {

		if (idTokenString != null)
			return idTokenString;

		if (idToken != null) {

			// Reproduce originally parsed string if any
			if (idToken.getParsedString() != null)
				return idToken.getParsedString();

			try {
				return idToken.serialize();

			} catch(IllegalStateException e) {

				return null;
			}
		}

		return null;
	}


	@Override
	public Set<String> getParameterNames() {

		Set<String> paramNames = new HashSet<>(super.getParameterNames());
		if (idToken != null || idTokenString != null) {
			paramNames.add("id_token");
		}
		return Collections.unmodifiableSet(paramNames);
	}


	@Override
	public JSONObject toJSONObject() {

		JSONObject o = super.toJSONObject();
		if (getIDTokenString() != null) {
			o.put("id_token", getIDTokenString());
		}
		return o;
	}


	/**
	 * Parses an OpenID Connect tokens instance from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The OpenID Connect tokens.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OpenID Connect tokens instance.
	 */
	public static OIDCTokens parse(final JSONObject jsonObject)
		throws ParseException {
		
		AccessToken accessToken = AccessToken.parse(jsonObject);
		
		RefreshToken refreshToken = RefreshToken.parse(jsonObject);
		
		if (jsonObject.get("id_token") != null) {
			
			JWT idToken;
			try {
				idToken = JWTParser.parse(JSONObjectUtils.getString(jsonObject, "id_token"));
			} catch (java.text.ParseException e) {
				throw new ParseException("Couldn't parse ID token: " + e.getMessage(), e);
			}
			
			return new OIDCTokens(idToken, accessToken, refreshToken);
			
		} else {
		
			// Likely a token response from a refresh token grant without an ID token
			return new OIDCTokens(accessToken, refreshToken);
		}
	}
}
