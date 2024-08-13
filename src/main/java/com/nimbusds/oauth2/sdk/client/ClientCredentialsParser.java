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
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.minidev.json.JSONObject;

import java.net.URI;
import java.util.Date;


/**
 * Client credentials parser.
 */
public class ClientCredentialsParser {


	/**
	 * Parses a client identifier from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The client identifier.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ClientID parseID(final JSONObject jsonObject)
		throws ParseException {

		return new ClientID(JSONObjectUtils.getString(jsonObject, "client_id"));
	}


	/**
	 * Parses a client identifier issue date from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The client identifier issue date, {@code null} if not
	 *         specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static Date parseIDIssueDate(final JSONObject jsonObject)
		throws ParseException {

		if (jsonObject.containsKey("client_id_issued_at")) {

			return new Date(JSONObjectUtils.getLong(jsonObject, "client_id_issued_at") * 1000);
		} else {
			return null;
		}
	}


	/**
	 * Parses a client secret from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The client secret, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static Secret parseSecret(final JSONObject jsonObject)
		throws ParseException {

		if (jsonObject.containsKey("client_secret")) {

			String value = JSONObjectUtils.getString(jsonObject, "client_secret");

			Date exp = null;

			if (jsonObject.containsKey("client_secret_expires_at")) {

				final long t = JSONObjectUtils.getLong(jsonObject, "client_secret_expires_at");

				if (t > 0) {
					exp = new Date(t * 1000);
				}
			}

			return new Secret(value, exp);
		} else {
			return null;
		}
	}


	/**
	 * Parses a client registration URI from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The client registration URI, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static URI parseRegistrationURI(final JSONObject jsonObject)
		throws ParseException {

		return JSONObjectUtils.getURI(jsonObject, "registration_client_uri", null);
	}


	/**
	 * Parses a client registration access token from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The client registration access token, {@code null} if not
	 *         specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static BearerAccessToken parseRegistrationAccessToken(final JSONObject jsonObject)
		throws ParseException {

		if (jsonObject.containsKey("registration_access_token")) {

			return new BearerAccessToken(
				JSONObjectUtils.getString(jsonObject, "registration_access_token"));
		} else {
			return null;
		}
	}
}
