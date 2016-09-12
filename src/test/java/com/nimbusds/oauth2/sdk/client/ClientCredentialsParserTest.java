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


import java.util.Date;

import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;


/**
 * Tests the client credentials parser.
 */
public class ClientCredentialsParserTest extends TestCase {


	public void testParseMinimal()
		throws Exception {

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("client_id", "123");

		assertEquals(new ClientID("123"), ClientCredentialsParser.parseID(jsonObject));
		assertNull(ClientCredentialsParser.parseIDIssueDate(jsonObject));
		assertNull(ClientCredentialsParser.parseSecret(jsonObject));
		assertNull(ClientCredentialsParser.parseRegistrationURI(jsonObject));
		assertNull(ClientCredentialsParser.parseRegistrationAccessToken(jsonObject));
	}


	public void testNoIDParseException() {

		try {
			ClientCredentialsParser.parseID(new JSONObject());
			fail();
		} catch (ParseException e) {
			// ok
		}
	}


	public void testParseSecretWithNoExpiration()
		throws ParseException {

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("client_secret", "secret");

		Secret secret = ClientCredentialsParser.parseSecret(jsonObject);

		assertEquals("secret", secret.getValue());
		assertFalse(secret.expired());
	}


	public void testParseSecretWithFutureExpiration()
		throws ParseException {

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("client_secret", "secret");
		Date futureDate = new Date(new Date().getTime() + 3600 * 1000l);
		jsonObject.put("client_secret_expires_at", futureDate.getTime() / 1000l);

		Secret secret = ClientCredentialsParser.parseSecret(jsonObject);
		assertEquals("secret", secret.getValue());
		assertFalse(secret.expired());
		assertEquals(futureDate.getTime() / 1000l, secret.getExpirationDate().getTime() / 1000l);
	}


	public void testParseSecretWithPastExpiration()
		throws ParseException {

		JSONObject jsonObject = new JSONObject();
		jsonObject.put("client_secret", "secret");
		Date pastDate = new Date(new Date().getTime() - 3600 * 1000l);
		jsonObject.put("client_secret_expires_at", pastDate.getTime() / 1000l);

		Secret secret = ClientCredentialsParser.parseSecret(jsonObject);
		assertEquals("secret", secret.getValue());
		assertTrue(secret.expired());
		assertEquals(pastDate.getTime() / 1000l, secret.getExpirationDate().getTime() / 1000l);
	}
}
