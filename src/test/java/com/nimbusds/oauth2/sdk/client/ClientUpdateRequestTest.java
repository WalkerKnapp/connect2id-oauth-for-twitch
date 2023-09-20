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


import java.net.URI;
import java.net.URL;
import java.util.Set;

import junit.framework.TestCase;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.langtag.LangTag;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;


/**
 * Tests the client update request class.
 */
public class ClientUpdateRequestTest extends TestCase {
	

	public void testParse()
		throws Exception {
		
		URI regURI = new URI("https://server.example.com/register/s6BhdRkqt3");
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.PUT, regURI.toURL());
		httpRequest.setAuthorization("Bearer reg-23410913-abewfq.123483");
		httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);

		String json = "{\"client_id\":\"s6BhdRkqt3\","
			+ "    \"client_secret\": \"cf136dc3c1fc93f31185e5885805d\","
			+ "    \"redirect_uris\":[\"https://client.example.org/callback\",\"https://client.example.org/alt\"],"
			+ "    \"scope\": \"read write dolphin\","
			+ "    \"grant_types\": [\"authorization_code\", \"refresh_token\"],"
			+ "    \"token_endpoint_auth_method\": \"client_secret_basic\","
			+ "    \"jwks_uri\": \"https://client.example.org/my_public_keys.jwks\","
			+ "    \"client_name\":\"My New Example\","
			+ "    \"client_name#fr\":\"Mon Nouvel Exemple\","
			+ "    \"logo_uri\":\"https://client.example.org/newlogo.png\","
			+ "    \"logo_uri#fr\":\"https://client.example.org/fr/newlogo.png\""
			+ "   }";

		httpRequest.setBody(json);
		
		ClientUpdateRequest request = ClientUpdateRequest.parse(httpRequest);
		
		assertEquals(regURI, request.getEndpointURI());
		
		assertEquals("reg-23410913-abewfq.123483", request.getAccessToken().getValue());
		
		assertEquals("s6BhdRkqt3", request.getClientID().getValue());
		
		assertEquals("cf136dc3c1fc93f31185e5885805d", request.getClientSecret().getValue());
		
		ClientMetadata metadata = request.getClientMetadata();
		
		Set<URI> redirectURIs = metadata.getRedirectionURIs();
		assertTrue(redirectURIs.contains(new URI("https://client.example.org/callback")));
		assertTrue(redirectURIs.contains(new URI("https://client.example.org/alt")));
		assertEquals(2, redirectURIs.size());
		
		assertEquals(Scope.parse("read write dolphin"), metadata.getScope());
		
		Set<GrantType> grantTypes = metadata.getGrantTypes();
		assertTrue(grantTypes.contains(GrantType.AUTHORIZATION_CODE));
		assertTrue(grantTypes.contains(GrantType.REFRESH_TOKEN));
		assertEquals(2, grantTypes.size());
		
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, metadata.getTokenEndpointAuthMethod());
		
		assertEquals(new URI("https://client.example.org/my_public_keys.jwks"), metadata.getJWKSetURI());
		
		assertEquals("My New Example", metadata.getName());
		assertEquals("My New Example", metadata.getName(null));
		
		assertEquals("Mon Nouvel Exemple", metadata.getName(LangTag.parse("fr")));
		
		assertEquals(2, metadata.getNameEntries().size());
		
		assertEquals(new URI("https://client.example.org/newlogo.png"), metadata.getLogoURI());
		assertEquals(new URI("https://client.example.org/newlogo.png"), metadata.getLogoURI(null));
		
		assertEquals(new URI("https://client.example.org/fr/newlogo.png"), metadata.getLogoURI(LangTag.parse("fr")));
		
		assertEquals(2, metadata.getLogoURIEntries().size());
	}


	public void testParseWithMissingAuthorizationHeader()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.PUT, new URL("https://c2id.com/client-reg/123"));

		httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);

		String json = "{\"client_id\":\"123\","
			+ "    \"client_secret\": \"cf136dc3c1fc93f31185e5885805d\","
			+ "    \"redirect_uris\":[\"https://client.example.org/callback\",\"https://client.example.org/alt\"],"
			+ "    \"scope\": \"read write dolphin\","
			+ "    \"grant_types\": [\"authorization_code\", \"refresh_token\"],"
			+ "    \"token_endpoint_auth_method\": \"client_secret_basic\","
			+ "    \"jwks_uri\": \"https://client.example.org/my_public_keys.jwks\","
			+ "    \"client_name\":\"My New Example\","
			+ "    \"client_name#fr\":\"Mon Nouvel Exemple\","
			+ "    \"logo_uri\":\"https://client.example.org/newlogo.png\","
			+ "    \"logo_uri#fr\":\"https://client.example.org/fr/newlogo.png\""
			+ "   }";

		httpRequest.setBody(json);

		try {
			ClientUpdateRequest.parse(httpRequest);

			fail();

		} catch (ParseException e) {

			assertTrue(e.getErrorObject() instanceof BearerTokenError);

			BearerTokenError bte = (BearerTokenError)e.getErrorObject();

			assertEquals(401, bte.getHTTPStatusCode());
			assertNull(bte.getCode());
			assertEquals("Bearer", bte.toWWWAuthenticateHeader());
		}
	}
}