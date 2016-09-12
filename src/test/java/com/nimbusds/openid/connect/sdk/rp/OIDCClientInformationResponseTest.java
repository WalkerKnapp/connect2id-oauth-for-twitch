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

package com.nimbusds.openid.connect.sdk.rp;


import java.net.URI;
import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


/**
 * Tests the OIDC client information response.
 */
public class OIDCClientInformationResponseTest extends TestCase {


	public void testCycle()
		throws Exception {

		ClientID id = new ClientID("123");
		Date issueDate = new Date(new Date().getTime() / 1000 * 1000);
		OIDCClientMetadata metadata = new OIDCClientMetadata();
		metadata.setRedirectionURI(new URI("https://client.com/cb"));
		metadata.applyDefaults();
		Secret secret = new Secret();
		BearerAccessToken accessToken = new BearerAccessToken();
		URI uri = new URI("https://c2id.com/client-reg/123");

		OIDCClientInformation info = new OIDCClientInformation(
			id, issueDate, metadata, secret, uri, accessToken);

		OIDCClientInformationResponse response = new OIDCClientInformationResponse(info);

		assertTrue(response.indicatesSuccess());
		assertEquals(info, response.getOIDCClientInformation());
		assertEquals(info, response.getClientInformation());

		HTTPResponse httpResponse = response.toHTTPResponse();

		response = OIDCClientInformationResponse.parse(httpResponse);

		assertTrue(response.indicatesSuccess());
		assertEquals(id.getValue(), response.getClientInformation().getID().getValue());
		assertEquals(issueDate, response.getClientInformation().getIDIssueDate());
		assertEquals("https://client.com/cb", response.getClientInformation().getMetadata().getRedirectionURIs().iterator().next().toString());
		assertEquals(secret.getValue(), response.getClientInformation().getSecret().getValue());
		assertEquals(uri.toString(), response.getClientInformation().getRegistrationURI().toString());
		assertEquals(accessToken.getValue(), response.getClientInformation().getRegistrationAccessToken().getValue());
	}
}
