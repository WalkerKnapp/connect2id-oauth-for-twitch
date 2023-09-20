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
import java.util.*;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;


public class ClientRegistrationRequestTest extends TestCase {


	@SuppressWarnings("unchecked")
	public void testSerializeAndParse()
		throws Exception {

		URI uri = new URI("https://c2id.com/client-reg");

		ClientMetadata metadata = new ClientMetadata();
		metadata.setName("My test app");
		metadata.setRedirectionURI(new URI("https://client.com/callback"));
		metadata.applyDefaults();

		BearerAccessToken accessToken = new BearerAccessToken();

		ClientRegistrationRequest request = new ClientRegistrationRequest(uri, metadata, accessToken);

		HTTPRequest httpRequest = request.toHTTPRequest();

		assertEquals(uri.toString(), httpRequest.getURL().toString());
		assertTrue(httpRequest.getEntityContentType().toString().startsWith("application/json"));

		JSONObject jsonObject = httpRequest.getQueryAsJSONObject();

//		System.out.println(jsonObject);

		List<String> stringList = (List<String>)jsonObject.get("redirect_uris");
		assertEquals(metadata.getRedirectionURIs().iterator().next().toString(), stringList.get(0));
		assertEquals(metadata.getName(), (String) jsonObject.get("client_name"));
		assertEquals("client_secret_basic", (String)jsonObject.get("token_endpoint_auth_method"));
		stringList = (List<String>)jsonObject.get("response_types");
		assertEquals("code", stringList.get(0));
		stringList = (List<String>)jsonObject.get("grant_types");
		assertEquals("authorization_code", stringList.get(0));

		request = ClientRegistrationRequest.parse(httpRequest);

		assertEquals(metadata.getName(), request.getClientMetadata().getName());
		assertEquals(metadata.getRedirectionURIs().iterator().next().toString(), request.getClientMetadata().getRedirectionURIs().iterator().next().toString());
		assertEquals(metadata.getTokenEndpointAuthMethod(), request.getClientMetadata().getTokenEndpointAuthMethod());
		assertEquals("code", request.getClientMetadata().getResponseTypes().iterator().next().toString());
		assertEquals("authorization_code", request.getClientMetadata().getGrantTypes().iterator().next().toString());
	}
	
	
	public void _testExampleRegisterForCodeGrant()
		throws Exception {
		
		// The client registration endpoint
		URI clientsEndpoint = new URI("https://demo.c2id.com/c2id/clients");
		
		// Master API token for the clients endpoint
		BearerAccessToken masterToken = new BearerAccessToken("ztucZS1ZyFKgh0tUEruUtiSTXhnexmd6");
		
		// We want to register a client for the code grant
		ClientMetadata clientMetadata = new ClientMetadata();
		clientMetadata.setGrantTypes(Collections.singleton(GrantType.AUTHORIZATION_CODE));
		clientMetadata.setRedirectionURI(URI.create("https://example.com/cb"));
		clientMetadata.setName("My Client App");
		
		ClientRegistrationRequest regRequest = new ClientRegistrationRequest(
			clientsEndpoint,
			clientMetadata,
			masterToken
		);
		
		HTTPResponse httpResponse = regRequest.toHTTPRequest().send();
		
		ClientRegistrationResponse regResponse = ClientRegistrationResponse.parse(httpResponse);
		
		if (! regResponse.indicatesSuccess()) {
			// We have an error
			ClientRegistrationErrorResponse errorResponse = (ClientRegistrationErrorResponse)regResponse;
			System.err.println(errorResponse.getErrorObject());
			return;
		}
		
		// Successful registration
		ClientInformationResponse successResponse = (ClientInformationResponse)regResponse;
		
		ClientInformation clientInfo = successResponse.getClientInformation();
		
		// The client credentials - store them:
		
		// The client_id
		System.out.println("Client ID: " + clientInfo.getID());
		
		// The client_secret
		System.out.println("Client secret: " + clientInfo.getSecret().getValue());
		
		// The client's registration resource
		System.out.println("Client registration URI: " + clientInfo.getRegistrationURI());
		
		// The token for accessing the client's registration (for update, etc)
		System.out.println("Client reg access token: " + clientInfo.getRegistrationAccessToken());
		
		// Print the remaining client metadata
		System.out.println("Client metadata: " + clientInfo.getMetadata().toJSONObject());
		
		
		// Query
		ClientReadRequest readRequest = new ClientReadRequest(
			clientInfo.getRegistrationURI(),
			clientInfo.getRegistrationAccessToken()
		);
		
		httpResponse = readRequest.toHTTPRequest().send();
		
		regResponse = ClientRegistrationResponse.parse(httpResponse);
		
		if (! regResponse.indicatesSuccess()) {
			// We have an error
			ClientRegistrationErrorResponse errorResponse = (ClientRegistrationErrorResponse)regResponse;
			System.err.println(errorResponse.getErrorObject());
			return;
		}
		
		// Success
		successResponse = (ClientInformationResponse)regResponse;
		
		System.out.println("Client registration data: " + successResponse.getClientInformation().toJSONObject());
		
		
		// Update client name
		clientMetadata = clientInfo.getMetadata();
		clientMetadata.setName("My app has a new name");
		
		// Send request
		ClientUpdateRequest updateRequest = new ClientUpdateRequest(
			clientInfo.getRegistrationURI(),
			clientInfo.getID(),
			clientInfo.getRegistrationAccessToken(),
			clientMetadata,
			clientInfo.getSecret()
		);
	
		httpResponse = updateRequest.toHTTPRequest().send();
		
		regResponse = ClientRegistrationResponse.parse(httpResponse);
		
		if (! regResponse.indicatesSuccess()) {
			// We have an error
			ClientRegistrationErrorResponse errorResponse = (ClientRegistrationErrorResponse)regResponse;
			System.err.println(errorResponse.getErrorObject());
			return;
		}
		
		// Success
		successResponse = (ClientInformationResponse)regResponse;
		
		// Ensure the client name has been updated
		clientInfo = successResponse.getClientInformation();
		System.out.println("Client name: " + clientInfo.getMetadata().getName());
		
		
		// Request deletion
		ClientDeleteRequest deleteRequest = new ClientDeleteRequest(
			clientInfo.getRegistrationURI(),
			clientInfo.getRegistrationAccessToken()
		);
		
		httpResponse = deleteRequest.toHTTPRequest().send();
		
		regResponse = ClientRegistrationResponse.parse(httpResponse);
		
		if (! regResponse.indicatesSuccess()) {
			// We have an error
			ClientRegistrationErrorResponse errorResponse = (ClientRegistrationErrorResponse)regResponse;
			System.err.println(errorResponse.getErrorObject());
			return;
		}
		
		// Success: nothing returned
	}
	

	public void testParse()
		throws Exception {
		
		URI endpointURI = new URI("https://server.example.com/register/");
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpointURI.toURL());
		httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);
		
		String json = "{"
			+ "    \"redirect_uris\":[\"https://client.example.org/callback\","
			+ "       \"https://client.example.org/callback2\"],"
			+ "    \"client_name\":\"My Example Client\","
			+ "    \"client_name#ja-Jpan-JP\":\"\\u30AF\\u30E9\\u30A4\\u30A2\\u30F3\\u30C8\\u540D\","
			+ "    \"token_endpoint_auth_method\":\"client_secret_basic\","
			+ "    \"scope\":\"read write dolphin\","
			+ "    \"logo_uri\":\"https://client.example.org/logo.png\","
			+ "    \"jwks_uri\":\"https://client.example.org/my_public_keys.jwks\""
			+ "   }";
		
		
		httpRequest.setBody(json);
		
		ClientRegistrationRequest request = ClientRegistrationRequest.parse(httpRequest);
		
		assertNull(request.getAccessToken());
		
		ClientMetadata metadata = request.getClientMetadata();
		
		Set<URI> redirectURIs = metadata.getRedirectionURIs();
		assertTrue(redirectURIs.contains(new URI("https://client.example.org/callback")));
		assertTrue(redirectURIs.contains(new URI("https://client.example.org/callback2")));
		assertEquals(2, redirectURIs.size());
		
		assertEquals("My Example Client", metadata.getName());
		assertEquals("\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D", metadata.getName(LangTag.parse("ja-Jpan-JP")));
		
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, metadata.getTokenEndpointAuthMethod());
		
		assertEquals(Scope.parse("read write dolphin"), metadata.getScope());
		
		assertEquals(new URI("https://client.example.org/logo.png"), metadata.getLogoURI());
		
		assertEquals(new URI("https://client.example.org/my_public_keys.jwks"), metadata.getJWKSetURI());
	}


	public void testSoftwareStatement()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer("https://c2id.com")
			.build();

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
		jwt.sign(new MACSigner("01234567890123456789012345678901"));

		ClientMetadata metadata = new ClientMetadata();
		metadata.setRedirectionURI(new URI("https://client.com/in"));
		metadata.setName("Test App");

		ClientRegistrationRequest request = new ClientRegistrationRequest(new URI("https://c2id.com/reg"), metadata, jwt, null);

		assertEquals(metadata, request.getClientMetadata());
		assertEquals(jwt, request.getSoftwareStatement());
		assertNull(request.getAccessToken());

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = ClientRegistrationRequest.parse(httpRequest);

		assertEquals("https://client.com/in", request.getClientMetadata().getRedirectionURIs().iterator().next().toString());
		assertEquals("Test App", request.getClientMetadata().getName());
		assertEquals(jwt.serialize(), request.getSoftwareStatement().getParsedString());
		assertTrue(request.getSoftwareStatement().verify(new MACVerifier("01234567890123456789012345678901")));
	}


	public void testRejectUnsignedSoftwareStatement()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer("https://c2id.com")
			.build();

		ClientMetadata metadata = new ClientMetadata();
		metadata.setRedirectionURI(new URI("https://client.com/in"));
		metadata.setName("Test App");

		try {
			new ClientRegistrationRequest(
				new URI("https://c2id.com/reg"),
				metadata,
				new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet),
				null);

		} catch (IllegalArgumentException e) {

			// ok
			assertEquals("The software statement JWT must be signed", e.getMessage());
		}

	}


	public void testRejectSoftwareStatementWithoutIssuer()
		throws Exception {

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder().build());
		jwt.sign(new MACSigner("01234567890123456789012345678901"));

		ClientMetadata metadata = new ClientMetadata();
		metadata.setRedirectionURI(new URI("https://client.com/in"));
		metadata.setName("Test App");

		try {
			new ClientRegistrationRequest(
				new URI("https://c2id.com/reg"),
				metadata,
				jwt,
				null);

		} catch (IllegalArgumentException e) {

			// ok
			assertEquals("The software statement JWT must contain an 'iss' claim", e.getMessage());
		}
	}
	
	
	//     POST /register HTTP/1.1
	//     Content-Type: application/json
	//     Accept: application/json
	//     Host: server.example.com
	//     Authorization: Bearer
	//
	//     {
	//      "redirect_uris": [
	//        "https://client.example.org/callback",
	//        "https://client.example.org/callback2"],
	//      "client_name": "My Example Client",
	//      "token_endpoint_auth_method": "client_secret_basic",
	//     }
	public void testParseExampleFromHTTPRequest()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://server.example.com/register"));
		httpRequest.setAuthorization("Bearer ooyeph4wij2eyuagax4een8Eeshohpha");
		httpRequest.setContentType("application/json");
		httpRequest.setAccept("application/json");
		httpRequest.setBody("{\n" +
			" \"redirect_uris\": [\n" +
			"   \"https://client.example.org/callback\",\n" +
			"   \"https://client.example.org/callback2\"],\n" +
			" \"client_name\": \"My Example Client\",\n" +
			" \"token_endpoint_auth_method\": \"client_secret_basic\"\n" +
			"}");
		
		ClientRegistrationRequest registrationRequest = ClientRegistrationRequest.parse(httpRequest);
		assertEquals(new BearerAccessToken("ooyeph4wij2eyuagax4een8Eeshohpha"), registrationRequest.getAccessToken());
		assertEquals(new URI("https://server.example.com/register"), registrationRequest.getEndpointURI());
		
		assertEquals(new HashSet<>(Arrays.asList(new URI("https://client.example.org/callback"), new URI("https://client.example.org/callback2"))), registrationRequest.getClientMetadata().getRedirectionURIs());
		assertEquals("My Example Client", registrationRequest.getClientMetadata().getName());
		assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registrationRequest.getClientMetadata().getTokenEndpointAuthMethod());
	}
}