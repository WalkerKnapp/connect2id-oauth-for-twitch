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

package com.nimbusds.oauth2.sdk.as;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;


public class AuthorizationServerEndpointMetadataTest extends TestCase {
	
	
	public void testRegisteredParameters() {
		
		Set<String> paramNames = AuthorizationServerEndpointMetadata.getRegisteredParameterNames();
		
		assertTrue(paramNames.contains("authorization_endpoint"));
		assertTrue(paramNames.contains("token_endpoint"));
		assertTrue(paramNames.contains("registration_endpoint"));
		assertTrue(paramNames.contains("pushed_authorization_request_endpoint"));
		assertTrue(paramNames.contains("request_object_endpoint"));
		assertTrue(paramNames.contains("introspection_endpoint"));
		assertTrue(paramNames.contains("revocation_endpoint"));
		assertTrue(paramNames.contains("device_authorization_endpoint"));
		assertTrue(paramNames.contains("backchannel_authentication_endpoint"));
		assertTrue(paramNames.contains("federation_registration_endpoint"));
		assertEquals(10, paramNames.size());
	}


	public void testEmpty() throws ParseException {
		
		AuthorizationServerEndpointMetadata endpointMetadata = new AuthorizationServerEndpointMetadata();
		
		assertNull(endpointMetadata.getAuthorizationEndpointURI());
		assertNull(endpointMetadata.getTokenEndpointURI());
		assertNull(endpointMetadata.getRegistrationEndpointURI());
		assertNull(endpointMetadata.getPushedAuthorizationRequestEndpointURI());
		assertNull(endpointMetadata.getRequestObjectEndpoint());
		assertNull(endpointMetadata.getIntrospectionEndpointURI());
		assertNull(endpointMetadata.getRevocationEndpointURI());
		assertNull(endpointMetadata.getDeviceAuthorizationEndpointURI());
		assertNull(endpointMetadata.getBackChannelAuthenticationEndpoint());
		assertNull(endpointMetadata.getFederationRegistrationEndpointURI());
		
		JSONObject jsonObject = endpointMetadata.toJSONObject();
		
		ReadOnlyAuthorizationServerEndpointMetadata parsedEndpointMetadata = AuthorizationServerEndpointMetadata.parse(jsonObject);
		
		assertNull(parsedEndpointMetadata.getAuthorizationEndpointURI());
		assertNull(parsedEndpointMetadata.getTokenEndpointURI());
		assertNull(parsedEndpointMetadata.getRegistrationEndpointURI());
		assertNull(parsedEndpointMetadata.getPushedAuthorizationRequestEndpointURI());
		assertNull(parsedEndpointMetadata.getRequestObjectEndpoint());
		assertNull(parsedEndpointMetadata.getIntrospectionEndpointURI());
		assertNull(parsedEndpointMetadata.getRevocationEndpointURI());
		assertNull(parsedEndpointMetadata.getDeviceAuthorizationEndpointURI());
		assertNull(parsedEndpointMetadata.getBackChannelAuthenticationEndpointURI());
		assertNull(parsedEndpointMetadata.getBackChannelAuthenticationEndpoint());
		assertNull(endpointMetadata.getFederationRegistrationEndpointURI());
	}
	
	
	public void testGetterAndSetters() throws ParseException, URISyntaxException {
		
		AuthorizationServerEndpointMetadata endpointMetadata = new AuthorizationServerEndpointMetadata();
		
		endpointMetadata.setAuthorizationEndpointURI(new URI("https://c2id.com/authz"));
		assertEquals(new URI("https://c2id.com/authz"), endpointMetadata.getAuthorizationEndpointURI());
		
		endpointMetadata.setTokenEndpointURI(new URI("https://c2id.com/token"));
		assertEquals(new URI("https://c2id.com/token"), endpointMetadata.getTokenEndpointURI());
		
		endpointMetadata.setRegistrationEndpointURI(new URI("https://c2id.com/reg"));
		assertEquals(new URI("https://c2id.com/reg"), endpointMetadata.getRegistrationEndpointURI());
		
		endpointMetadata.setIntrospectionEndpointURI(new URI("https://c2id.com/inspect"));
		assertEquals(new URI("https://c2id.com/inspect"), endpointMetadata.getIntrospectionEndpointURI());
		
		endpointMetadata.setRevocationEndpointURI(new URI("https://c2id.com/revoke"));
		assertEquals(new URI("https://c2id.com/revoke"), endpointMetadata.getRevocationEndpointURI());
		
		endpointMetadata.setPushedAuthorizationRequestEndpointURI(new URI("https://c2id.com/par"));
		assertEquals(new URI("https://c2id.com/par"), endpointMetadata.getPushedAuthorizationRequestEndpointURI());
		
		endpointMetadata.setRequestObjectEndpoint(new URI("https://c2id.com/jar"));
		assertEquals(new URI("https://c2id.com/jar"), endpointMetadata.getRequestObjectEndpoint());
		
		endpointMetadata.setDeviceAuthorizationEndpointURI(new URI("https://c2id.com/device"));
		assertEquals(new URI("https://c2id.com/device"), endpointMetadata.getDeviceAuthorizationEndpointURI());
		
		endpointMetadata.setBackChannelAuthenticationEndpointURI(new URI("https://c2id.com/ciba"));
		assertEquals(new URI("https://c2id.com/ciba"), endpointMetadata.getBackChannelAuthenticationEndpointURI());
		
		endpointMetadata.setFederationRegistrationEndpointURI(new URI("https://c2id.com/reg/federation"));
		assertEquals(new URI("https://c2id.com/reg/federation"), endpointMetadata.getFederationRegistrationEndpointURI());
		
		JSONObject jsonObject = endpointMetadata.toJSONObject();
		
		for (String paramName: AuthorizationServerEndpointMetadata.getRegisteredParameterNames()) {
			assertTrue(paramName, jsonObject.containsKey(paramName));
		}
		
		endpointMetadata = AuthorizationServerEndpointMetadata.parse(jsonObject);
		
		assertEquals(new URI("https://c2id.com/authz"), endpointMetadata.getAuthorizationEndpointURI());
		assertEquals(new URI("https://c2id.com/token"), endpointMetadata.getTokenEndpointURI());
		assertEquals(new URI("https://c2id.com/reg"), endpointMetadata.getRegistrationEndpointURI());
		assertEquals(new URI("https://c2id.com/inspect"), endpointMetadata.getIntrospectionEndpointURI());
		assertEquals(new URI("https://c2id.com/revoke"), endpointMetadata.getRevocationEndpointURI());
		assertEquals(new URI("https://c2id.com/par"), endpointMetadata.getPushedAuthorizationRequestEndpointURI());
		assertEquals(new URI("https://c2id.com/jar"), endpointMetadata.getRequestObjectEndpoint());
		assertEquals(new URI("https://c2id.com/device"), endpointMetadata.getDeviceAuthorizationEndpointURI());
		assertEquals(new URI("https://c2id.com/ciba"), endpointMetadata.getBackChannelAuthenticationEndpointURI());
		assertEquals(new URI("https://c2id.com/ciba"), endpointMetadata.getBackChannelAuthenticationEndpoint());
		assertEquals(new URI("https://c2id.com/reg/federation"), endpointMetadata.getFederationRegistrationEndpointURI());
	}
}
