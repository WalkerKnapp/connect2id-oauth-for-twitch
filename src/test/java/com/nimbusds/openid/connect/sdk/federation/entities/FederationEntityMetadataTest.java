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

package com.nimbusds.openid.connect.sdk.federation.entities;


import java.net.URI;
import java.util.Arrays;
import java.util.List;

import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


public class FederationEntityMetadataTest extends TestCase {
	
	
	public void testConstructorWithEndpoint() throws ParseException {
		
		URI fetchEndpoint = URI.create("https://c2id.com/fed");
		FederationEntityMetadata metadata = new FederationEntityMetadata(fetchEndpoint);
		assertEquals(fetchEndpoint, metadata.getFederationFetchEndpointURI());
		
		assertNull(metadata.getFederationListEndpointURI());
		URI listEndpoint = URI.create("https://c2id.com/fed/list");
		metadata.setFederationListEndpointURI(listEndpoint);
		assertEquals(listEndpoint, metadata.getFederationListEndpointURI());
		
		assertNull(metadata.getFederationResolveEndpointURI());
		URI resolveEndpoint = URI.create("https://c2id.com/fed/resolve");
		metadata.setFederationResolveEndpointURI(resolveEndpoint);
		assertEquals(resolveEndpoint, metadata.getFederationResolveEndpointURI());
		
		assertNull(metadata.getOrganizationName());
		String name = "Org name";
		metadata.setOrganizationName(name);
		assertEquals(name, metadata.getOrganizationName());
		
		assertNull(metadata.getContacts());
		List<String> contacts = Arrays.asList("federation@c2id.com", "+359102030");
		metadata.setContacts(contacts);
		assertEquals(contacts, metadata.getContacts());
		
		assertNull(metadata.getPolicyURI());
		URI policyURI = URI.create("https://c2id.com/federation-policy.html");
		metadata.setPolicyURI(policyURI);
		assertEquals(policyURI, metadata.getPolicyURI());
		
		assertNull(metadata.getHomepageURI());
		URI homepageURI = URI.create("https://c2id.com");
		metadata.setHomepageURI(homepageURI);
		assertEquals(homepageURI, metadata.getHomepageURI());
		
		JSONObject jsonObject = metadata.toJSONObject();
		assertEquals(fetchEndpoint.toString(), jsonObject.get("federation_fetch_endpoint"));
		assertEquals(listEndpoint.toString(), jsonObject.get("federation_list_endpoint"));
		assertEquals(resolveEndpoint.toString(), jsonObject.get("federation_resolve_endpoint"));
		assertEquals(name, jsonObject.get("organization_name"));
		assertEquals(contacts, JSONObjectUtils.getStringList(jsonObject, "contacts"));
		assertEquals(policyURI.toString(), jsonObject.get("policy_uri"));
		assertEquals(homepageURI.toString(), jsonObject.get("homepage_uri"));
		
		metadata = FederationEntityMetadata.parse(metadata.toJSONObject().toJSONString());
		
		assertEquals(fetchEndpoint, metadata.getFederationFetchEndpointURI());
		assertEquals(listEndpoint, metadata.getFederationListEndpointURI());
		assertEquals(resolveEndpoint, metadata.getFederationResolveEndpointURI());
		assertEquals(contacts, metadata.getContacts());
		assertEquals(policyURI, metadata.getPolicyURI());
		assertEquals(homepageURI, metadata.getHomepageURI());
	}
	
	
	public void testConstructorWithNoFetchEndpoint() throws ParseException {
		
		FederationEntityMetadata metadata = new FederationEntityMetadata(null);
		assertNull(metadata.getFederationFetchEndpointURI());
		
		JSONObject jsonObject = metadata.toJSONObject();
		assertTrue(jsonObject.isEmpty());
		
		String json = metadata.toJSONObject().toJSONString();
		assertEquals("{}", json);
		
		metadata = FederationEntityMetadata.parse(json);
		
		assertNull(metadata.getFederationFetchEndpointURI());
		assertNull(metadata.getFederationListEndpointURI());
		assertNull(metadata.getFederationResolveEndpointURI());
		assertNull(metadata.getOrganizationName());
		assertNull(metadata.getContacts());
		assertNull(metadata.getPolicyURI());
		assertNull(metadata.getHomepageURI());
	}
	
	
	public void testParseExample()
		throws ParseException {
		
		String json =
			"{" +
			"  \"federation_fetch_endpoint\":\"https://example.com/federation_fetch\"," +
			"  \"federation_list_endpoint\":\"https://example.com/federation_list\"," +
			"  \"organization_name\": \"The example cooperation\"," +
			"  \"homepage_uri\": \"https://www.example.com\"" +
			"}";
		
		FederationEntityMetadata metadata = FederationEntityMetadata.parse(json);
		
		assertEquals(URI.create("https://example.com/federation_fetch"), metadata.getFederationFetchEndpointURI());
		assertEquals(URI.create("https://example.com/federation_list"), metadata.getFederationListEndpointURI());
		assertEquals("The example cooperation", metadata.getOrganizationName());
		assertEquals(URI.create("https://www.example.com"), metadata.getHomepageURI());
	}
}
