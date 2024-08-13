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

package com.nimbusds.openid.connect.sdk.claims;


import java.net.URI;
import java.util.*;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;


public class DistributedClaimsTest extends TestCase {
	

	public void testMinimalConstructor() {
		
		Set<String> names = new HashSet<>(Arrays.asList("email", "email_verified"));
		URI endpoint = URI.create("https://claims-provider.com");
		AccessToken token = new BearerAccessToken();
		
		DistributedClaims distributedClaims = new DistributedClaims(names, endpoint, token);
		assertNotNull(UUID.fromString(distributedClaims.getSourceID()));
		assertEquals(names, distributedClaims.getNames());
		assertEquals(endpoint, distributedClaims.getSourceEndpoint());
		assertEquals(token.getValue(), distributedClaims.getAccessToken().getValue());
		
		JSONObject jsonObject = new JSONObject();
		
		distributedClaims.mergeInto(jsonObject);
		
		assertEquals(distributedClaims.getSourceID(), ((JSONObject)jsonObject.get("_claim_names")).get("email"));
		assertEquals(distributedClaims.getSourceID(), ((JSONObject)jsonObject.get("_claim_names")).get("email_verified"));
		assertEquals(2, ((JSONObject)jsonObject.get("_claim_names")).size());
		
		assertEquals(endpoint.toString(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get(distributedClaims.getSourceID())).get("endpoint"));
		assertEquals(token.getValue(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get(distributedClaims.getSourceID())).get("access_token"));
		assertEquals(2, ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get(distributedClaims.getSourceID())).size());
		assertEquals(1, ((JSONObject)jsonObject.get("_claim_sources")).size());
		
		assertEquals(2, jsonObject.size());
	}
	

	public void testMinimalConstructor_noAccessToken() {
		
		Set<String> names = new HashSet<>(Arrays.asList("email", "email_verified"));
		URI endpoint = URI.create("https://claims-provider.com");
		
		DistributedClaims distributedClaims = new DistributedClaims(names, endpoint, null);
		assertNotNull(UUID.fromString(distributedClaims.getSourceID()));
		assertEquals(names, distributedClaims.getNames());
		assertEquals(endpoint, distributedClaims.getSourceEndpoint());
		assertNull(distributedClaims.getAccessToken());
		
		JSONObject jsonObject = new JSONObject();
		
		distributedClaims.mergeInto(jsonObject);
		
		assertEquals(distributedClaims.getSourceID(), ((JSONObject)jsonObject.get("_claim_names")).get("email"));
		assertEquals(distributedClaims.getSourceID(), ((JSONObject)jsonObject.get("_claim_names")).get("email_verified"));
		assertEquals(2, ((JSONObject)jsonObject.get("_claim_names")).size());
		
		assertEquals(endpoint.toString(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get(distributedClaims.getSourceID())).get("endpoint"));
		assertEquals(1, ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get(distributedClaims.getSourceID())).size());
		assertEquals(1, ((JSONObject)jsonObject.get("_claim_sources")).size());
		
		assertEquals(2, jsonObject.size());
	}
	
	
	public void testMainConstructor() {
		
		String sourceID = "src1";
		Set<String> names = new HashSet<>(Arrays.asList("email", "email_verified"));
		URI endpoint = URI.create("https://claims-provider.com");
		AccessToken token = new BearerAccessToken();
		
		DistributedClaims distributedClaims = new DistributedClaims(sourceID, names, endpoint, token);
		assertEquals(sourceID, distributedClaims.getSourceID());
		assertEquals(names, distributedClaims.getNames());
		assertEquals(endpoint, distributedClaims.getSourceEndpoint());
		assertEquals(token.getValue(), distributedClaims.getAccessToken().getValue());
		
		JSONObject jsonObject = new JSONObject();
		
		distributedClaims.mergeInto(jsonObject);
		
		assertEquals(distributedClaims.getSourceID(), ((JSONObject)jsonObject.get("_claim_names")).get("email"));
		assertEquals(distributedClaims.getSourceID(), ((JSONObject)jsonObject.get("_claim_names")).get("email_verified"));
		assertEquals(2, ((JSONObject)jsonObject.get("_claim_names")).size());
		
		assertEquals(endpoint.toString(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get(distributedClaims.getSourceID())).get("endpoint"));
		assertEquals(token.getValue(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get(distributedClaims.getSourceID())).get("access_token"));
		assertEquals(2, ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get(distributedClaims.getSourceID())).size());
		assertEquals(1, ((JSONObject)jsonObject.get("_claim_sources")).size());
		
		assertEquals(2, jsonObject.size());
	}
	
	
	public void testMainConstructor_noAccessToken() {
		
		String sourceID = "src1";
		Set<String> names = new HashSet<>(Arrays.asList("email", "email_verified"));
		URI endpoint = URI.create("https://claims-provider.com");
		
		DistributedClaims distributedClaims = new DistributedClaims(sourceID, names, endpoint, null);
		assertEquals(sourceID, distributedClaims.getSourceID());
		assertEquals(names, distributedClaims.getNames());
		assertEquals(endpoint, distributedClaims.getSourceEndpoint());
		assertNull(distributedClaims.getAccessToken());
		
		JSONObject jsonObject = new JSONObject();
		
		distributedClaims.mergeInto(jsonObject);
		
		assertEquals(distributedClaims.getSourceID(), ((JSONObject)jsonObject.get("_claim_names")).get("email"));
		assertEquals(distributedClaims.getSourceID(), ((JSONObject)jsonObject.get("_claim_names")).get("email_verified"));
		assertEquals(2, ((JSONObject)jsonObject.get("_claim_names")).size());
		
		assertEquals(endpoint.toString(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get(distributedClaims.getSourceID())).get("endpoint"));
		assertEquals(1, ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get(distributedClaims.getSourceID())).size());
		assertEquals(1, ((JSONObject)jsonObject.get("_claim_sources")).size());
		
		assertEquals(2, jsonObject.size());
	}
	
	
	public void testMergeTwoSources() {
		
		String sourceID1 = "src1";
		Set<String> names1 = new HashSet<>(Arrays.asList("email", "email_verified"));
		URI endpoint1 = URI.create("https://claims-provider.com");
		AccessToken token1 = new BearerAccessToken();
		
		DistributedClaims d1 = new DistributedClaims(sourceID1, names1, endpoint1, token1);
		assertEquals(sourceID1, d1.getSourceID());
		assertEquals(names1, d1.getNames());
		assertEquals(endpoint1, d1.getSourceEndpoint());
		assertEquals(token1, d1.getAccessToken());
		
		JSONObject jsonObject = new JSONObject();
		
		d1.mergeInto(jsonObject);
		
		String sourceID2 = "src2";
		Set<String> names2 = Collections.singleton("score");
		URI endpoint2 = URI.create("https://other-provider.com");
		AccessToken token2 = new BearerAccessToken();
		
		DistributedClaims d2 = new DistributedClaims(sourceID2, names2, endpoint2, token2);
		assertEquals(sourceID2, d2.getSourceID());
		assertEquals(names2, d2.getNames());
		assertEquals(endpoint2, d2.getSourceEndpoint());
		assertEquals(token2, d2.getAccessToken());
		
		d2.mergeInto(jsonObject);
		
		assertEquals(d1.getSourceID(), ((JSONObject)jsonObject.get("_claim_names")).get("email"));
		assertEquals(d1.getSourceID(), ((JSONObject)jsonObject.get("_claim_names")).get("email_verified"));
		assertEquals(d2.getSourceID(), ((JSONObject)jsonObject.get("_claim_names")).get("score"));
		assertEquals(3, ((JSONObject)jsonObject.get("_claim_names")).size());
		
		assertEquals(endpoint1.toString(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get(d1.getSourceID())).get("endpoint"));
		assertEquals(token1.getValue(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get(d1.getSourceID())).get("access_token"));
		assertEquals(2, ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get(d1.getSourceID())).size());
		
		assertEquals(endpoint2.toString(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get(d2.getSourceID())).get("endpoint"));
		assertEquals(token2.getValue(), ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get(d2.getSourceID())).get("access_token"));
		assertEquals(2, ((JSONObject)((JSONObject)jsonObject.get("_claim_sources")).get(d2.getSourceID())).size());
		
		assertEquals(2, ((JSONObject)jsonObject.get("_claim_sources")).size());
		
		assertEquals(2, jsonObject.size());
	}
	
	
	public void testRejectNullSourceID() {
		
		try {
			new DistributedClaims(null, Collections.singleton("score"), URI.create("https://provider.com"), new BearerAccessToken());
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The claims source identifier must not be null or empty", e.getMessage());
		}
	}
	
	
	public void testRejectEmptySourceID() {
		
		try {
			new DistributedClaims("", Collections.singleton("score"), URI.create("https://provider.com"), new BearerAccessToken());
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The claims source identifier must not be null or empty", e.getMessage());
		}
	}
	
	
	public void testRejectNullNames() {
		
		try {
			new DistributedClaims("src1", null, URI.create("https://provider.com"), new BearerAccessToken());
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The claim names must not be null or empty", e.getMessage());
		}
	}
	
	
	public void testRejectEmptyNames() {
		
		try {
			new DistributedClaims("src1", Collections.<String>emptySet(), URI.create("https://provider.com"), new BearerAccessToken());
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The claim names must not be null or empty", e.getMessage());
		}
	}
	
	
	public void testRejectNullEndpoint() {
		
		try {
			new DistributedClaims("src1", Collections.singleton("score"), null, new BearerAccessToken());
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
}
