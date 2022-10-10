/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.federation.api;


import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;
import net.minidev.json.JSONArray;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;


public class EntityListingSuccessResponseTest extends TestCase {
	
	
	static final List<EntityID> ENTITY_IDS = Collections.unmodifiableList(Arrays.asList(
		new EntityID("https://ntnu.andreas.labs.uninett.no/"),
		new EntityID("https://blackboard.ntnu.no/openid/callback"),
		new EntityID("https://serviceprovider.andreas.labs.uninett.no/application17")
	));
	
	
	public void testLifecycle() throws ParseException {
		
		EntityListingSuccessResponse response = new EntityListingSuccessResponse(ENTITY_IDS);
		assertEquals(ENTITY_IDS, response.getEntityListing());
		assertTrue(response.indicatesSuccess());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertEquals(200, httpResponse.getStatusCode());
		assertEquals("application/json; charset=UTF-8", httpResponse.getEntityContentType().toString());
		JSONArray jsonArray = httpResponse.getContentAsJSONArray();
		assertEquals(ENTITY_IDS.get(0).getValue(), jsonArray.get(0));
		assertEquals(ENTITY_IDS.get(1).getValue(), jsonArray.get(1));
		assertEquals(ENTITY_IDS.get(2).getValue(), jsonArray.get(2));
		assertEquals(3, jsonArray.size());
		
		response = EntityListingSuccessResponse.parse(httpResponse);
		assertEquals(ENTITY_IDS, response.getEntityListing());
		assertTrue(response.indicatesSuccess());
	}
	
	
	public void testLifecycle_emptyList() throws ParseException {
		
		EntityListingSuccessResponse response = new EntityListingSuccessResponse(Collections.<EntityID>emptyList());
		assertTrue(response.getEntityListing().isEmpty());
		assertTrue(response.indicatesSuccess());
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertEquals(200, httpResponse.getStatusCode());
		assertEquals("application/json; charset=UTF-8", httpResponse.getEntityContentType().toString());
		assertTrue(httpResponse.getContentAsJSONArray().isEmpty());
		
		response = EntityListingSuccessResponse.parse(httpResponse);
		assertTrue(response.getEntityListing().isEmpty());
		assertTrue(response.indicatesSuccess());
	}
	
	
	public void testRejectNotOK() {
		
		try {
			EntityListingSuccessResponse.parse(new HTTPResponse(400));
			fail();
		} catch (ParseException e) {
			assertEquals("Unexpected HTTP status code 400, must be [200]", e.getMessage());
		}
	}
}
