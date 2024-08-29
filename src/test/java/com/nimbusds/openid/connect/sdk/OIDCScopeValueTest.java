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

package com.nimbusds.openid.connect.sdk;


import com.nimbusds.oauth2.sdk.Scope;
import junit.framework.TestCase;

import net.minidev.json.JSONObject;

import java.util.*;


/**
 * Tests the OpenID Connect scope value class.
 */
public class OIDCScopeValueTest extends TestCase {


	public void testValues() {

		assertEquals("openid", OIDCScopeValue.OPENID.getValue());
		assertEquals("profile", OIDCScopeValue.PROFILE.getValue());
		assertEquals("email", OIDCScopeValue.EMAIL.getValue());
		assertEquals("address", OIDCScopeValue.ADDRESS.getValue());
		assertEquals("phone", OIDCScopeValue.PHONE.getValue());
		assertEquals("offline_access", OIDCScopeValue.OFFLINE_ACCESS.getValue());

		assertEquals(6, OIDCScopeValue.values().length);
	}


	public void testToClaimsRequestJSON() {

		JSONObject o = OIDCScopeValue.OPENID.toClaimsRequestJSONObject();
		assertTrue(o.containsKey("sub"));
		assertTrue((Boolean)((JSONObject)o.get("sub")).get("essential"));
		assertEquals(1, o.size());

		o = OIDCScopeValue.PROFILE.toClaimsRequestJSONObject();
		assertTrue(o.containsKey("name"));
		assertNull(o.get("name"));
		assertTrue(o.containsKey("family_name"));
		assertNull(o.get("family_name"));
		assertTrue(o.containsKey("given_name"));
		assertNull(o.get("given_name"));
		assertTrue(o.containsKey("middle_name"));
		assertNull(o.get("middle_name"));
		assertTrue(o.containsKey("nickname"));
		assertNull(o.get("nickname"));
		assertTrue(o.containsKey("preferred_username"));
		assertNull(o.get("preferred_username"));
		assertTrue(o.containsKey("profile"));
		assertNull(o.get("profile"));
		assertTrue(o.containsKey("picture"));
		assertNull(o.get("picture"));
		assertTrue(o.containsKey("website"));
		assertNull(o.get("website"));
		assertTrue(o.containsKey("gender"));
		assertNull(o.get("gender"));
		assertTrue(o.containsKey("birthdate"));
		assertNull(o.get("birthdate"));
		assertTrue(o.containsKey("zoneinfo"));
		assertNull(o.get("zoneinfo"));
		assertTrue(o.containsKey("locale"));
		assertNull(o.get("locale"));
		assertTrue(o.containsKey("updated_at"));
		assertNull(o.get("updated_at"));
		assertEquals(14, o.size());

		o = OIDCScopeValue.EMAIL.toClaimsRequestJSONObject();
		assertTrue(o.containsKey("email"));
		assertNull(o.get("email"));
		assertTrue(o.containsKey("email_verified"));
		assertNull(o.get("email_verified"));
		assertEquals(2, o.size());


		o = OIDCScopeValue.ADDRESS.toClaimsRequestJSONObject();
		assertTrue(o.containsKey("address"));
		assertNull(o.get("address"));
		assertEquals(1, o.size());

		o = OIDCScopeValue.PHONE.toClaimsRequestJSONObject();
		assertTrue(o.containsKey("phone_number"));
		assertNull(o.get("phone_number"));
		assertTrue(o.containsKey("phone_number_verified"));
		assertNull(o.get("phone_number_verified"));
		assertEquals(2, o.size());

		assertNull(OIDCScopeValue.OFFLINE_ACCESS.toClaimsRequestJSONObject());
	}


	public void testResolveMethods_toEmpty() {

		assertTrue(OIDCScopeValue.resolveClaimNames(null).isEmpty());
		assertTrue(OIDCScopeValue.resolveClaimNames(null, null).isEmpty());

		assertTrue(OIDCScopeValue.resolveClaimNames(new Scope()).isEmpty());
		assertTrue(OIDCScopeValue.resolveClaimNames(new Scope(), null).isEmpty());
		assertTrue(OIDCScopeValue.resolveClaimNames(new Scope(), new HashMap<Scope.Value, Set<String>>()).isEmpty());
	}


	public void testResolveMethods_toSet() {

		Set<String> claims = new HashSet<>(Arrays.asList("sub", "email", "email_verified"));

		assertEquals(claims, OIDCScopeValue.resolveClaimNames(new Scope("openid", "email", "read")));
		assertEquals(claims, OIDCScopeValue.resolveClaimNames(new Scope("openid", "email", "read"), null));
		assertEquals(claims, OIDCScopeValue.resolveClaimNames(new Scope("openid", "email", "read"), new HashMap<Scope.Value, Set<String>>()));
	}


	public void testResolveMethods_toSet_withCustomMap() {

		HashMap<Scope.Value, Set<String>> map = new HashMap<>();
		map.put(new Scope.Value("office"), new HashSet<>(Arrays.asList("floor", "location")));
		map.put(new Scope.Value("geo"), new HashSet<>(Arrays.asList("geo_lat", "get_long")));

		Set<String> claims = new HashSet<>(Arrays.asList("sub", "email", "email_verified", "geo_lat", "get_long"));

		assertEquals(claims, OIDCScopeValue.resolveClaimNames(new Scope("openid", "email", "read", "geo"), map));
	}
}
