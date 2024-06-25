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

package com.nimbusds.oauth2.sdk.auth;


import com.nimbusds.oauth2.sdk.id.ClientID;
import junit.framework.TestCase;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Tests the base abstract JWT authentication class.
 */
public class JWTAuthenticationTest extends TestCase {


	public void testAssertionTypeConstant() {
	
		assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", 
			     JWTAuthentication.CLIENT_ASSERTION_TYPE);
	}


	public void testParseClientID_success() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("client_id", Collections.singletonList("123"));

		assertEquals(new ClientID("123"), JWTAuthentication.parseClientID(params));
	}


	public void testParseClientID_none() {

		assertNull(JWTAuthentication.parseClientID(Collections.<String, List<String>>emptyMap()));
	}


	public void testParseClientID_emptyString() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("client_id", Collections.singletonList(""));

		assertNull(JWTAuthentication.parseClientID(params));
	}


	public void testParseClientID_blankString() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("client_id", Collections.singletonList(" "));

		assertNull(JWTAuthentication.parseClientID(params));
	}
}
