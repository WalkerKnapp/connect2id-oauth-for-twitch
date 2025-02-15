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

package com.nimbusds.openid.connect.sdk.op;


import junit.framework.TestCase;


public class EndpointNameTest extends TestCase {
	
	
	public void testConstants() {
		assertEquals("authorization_endpoint", EndpointName.AUTHORIZATION.getValue());
		assertEquals("ar", EndpointName.AR.getValue());
		assertEquals("pushed_authorization_request_endpoint", EndpointName.PAR.getValue());
	}
	
	
	public void testConstructor() {
		
		String name = "authorization_endpoint";
		EndpointName endpointName = new EndpointName("authorization_endpoint");
		assertEquals(name, endpointName.getValue());
		assertEquals(name, endpointName.toString());
		
		assertEquals(endpointName, EndpointName.AUTHORIZATION);
		assertEquals(endpointName.hashCode(), EndpointName.AUTHORIZATION.hashCode());
	}
}
