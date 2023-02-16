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

package com.nimbusds.openid.connect.sdk.federation.policy.operations;


import junit.framework.TestCase;


public class ConfigurationTypeTest extends TestCase {
	
	public void testConstants() {
		
		assertEquals("STRING", ConfigurationType.STRING.name());
		assertEquals("STRING_LIST", ConfigurationType.STRING_LIST.name());
		assertEquals("BOOLEAN", ConfigurationType.BOOLEAN.name());
		assertEquals("NUMBER", ConfigurationType.NUMBER.name());
		assertEquals("JSON_OBJECT", ConfigurationType.JSON_OBJECT.name());
		
		assertEquals(5, ConfigurationType.values().length);
	}
}
