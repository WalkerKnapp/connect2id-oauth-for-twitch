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

package com.nimbusds.openid.connect.sdk.assurance.evidences;


import junit.framework.TestCase;


public class DocumentNumberTest extends TestCase {


	public void testEqualityAndHashCode() {
		
		assertEquals(new DocumentNumber("123"), new DocumentNumber("123"));
		assertEquals(new DocumentNumber("123").hashCode(), new DocumentNumber("123").hashCode());
	}
	
	
	public void testInequality() {
		
		assertNotSame(new DocumentNumber("123"), new DocumentNumber("456"));
		assertNotSame(new DocumentNumber("123").hashCode(), new DocumentNumber("456").hashCode());
	}
	
	
	public void testRejectNull() {
		
		try {
			new DocumentNumber(null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The value must not be null or empty string", e.getMessage());
		}
	}
}
