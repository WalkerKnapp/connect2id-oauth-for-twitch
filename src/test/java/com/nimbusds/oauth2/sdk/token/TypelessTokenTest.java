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

package com.nimbusds.oauth2.sdk.token;


import junit.framework.TestCase;
import net.minidev.json.JSONObject;


public class TypelessTokenTest extends TestCase {


	public void testConstruct() {
		
		String value = "iePhohph8hoozaet";
		
		TypelessToken token = new TypelessToken(value);
		assertEquals(value, token.getValue());
		
		assertTrue(token.getParameterNames().isEmpty());
		
		assertTrue(token.toJSONObject().isEmpty());
	}
	
	
	public void testAllowInheritance() {
		
		class SubjectToken extends TypelessToken {
			
			private static final long serialVersionUID = -7762251620348256618L;
			
			public SubjectToken(final String value) {
				super(value);
			}
		}
		
		String value = "jooroo3eXuatha1a";
		SubjectToken subjectToken = new SubjectToken(value);
		assertEquals(value, subjectToken.getValue());
	}


	public void testCustomParameters() {

		TypelessToken token = new TypelessToken("abc");

		assertTrue(token.getCustomParameters().isEmpty());

		token.getCustomParameters().put("access_token_x", "xyz");

		assertEquals("xyz", token.getCustomParameters().get("access_token_x"));
		assertEquals(1, token.getCustomParameters().size());

		assertTrue(token.getParameterNames().contains("access_token_x"));
		assertEquals(1, token.getParameterNames().size());

		JSONObject jsonObject = token.toJSONObject();
		assertEquals("xyz", jsonObject.get("access_token_x"));
		assertEquals(1, jsonObject.size());
	}
}
