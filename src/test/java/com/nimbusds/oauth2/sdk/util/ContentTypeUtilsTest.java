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

package com.nimbusds.oauth2.sdk.util;


import junit.framework.TestCase;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;


public class ContentTypeUtilsTest extends TestCase {
	
	
	public void testEnsureContentType_matches() throws ParseException {

		// Exact
		ContentTypeUtils.ensureContentType(ContentType.APPLICATION_JSON, ContentType.APPLICATION_JSON);
		ContentTypeUtils.ensureContentType(ContentType.APPLICATION_JSON, null, ContentType.APPLICATION_JSON);

		// Accept suffix
		ContentTypeUtils.ensureContentType(ContentType.APPLICATION_JSON, "json", ContentType.APPLICATION_JSON);
		ContentTypeUtils.ensureContentType(ContentType.APPLICATION_JSON, "json", new ContentType("application", "jws+json"));
	}
	
	
	public void testEnsureContentType_nullFound() {
		
		try {
			ContentTypeUtils.ensureContentType(ContentType.APPLICATION_JSON, null);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing HTTP Content-Type header", e.getMessage());
		}

		try {
			ContentTypeUtils.ensureContentType(ContentType.APPLICATION_JSON, null, null);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing HTTP Content-Type header", e.getMessage());
		}

		try {
			ContentTypeUtils.ensureContentType(ContentType.APPLICATION_JSON, "json", null);
			fail();
		} catch (ParseException e) {
			assertEquals("Missing HTTP Content-Type header", e.getMessage());
		}
	}
	
	
	public void testEnsureContentType_mismatch() {
		
		try {
			ContentTypeUtils.ensureContentType(ContentType.APPLICATION_JSON, ContentType.APPLICATION_JWT);
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP Content-Type header must be application/json, received application/jwt", e.getMessage());
		}

		try {
			ContentTypeUtils.ensureContentType(ContentType.APPLICATION_JSON, null, ContentType.APPLICATION_JWT);
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP Content-Type header must be application/json, received application/jwt", e.getMessage());
		}

		try {
			ContentTypeUtils.ensureContentType(ContentType.APPLICATION_JSON, "json", ContentType.APPLICATION_JWT);
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP Content-Type header must be application/json or have the +json suffix, received application/jwt", e.getMessage());
		}

		try {
			ContentTypeUtils.ensureContentType(ContentType.APPLICATION_JSON, "json", new ContentType("text", "json"));
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP Content-Type header must be application/json or have the +json suffix, received text/json", e.getMessage());
		}
	}
}
