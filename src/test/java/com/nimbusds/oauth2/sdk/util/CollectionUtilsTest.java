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

package com.nimbusds.oauth2.sdk.util;


import java.util.Arrays;
import java.util.Collection;

import junit.framework.TestCase;


public class CollectionUtilsTest extends TestCase {


	public void testContains() {
		
		Collection<String> collection = Arrays.asList("a", "b", "c");
		
		assertTrue(CollectionUtils.contains(collection, "a"));
		assertTrue(CollectionUtils.contains(collection, "b"));
		assertTrue(CollectionUtils.contains(collection, "c"));
		assertFalse(CollectionUtils.contains(collection, "d"));
		assertFalse(CollectionUtils.contains(collection, null));
	}


	public void testContains_null() {
		
		assertFalse(CollectionUtils.contains(null, "d"));
		assertFalse(CollectionUtils.contains(null, null));
	}
}
