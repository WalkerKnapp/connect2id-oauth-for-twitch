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

package com.nimbusds.oauth2.sdk.id;


import java.io.Serializable;
import java.util.Arrays;
import java.util.List;

import junit.framework.TestCase;


/**
 * Tests the base Identifier class.
 */
public class IdentifierTest extends TestCase {


	public void testConstant() {
		
		assertEquals(32, Identifier.DEFAULT_BYTE_LENGTH);
	}


	public void testForSerializableInstance() {

		assertTrue((new Identifier() {

			public boolean equals(final Object object) {
				return true;
			}

		}) instanceof Serializable);
	}


	public void testToStringList_omitNullItems() {

		List<Identifier> in = Arrays.asList(new Identifier("a"), new Identifier("b"), null, new Identifier("c"), null);

		List<String> out = Identifier.toStringList(in);

		assertEquals(Arrays.asList("a", "b", "c"), out);
	}
}