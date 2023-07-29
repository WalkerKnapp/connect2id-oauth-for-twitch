/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2023, Connect2id Ltd and contributors.
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

package com.nimbusds.oauth2.sdk.rar;

import junit.framework.TestCase;

import java.net.URI;

public class LocationTest extends TestCase {


        public void testURIConstructor() {

                URI uri = URI.create("https://demo.c2id.com/userinfo");

                Location location = new Location(uri);

                assertEquals(uri, location.getURI());
                assertEquals(uri.toString(), location.getValue());

                assertEquals(location, new Location(uri));
                assertEquals(location.hashCode(), new Location(uri).hashCode());
        }


        public void testStringConstructor() {

                String value = "%location_123";

                Location location = new Location(value);

                assertEquals(value, location.getValue());
                assertNull(location.getURI());

                assertEquals(location, new Location(value));
                assertEquals(location.hashCode(), new Location(value).hashCode());
        }


        public void testInequality() {

                assertNotSame(new Location("rs_1"), new Location("rs_2"));
                assertNotSame(new Location("rs_1").hashCode(), new Location("rs_2").hashCode());

                assertNotSame(new Location("rs_1"), "rs_2");
        }
}
