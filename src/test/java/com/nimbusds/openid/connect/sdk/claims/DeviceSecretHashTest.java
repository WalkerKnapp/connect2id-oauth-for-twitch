/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2024, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.claims;

import junit.framework.TestCase;

public class DeviceSecretHashTest extends TestCase {


        public void testConstructor() {

                String value = "aa1heg4TahGe6eiT";

                DeviceSecretHash hash = new DeviceSecretHash(value);

                assertEquals(value, hash.getValue());

                assertEquals(hash, new DeviceSecretHash(value));
                assertEquals(hash.hashCode(), new DeviceSecretHash(value).hashCode());
        }


        public void testRejectNullValue() {

                try {
                        new DeviceSecretHash(null);
                        fail();
                } catch (IllegalArgumentException e) {
                        assertEquals("The value must not be null or empty string", e.getMessage());
                }
        }
}
