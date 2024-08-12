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

package com.nimbusds.openid.connect.sdk.nativesso;

import junit.framework.TestCase;


public class DeviceSecretTest extends TestCase {


        public void testConstructor() {

                String value = "aix5tahwo7De";
                DeviceSecret deviceSecret = new DeviceSecret(value);
                assertEquals(value, deviceSecret.getValue());

                assertEquals(deviceSecret, new DeviceSecret(value));
                assertEquals(deviceSecret.hashCode(), new DeviceSecret(value).hashCode());
        }


        public void testParse() {

                String value = "aix5tahwo7De";
                DeviceSecret deviceSecret = DeviceSecret.parse(value);

                assertEquals(value, deviceSecret.getValue());

                assertEquals(deviceSecret, new DeviceSecret(value));
                assertEquals(deviceSecret.hashCode(), new DeviceSecret(value).hashCode());
        }


        public void testParseNull() {

                assertNull(DeviceSecret.parse(null));
        }


        public void testParseEmpty() {

                assertNull(DeviceSecret.parse(""));
        }


        public void testParseBlank() {

                assertNull(DeviceSecret.parse(" "));
        }
}
