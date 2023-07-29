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

public class PrivilegeTest extends TestCase {


        public void testStringConstructor() {

                String value = "admin";

                Privilege privilege = new Privilege(value);

                assertEquals(value, privilege.getValue());

                assertEquals(privilege, new Privilege(value));
                assertEquals(privilege.hashCode(), new Privilege(value).hashCode());
        }


        public void testInequality() {

                assertNotSame(new Privilege("admin"), new Privilege("audit"));
                assertNotSame(new Privilege("admin").hashCode(), new Privilege("audit").hashCode());

                assertNotSame(new Privilege("admin"), "audit");
        }
}
