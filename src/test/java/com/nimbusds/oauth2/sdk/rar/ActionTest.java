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

public class ActionTest extends TestCase {


        public void testStringConstructor() {

                String value = "write";

                Action action = new Action(value);

                assertEquals(value, action.getValue());

                assertEquals(action, new Action(value));
                assertEquals(action.hashCode(), new Action(value).hashCode());
        }


        public void testInequality() {

                assertNotSame(new Action("read"), new Action("write"));
                assertNotSame(new Action("read").hashCode(), new Action("write").hashCode());

                assertNotSame(new Action("read"), "write");
        }
}
