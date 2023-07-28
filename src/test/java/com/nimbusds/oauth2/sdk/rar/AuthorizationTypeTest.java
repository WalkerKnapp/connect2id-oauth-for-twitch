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

public class AuthorizationTypeTest extends TestCase {


        public void testStringConstructor() {

                String value = "account_information";

                AuthorizationType type = new AuthorizationType(value);

                assertEquals(value, type.getValue());

                assertEquals(type, new AuthorizationType(value));
                assertEquals(type.hashCode(), new AuthorizationType(value).hashCode());
        }


        public void testURIConstructor() {

                URI uri = URI.create("https://rar.example.com/types/account_information");

                AuthorizationType type = new AuthorizationType(uri);

                assertEquals(uri, type.getURI());
                assertEquals(uri.toString(), type.getValue());

                assertEquals(type, new AuthorizationType(uri));
                assertEquals(type.hashCode(), new AuthorizationType(uri).hashCode());
        }


        public void testInequality() {

                assertNotSame(new AuthorizationType("account_information"), new Action("payment_initiation"));
                assertNotSame(new AuthorizationType("account_information").hashCode(), new Action("payment_initiation").hashCode());
        }
}
