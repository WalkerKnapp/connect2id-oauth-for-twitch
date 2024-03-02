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

package com.nimbusds.oauth2.sdk.id;

import junit.framework.TestCase;

import java.net.URI;

public class IdentifierWithOptionalURIRepresentationTest extends TestCase {


        public void testURIConstructor() {

                URI uri = URI.create("https://demo.c2id.com/userinfo");

                IdentifierWithOptionalURIRepresentation identifier = new IdentifierWithOptionalURIRepresentation(uri);
                assertEquals(uri, identifier.getURI());
                assertEquals(uri.toString(), identifier.getValue());

                assertEquals(identifier, new IdentifierWithOptionalURIRepresentation(uri));
                assertEquals(identifier.hashCode(), new IdentifierWithOptionalURIRepresentation(uri).hashCode());
        }


        public void testStringConstructor() {

                String value = "%%%not-legal-uri%%%";
                IdentifierWithOptionalURIRepresentation identifier = new IdentifierWithOptionalURIRepresentation(value);
                assertNull(identifier.getURI());
                assertEquals(value, identifier.getValue());

                assertEquals(identifier, new IdentifierWithOptionalURIRepresentation(value));
                assertEquals(identifier.hashCode(), new IdentifierWithOptionalURIRepresentation(value).hashCode());
        }


        public void testStringConstructor_valueParsesToURI() {

                String value = "https://demo.c2id.com/userinfo";
                IdentifierWithOptionalURIRepresentation identifier = new IdentifierWithOptionalURIRepresentation(value);
                assertEquals(URI.create(value), identifier.getURI());
                assertEquals(value, identifier.getValue());

                assertEquals(identifier, new IdentifierWithOptionalURIRepresentation(value));
                assertEquals(identifier.hashCode(), new IdentifierWithOptionalURIRepresentation(value).hashCode());
        }


        public void testURIConstructor_null() {

                try {
                        new IdentifierWithOptionalURIRepresentation((URI)null);
                        fail();
                } catch (NullPointerException e) {
                        assertEquals("Cannot invoke \"java.net.URI.toString()\" because \"uri\" is null", e.getMessage());
                }
        }


        public void testStringConstructor_null() {

                try {
                        new IdentifierWithOptionalURIRepresentation((String)null);
                        fail();
                } catch (IllegalArgumentException e) {
                        assertEquals("The value must not be null or empty string", e.getMessage());
                }
        }
}
