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

package com.nimbusds.oauth2.sdk.client;

import junit.framework.TestCase;

import java.net.URI;

public class RedirectURIValidatorTest extends TestCase {


        public void testProhibitedRedirectURISchemes() {

                assertTrue(RedirectURIValidator.PROHIBITED_REDIRECT_URI_SCHEMES.contains("data"));
                assertTrue(RedirectURIValidator.PROHIBITED_REDIRECT_URI_SCHEMES.contains("javascript"));
                assertTrue(RedirectURIValidator.PROHIBITED_REDIRECT_URI_SCHEMES.contains("vbscript"));
                assertEquals(3, RedirectURIValidator.PROHIBITED_REDIRECT_URI_SCHEMES.size());
        }


        public void testProhibitedRedirectURIQueryParamNames() {

                assertTrue(RedirectURIValidator.PROHIBITED_REDIRECT_URI_QUERY_PARAMETER_NAMES.contains("code"));
                assertTrue(RedirectURIValidator.PROHIBITED_REDIRECT_URI_QUERY_PARAMETER_NAMES.contains("state"));
                assertTrue(RedirectURIValidator.PROHIBITED_REDIRECT_URI_QUERY_PARAMETER_NAMES.contains("response"));
                assertEquals(3, RedirectURIValidator.PROHIBITED_REDIRECT_URI_QUERY_PARAMETER_NAMES.size());
        }


        public void testEnsureLegal_null() {

                RedirectURIValidator.ensureLegal(null);
        }


        public void testEnsureLegal_ok() {

                RedirectURIValidator.ensureLegal(URI.create("https://rp.example.com:8080/cb?iss=123"));
        }


        public void testEnsureLegal_rejectFragment() {

                try {
                        RedirectURIValidator.ensureLegal(URI.create("https://rp.example.com/cb#fragment"));
                        fail();
                } catch (IllegalArgumentException e) {
                        assertEquals("The redirect_uri must not contain fragment", e.getMessage());
                }
        }


        public void testEnsureLegal_rejectScheme() {

                for (String scheme: ClientMetadata.PROHIBITED_REDIRECT_URI_SCHEMES) {
                        try {
                                RedirectURIValidator.ensureLegal(URI.create(scheme + "://myapp"));
                                fail();
                        } catch (IllegalArgumentException e) {
                                assertEquals("The URI scheme " + scheme + " is prohibited", e.getMessage());
                        }
                }
        }


        public void testEnsureLegal_rejectQueryParam() {

                for (String queryParam: RedirectURIValidator.PROHIBITED_REDIRECT_URI_QUERY_PARAMETER_NAMES) {
                        try {
                                RedirectURIValidator.ensureLegal(URI.create("https://example.com/cb?" + queryParam + "=abc"));
                                fail();
                        } catch (IllegalArgumentException e) {
                                assertEquals("The query parameter " + queryParam + " is prohibited", e.getMessage());
                        }
                }
        }
}
