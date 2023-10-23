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

package com.nimbusds.oauth2.sdk.http;

import com.nimbusds.common.contenttype.ContentType;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.URL;
import java.util.Collections;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;

public class HTTPClientTest {

        @Before
        public void setUp() {
                initJadler();
        }


        @After
        public void tearDown() {
                closeJadler();
        }

        @Test
        public void testWithHTTPClient_HTTP_GET() throws IOException {

                onRequest()
                        .havingMethodEqualTo("GET")
                        .havingHeaderEqualTo("Authorization", "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW")
                        .havingHeaderEqualTo("X-Custom", "x-123")
                        .havingPathEqualTo("/c2id/clients/")
                        .respond()
                        .withStatus(200)
                        .withHeader("Content-Type", ContentType.APPLICATION_JSON.toString())
                        .withHeader("X-Custom", "x-123")
                        .withBody("[]");

                HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost:" + port() + "/c2id/clients/"));
                httpRequest.setAuthorization("Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW");
                httpRequest.setHeader("X-Custom", "x-123");

                HTTPResponse httpResponse = httpRequest.send(new ApacheHTTPClient());
                assertEquals(200, httpResponse.getStatusCode());
                assertEquals("OK", httpResponse.getStatusMessage());

                assertEquals(Collections.singletonList(ContentType.APPLICATION_JSON.toString()), httpResponse.getHeaderValues("Content-Type"));
                assertEquals(Collections.singletonList("[]".length() + ""), httpResponse.getHeaderValues("Content-Length"));
                assertEquals(Collections.singletonList("x-123"), httpResponse.getHeaderValues("X-Custom"));
                assertNotNull(httpResponse.getHeaderValue("Date"));
                assertEquals(4, httpResponse.getHeaderMap().size());

                assertEquals("[]", httpResponse.getBody());
        }

        @Test
        public void testWithHTTPClient_HTTP_POST() throws IOException {

                onRequest()
                        .havingMethodEqualTo("POST")
                        .havingHeaderEqualTo("Content-Type", ContentType.APPLICATION_JSON.toString())
                        .havingHeaderEqualTo("X-Custom", "x-123")
                        .havingPathEqualTo("/c2id/sts/")
                        .havingBodyEqualTo("{}")
                        .respond()
                        .withStatus(401)
                        .withHeader("WWW-Authenticate", "Bearer")
                        .withHeader("X-Custom", "x-123");

                HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost:" + port() + "/c2id/sts/"));
                httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);
                httpRequest.setHeader("X-Custom", "x-123");
                httpRequest.setBody("{}");

                HTTPResponse httpResponse = httpRequest.send(new ApacheHTTPClient());
                assertEquals(401, httpResponse.getStatusCode());
                assertEquals("Unauthorized", httpResponse.getStatusMessage());

                assertEquals(Collections.singletonList("0"), httpResponse.getHeaderValues("Content-Length"));
                assertEquals(Collections.singletonList("Bearer"), httpResponse.getHeaderValues("WWW-Authenticate"));
                assertEquals(Collections.singletonList("x-123"), httpResponse.getHeaderValues("X-Custom"));
                assertNotNull(httpResponse.getHeaderValue("Date"));
                assertEquals(4, httpResponse.getHeaderMap().size());

                assertNull(httpResponse.getBody());
        }
}
