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
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import net.jcip.annotations.ThreadSafe;
import org.apache.http.Header;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.entity.BasicHttpEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;

public class HTTPClientTest {

        @ThreadSafe
        public static class BasicClient implements HTTPRequestSender {

                private final CloseableHttpClient httpclient = HttpClients.createDefault();

                @Override
                public ReadOnlyHTTPResponse send(final ReadOnlyHTTPRequest httpRequest)
                        throws IOException {

                        RequestBuilder builder;
                        switch (httpRequest.getMethod()) {
                                case GET:
                                        builder = RequestBuilder.get();
                                        break;
                                case POST:
                                        builder = RequestBuilder.post();
                                        break;
                                case PUT:
                                        builder = RequestBuilder.put();
                                        break;
                                case DELETE:
                                        builder = RequestBuilder.delete();
                                        break;
                                default:
                                        throw new IOException("Unsupported HTTP method: " + httpRequest.getMethod());
                        }
                        builder.setUri(httpRequest.getURI());

                        for (Map.Entry<String, List<String>> en: httpRequest.getHeaderMap().entrySet()) {
                                String headerName = en.getKey();
                                List<String> headerValues = en.getValue();
                                if (CollectionUtils.isEmpty(headerValues)) {
                                        continue; // no header values, skip header
                                }
                                for (String headerValue: headerValues) {
                                        builder.setHeader(headerName, headerValue);
                                }
                        }

                        if (httpRequest.getBody() != null) {
                                BasicHttpEntity entity = new BasicHttpEntity();
                                entity.setContent(new ByteArrayInputStream(httpRequest.getBody().getBytes(StandardCharsets.UTF_8)));
                                builder.setEntity(entity);
                        }

                        HttpUriRequest request = builder.build();

                        CloseableHttpResponse response = httpclient.execute(request);

                        StatusLine statusLine = response.getStatusLine();

                        HTTPResponse httpResponse = new HTTPResponse(statusLine.getStatusCode());
                        httpResponse.setStatusMessage(statusLine.getReasonPhrase());

                        for (Header header: response.getAllHeaders()) {
                                httpResponse.setHeader(header.getName(), header.getValue());
                        }

                        if (response.getEntity() != null && response.getEntity().getContentLength() > 0) {
                               String body = EntityUtils.toString(response.getEntity());
                               httpResponse.setBody(body);
                        }

                        return httpResponse;
                }
        }

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

                HTTPResponse httpResponse = httpRequest.send(new BasicClient());
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

                HTTPResponse httpResponse = httpRequest.send(new BasicClient());
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
