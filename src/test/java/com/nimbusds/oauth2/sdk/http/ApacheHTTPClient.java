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

import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import net.jcip.annotations.ThreadSafe;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.entity.BasicHttpEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;


@ThreadSafe
public class ApacheHTTPClient implements HTTPRequestSender {


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

                for (Map.Entry<String, List<String>> en : httpRequest.getHeaderMap().entrySet()) {
                        String headerName = en.getKey();
                        List<String> headerValues = en.getValue();
                        if (CollectionUtils.isEmpty(headerValues)) {
                                continue; // no header values, skip header
                        }
                        for (String headerValue : headerValues) {
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

                for (Header header : response.getAllHeaders()) {
                        httpResponse.setHeader(header.getName(), header.getValue());
                }

                HttpEntity httpEntity = response.getEntity();
                if (httpEntity != null) {
                        String body = EntityUtils.toString(httpEntity);
                        if (StringUtils.isNotBlank(body)) {
                                httpResponse.setBody(body);
                        }
                }
                return httpResponse;
        }
}
