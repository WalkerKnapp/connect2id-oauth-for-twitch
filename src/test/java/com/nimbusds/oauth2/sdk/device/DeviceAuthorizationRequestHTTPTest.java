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

package com.nimbusds.oauth2.sdk.device;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.URI;

import static net.jadler.Jadler.*;
import static org.junit.Assert.assertEquals;

public class DeviceAuthorizationRequestHTTPTest {


        @Before
        public void setUp() {
                initJadler();
        }


        @After
        public void tearDown() {
                closeJadler();
        }


        @Test
        public void testAcceptHeader() throws IOException, ParseException {

                DeviceAuthorizationRequest request = new DeviceAuthorizationRequest.Builder(new ClientID())
                        .endpointURI(URI.create("http://localhost:" + port() + "/device"))
                        .build();

                DeviceAuthorizationSuccessResponse response = new DeviceAuthorizationSuccessResponse(
                        new DeviceCode(),
                        new UserCode(),
                        URI.create("https://example.com/device"),
                        600);


                onRequest()
                        .havingMethodEqualTo(HTTPRequest.Method.POST.toString())
                        .havingPathEqualTo("/device")
                        .havingHeaderEqualTo("Content-Type", ContentType.APPLICATION_URLENCODED.toString())
                        .havingHeaderEqualTo("Accept", "application/json")
                        .respond()
                        .withStatus(200)
                        .withContentType(ContentType.APPLICATION_JSON.toString())
                        .withBody(response.toJSONObject().toJSONString());


                HTTPRequest httpRequest = request.toHTTPRequest();
                HTTPResponse httpResponse = httpRequest.send();
                assertEquals(200, httpResponse.getStatusCode());

                DeviceAuthorizationSuccessResponse parsedSuccessResponse = DeviceAuthorizationResponse.parse(httpResponse).toSuccessResponse();
                assertEquals(response.toJSONObject(), parsedSuccessResponse.toJSONObject());
        }
}
