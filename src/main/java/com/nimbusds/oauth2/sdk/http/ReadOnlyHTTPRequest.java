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


import java.net.URI;
import java.net.URL;

/**
 * Read-only HTTP request.
 */
public interface ReadOnlyHTTPRequest extends ReadOnlyHTTPMessage {


        /**
         * Gets the request method.
         *
         * @return The request method.
         */
        HTTPRequest.Method getMethod();


        /**
         * Gets the request URL.
         *
         * @return The request URL.
         */
        URL getURL();


        /**
         * Gets the request URL as URI.
         *
         * @return The request URL as URI.
         */
        URI getURI();


        /**
         * Gets the HTTP connect timeout.
         *
         * @return The HTTP connect timeout, in milliseconds. Zero implies no
         *         timeout.
         */
        int getConnectTimeout();


        /**
         * Gets the HTTP response read timeout.
         *
         * @return The HTTP response read timeout, in milliseconds. Zero
         *         implies no timeout.
         */
        int getReadTimeout();
}
