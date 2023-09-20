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


/**
 * Read-only HTTP response.
 */
public interface ReadOnlyHTTPResponse extends ReadOnlyHTTPMessage {


        /**
         * Gets the HTTP status code.
         *
         * @return The HTTP status code.
         */
        int getStatusCode();


        /**
         * Gets the HTTP status message.
         *
         * @return The HTTP status message, {@code null} if not specified.
         */
        String getStatusMessage();
}
