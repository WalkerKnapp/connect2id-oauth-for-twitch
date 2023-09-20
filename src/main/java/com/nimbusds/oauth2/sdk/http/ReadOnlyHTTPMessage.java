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


import java.util.List;
import java.util.Map;


/**
 * Read-only HTTP message.
 */
public interface ReadOnlyHTTPMessage {


        /**
         * Returns the HTTP headers.
         *
         * @return The HTTP headers.
         */
        Map<String, List<String>> getHeaderMap();


        /**
         * Get the HTTP message body.
         *
         * @return The HTTP message body, {@code null} if not specified.
         */
        String getBody();
}
