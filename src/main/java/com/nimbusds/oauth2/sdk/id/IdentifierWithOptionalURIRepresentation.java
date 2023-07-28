/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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


import java.net.URI;
import java.net.URISyntaxException;

/**
 * The base class for representing identifiers with an optional URI
 * representation.
 *
 * <p>Extending classes must override the {@link #equals} method.
 */
public class IdentifierWithOptionalURIRepresentation extends Identifier {


        private static final long serialVersionUID = 1003164205665683809L;


        /**
         * Creates a new identifier with the specified URI.
         *
         * @param uri The URI. Must not be {@code null}.
         */
        public IdentifierWithOptionalURIRepresentation(final URI uri) {
                super(uri.toString());
        }


        /**
         * Creates a new identifier with the specified value.
         *
         * @param value The value. Must not be {@code null} or empty string.
         */
        public IdentifierWithOptionalURIRepresentation(final String value) {
                super(value);
        }


        /**
         * Returns the URI representation.
         *
         * @return The URI, {@code null} if the identifier value cannot be
         *         parsed to a URI.
         */
        public URI getURI() {
                try {
                        return new URI(getValue());
                } catch (URISyntaxException e) {
                        return null;
                }
        }
}
