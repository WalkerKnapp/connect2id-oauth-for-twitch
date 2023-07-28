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

package com.nimbusds.oauth2.sdk.rar;

import com.nimbusds.oauth2.sdk.id.IdentifierWithOptionalURIRepresentation;
import net.jcip.annotations.Immutable;

import java.net.URI;

/**
 * Location, such as resource server URI.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Rich Authorization Requests (RFC 9396), section 2.2.
 * </ul>
 */
@Immutable
public final class Location extends IdentifierWithOptionalURIRepresentation {


        private static final long serialVersionUID = -8439684080844512056L;


        /**
         * Creates a new location.
         *
         * @param uri The location URI. Must not be {@code null}.
         */
        public Location(final URI uri) {
                super(uri);
        }


        /**
         * Creates a new location.
         *
         * @param value The location value. Must not be {@code null}.
         */
        public Location(final String value) {
                super(value);
        }


        @Override
        public boolean equals(final Object object) {
                return object instanceof Location && this.toString().equals(object.toString());
        }
}
