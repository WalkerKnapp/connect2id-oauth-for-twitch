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

package com.nimbusds.oauth2.sdk.rar;

import com.nimbusds.oauth2.sdk.id.IdentifierWithOptionalURIRepresentation;
import net.jcip.annotations.Immutable;

import java.net.URI;


/**
 * OAuth 2.0 Rich Authorisation Request (RAR) detail type.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Rich Authorization Requests (RFC 9396)
 * </ul>
 */
@Immutable
public final class AuthorizationType extends IdentifierWithOptionalURIRepresentation {


        private static final long serialVersionUID = 741864278569413848L;


        /**
         * Creates a new authorisation type.
         *
         * @param value The type value. Must not be {@code null}.
         */
        public AuthorizationType(final String value) {
                super(value);
        }


        /**
         * Creates a new authorisation type.
         *
         * @param uri The type value as URI. Must not be {@code null}.
         */
        public AuthorizationType(final URI uri) {
                super(uri);
        }


        @Override
        public boolean equals(final Object object) {
                return object instanceof AuthorizationType && this.toString().equals(object.toString());
        }
}
