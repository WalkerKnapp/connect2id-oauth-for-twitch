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

import com.nimbusds.oauth2.sdk.id.Identifier;
import net.jcip.annotations.Immutable;


/**
 * Privilege.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Rich Authorization Requests (RFC 9396), section 2.2.
 * </ul>
 */
@Immutable
public class Privilege extends Identifier {


        private static final long serialVersionUID = -1171826593223231771L;


        /**
         * Creates a new privilege.
         *
         * @param value The value. Must not be {@code null}.
         */
        public Privilege(final String value) {
                super(value);
        }


        @Override
        public boolean equals(final Object object) {
                return object instanceof Privilege && this.toString().equals(object.toString());
        }
}
