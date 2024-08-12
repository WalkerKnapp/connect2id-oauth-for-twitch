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

package com.nimbusds.openid.connect.sdk.nativesso;

import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import net.jcip.annotations.Immutable;


/**
 * Device secret.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Native SSO for Mobile Apps 1.0
 * </ul>
 */
@Immutable
public final class DeviceSecret extends Identifier {


        private static final long serialVersionUID = 8861470156664697719L;


        /**
         * Creates a new device secret with the specified value.
         *
         * @param value The device secret value. Must not be {@code null} or
         *              empty string.
         */
        public DeviceSecret(final String value) {
                super(value);
        }


        @Override
        public boolean equals(final Object object) {

                return object instanceof DeviceSecret &&
                        this.toString().equals(object.toString());
        }


        /**
         * Parses a device secret from the specified string.
         *
         * @param s The string to parse, {@code null} or empty if no nonce is
         *          specified.
         *
         * @return The device string, {@code null} if the parsed string was
         *         {@code null} or empty.
         */
        public static DeviceSecret parse(final String s) {

                if (StringUtils.isBlank(s))
                        return null;

                return new DeviceSecret(s);
        }
}
