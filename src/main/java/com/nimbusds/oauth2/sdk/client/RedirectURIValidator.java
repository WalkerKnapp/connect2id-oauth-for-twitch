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

package com.nimbusds.oauth2.sdk.client;

import com.nimbusds.oauth2.sdk.util.URIUtils;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;


/**
 * Redirection URI validator.
 */
public final class RedirectURIValidator {


        /**
         * Prohibited {@code redirect_uri} schemes. See
         * https://security.lauritz-holtmann.de/post/sso-security-redirect-uri/.
         */
        public static final Set<String> PROHIBITED_REDIRECT_URI_SCHEMES =
                Collections.unmodifiableSet(new HashSet<>(Arrays.asList("data", "javascript", "vbscript")));


        /**
         * Prohibited {@code redirect_uri} query parameters. See "OAuth 2.0
         * Redirect URI Validation Falls Short, Literally", by Tommaso
         * Innocenti, Matteo Golinelli, Kaan Onarlioglu, Bruno Crispo, Engin
         * Kirda. Presented at OAuth Security Workshop 2023.
         */
        public static final Set<String> PROHIBITED_REDIRECT_URI_QUERY_PARAMETER_NAMES =
                Collections.unmodifiableSet(new HashSet<>(Arrays.asList("code", "state", "response")));

        /**
         * Ensures the specified redirection URI is legal.
         *
         * <p>Checks:
         *
         * <ul>
         *     <li>Must not contain fragment;
         *     <li>Must not have a {@link #PROHIBITED_REDIRECT_URI_SCHEMES
         *         prohibited URI scheme};
         *     <li>Must not have a {@link #PROHIBITED_REDIRECT_URI_QUERY_PARAMETER_NAMES
         *         prohibited query parameter}.
         * </ul>
         *
         * @param redirectURI The redirect URI to check, {@code null} if not
         *                    specified.
         *
         * @throws IllegalArgumentException If the redirection URI is illegal.
         */
        public static void ensureLegal(final URI redirectURI) {

                if (redirectURI == null) {
                        return;
                }

                if (redirectURI.getFragment() != null) {
                        throw new IllegalArgumentException("The redirect_uri must not contain fragment");
                }

                URIUtils.ensureSchemeIsNotProhibited(redirectURI, ClientMetadata.PROHIBITED_REDIRECT_URI_SCHEMES);

                URIUtils.ensureQueryIsNotProhibited(redirectURI, PROHIBITED_REDIRECT_URI_QUERY_PARAMETER_NAMES);
        }


        /**
         * Prevents public instantiation.
         */
        private RedirectURIValidator() {}
}
