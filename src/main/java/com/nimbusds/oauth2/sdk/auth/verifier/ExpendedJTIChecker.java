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

package com.nimbusds.oauth2.sdk.auth.verifier;

import com.nimbusds.oauth2.sdk.id.JWTID;

import java.util.Date;


/**
 * Expended JWT ID {@code jti} claim checker.
 */
public interface ExpendedJTIChecker<T> {


        /**
         * Checks if the specified JWT ID (@code jti) is expended.
         *
         * @param jti     The JWT ID. Must not be {@code null}.
         * @param context Additional context to be passed to the client
         *                credentials selector. May be {@code null}.
         *
         * @return {@code true} if the JWT ID is expended, {@code false} if
         *         not.
         */
        boolean isExpended(final JWTID jti, final Context<T> context);


        /**
         * Marks the specified JWT ID (@code jti) as expended.
         *
         * @param jti     The JWT ID. Must not be {@code null}.
         * @param exp     The JWT expiration time. Must not be {@code null}.
         * @param context Additional context to be passed to the client
         *                credentials selector. May be {@code null}.
         */
        void markExpended(final JWTID jti, final Date exp, final Context<T> context);
}
