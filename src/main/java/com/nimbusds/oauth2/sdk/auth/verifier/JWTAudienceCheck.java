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

package com.nimbusds.oauth2.sdk.auth.verifier;


/**
 * The {@code client_secret_jwt} and {@code private_key_jwt} audience (aud)
 * claim check.
 */
public enum JWTAudienceCheck {


        /**
         * The JWT audience (aud) must be single-valued and contain only the
         * required value.
         */
        STRICT,


        /**
         * The JWT audience (aud) may be multi-valued, one which must be the
         * required value.
         */
        LEGACY
}
