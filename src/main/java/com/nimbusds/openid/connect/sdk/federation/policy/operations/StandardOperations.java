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

package com.nimbusds.openid.connect.sdk.federation.policy.operations;

import com.nimbusds.openid.connect.sdk.federation.policy.language.OperationName;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * The standard policy operations defined in OpenID Connect Federation 1.0.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 5.1.2.
 * </ul>
 */
public final class StandardOperations {


        /**
         * The policy operation names in the order they must be applied.
         */
        public static final List<OperationName> NAMES_IN_APPLICATION_ORDER = Collections.unmodifiableList(
                Arrays.asList(
                        ValueOperation.NAME,
                        AddOperation.NAME,
                        DefaultOperation.NAME,
                        EssentialOperation.NAME,
                        SubsetOfOperation.NAME,
                        SupersetOfOperation.NAME,
                        OneOfOperation.NAME
                )
        );


        private StandardOperations() {}
}
