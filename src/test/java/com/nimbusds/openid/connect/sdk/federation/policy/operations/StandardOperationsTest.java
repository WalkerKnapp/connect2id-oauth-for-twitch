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
import junit.framework.TestCase;

import java.util.Arrays;

public class StandardOperationsTest extends TestCase {


        public void testOperationOrder() {

                assertEquals(
                        Arrays.asList(
                                new OperationName("value"),
                                new OperationName("add"),
                                new OperationName("default"),
                                new OperationName("essential"),
                                new OperationName("subset_of"),
                                new OperationName("superset_of"),
                                new OperationName("one_of")
                        ),
                        StandardOperations.NAMES_IN_APPLICATION_ORDER
                );
        }
}
