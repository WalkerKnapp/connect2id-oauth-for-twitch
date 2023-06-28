/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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


import java.util.List;

import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;


/**
 * Validates the permitted combinations of known policy operations for a given
 * metadata parameter.
 *
 * <p>To support combinations including non-standard policy operations on
 * metadata parameters consider overriding
 * {@link DefaultPolicyOperationCombinationValidator#validate(List)}.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 5.1.4.
 * </ul>
 */
public interface PolicyOperationCombinationValidator {
	
	
	/**
	 * Validates the specified combination of policy operations.
	 *
	 * @param policyOperations The policy operations, empty list if none.
	 *
	 * @return The validated and optionally optimised policy operations.
	 *
	 * @throws PolicyViolationException On a illegal policy combination.
	 */
	List<PolicyOperation> validate(final List<PolicyOperation> policyOperations)
		throws PolicyViolationException;
}
