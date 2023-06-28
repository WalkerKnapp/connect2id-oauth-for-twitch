/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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


import java.util.*;

import com.nimbusds.openid.connect.sdk.federation.policy.language.OperationName;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;
import com.nimbusds.openid.connect.sdk.federation.policy.language.StringOperation;


/**
 * One-of (one_of) operation.
 *
 * <p>Example policy:
 *
 * <pre>
 * "request_object_signing_alg" : { "one_of" : [ "ES256", "ES384", "ES512" ] }
 * </pre>
 *
 * <p>Input:
 *
 * <pre>
 * "request_object_signing_alg" : "ES384"
 * </pre>
 *
 * <p>Result:
 *
 * <pre>
 * "request_object_signing_alg" : "ES384"
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 5.1.2.
 * </ul>
 */
public class OneOfOperation extends AbstractSetBasedOperation implements StringOperation {
	
	
	public static final OperationName NAME = new OperationName("one_of");
	
	
	@Override
	public OperationName getOperationName() {
		return NAME;
	}
	
	
	@Override
	public Map.Entry<String, Object> toJSONObjectEntry() {
		if (configType == null) {
			throw new IllegalStateException("The policy is not initialized");
		}
		return new AbstractMap.SimpleImmutableEntry<>(getOperationName().getValue(), (Object) getStringListConfiguration());
	}
	
	
	@Override
	public PolicyOperation merge(final PolicyOperation other) throws PolicyViolationException {
		
		OneOfOperation otherTyped = Utils.castForMerge(other, OneOfOperation.class);
		
		// intersect
		Set<String> combinedConfig = new LinkedHashSet<>(setConfig);
		combinedConfig.retainAll(otherTyped.getStringListConfiguration());
		
		OneOfOperation mergedPolicy = new OneOfOperation();
		mergedPolicy.configure(new LinkedList<>(combinedConfig));
		return mergedPolicy;
	}
	
	
	@Override
	public String apply(final String value)
		throws PolicyViolationException {
		
		if (setConfig == null) {
			throw new IllegalStateException("The policy is not initialized");
		}
		
		if (value == null) {
			throw new PolicyViolationException("Value not set");
		}
		
		if (! setConfig.contains(value)) {
			throw new PolicyViolationException("Value " + value + " not in policy list: " + setConfig);
		}
		
		return value;
	}
}
