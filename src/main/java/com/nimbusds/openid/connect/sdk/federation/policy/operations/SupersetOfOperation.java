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

import com.nimbusds.openid.connect.sdk.federation.policy.language.*;


/**
 * Superset-of (superset_of) operation.
 *
 * <p>Example policy:
 *
 * <pre>
 * "request_object_signing_alg_values_supported" : { "superset_of ": [ "ES256", "RS256" ] }
 * </pre>
 *
 * <p>Input:
 *
 * <pre>
 * "request_object_signing_alg_values_supported" : [ "ES256", "ES384", "RS256", "RS512" ]
 * </pre>
 *
 * <p>Result:
 *
 * <pre>
 * "request_object_signing_alg_values_supported" : [ "ES256", "ES384", "RS256", "RS512" ]
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 5.1.2.
 * </ul>
 */
public class SupersetOfOperation extends AbstractSetBasedOperation implements PolicyOperation, StringListConfiguration, StringListOperation {
	
	
	public static final OperationName NAME = new OperationName("superset_of");
	
	
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
		
		SupersetOfOperation otherTyped = Utils.castForMerge(other, SupersetOfOperation.class);
		
		// intersect
		Set<String> combinedConfig = new LinkedHashSet<>(setConfig);
		combinedConfig.retainAll(otherTyped.getStringListConfiguration());
		
		SupersetOfOperation mergedPolicy = new SupersetOfOperation();
		mergedPolicy.configure(new LinkedList<>(combinedConfig));
		return mergedPolicy;
	}
	
	
	@Override
	public List<String> apply(final List<String> stringList)
		throws PolicyViolationException {
	
		if (setConfig == null) {
			throw new IllegalStateException("The policy is not initialized");
		}
		
		if (stringList == null) {
			throw new PolicyViolationException("Value not specified");
		}
		
		List<String> missingValues = new LinkedList<>();
		for (String requiredValue: setConfig) {
			if (! stringList.contains(requiredValue)) {
				missingValues.add(requiredValue);
			}
		}
		
		if (! missingValues.isEmpty()) {
			throw new PolicyViolationException("Missing values: " + missingValues);
		}
		
		return Collections.unmodifiableList(stringList);
	}
}
