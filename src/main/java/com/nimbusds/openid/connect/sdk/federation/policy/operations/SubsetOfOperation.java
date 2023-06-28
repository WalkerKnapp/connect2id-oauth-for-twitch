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
import com.nimbusds.openid.connect.sdk.federation.policy.language.StringListOperation;


/**
 * Subset-of (subset_of) operation.
 *
 * <p>Example policy:
 *
 * <pre>
 * "response_types" : { "subset_of" : [ "code", "code token", "code id_token" ] }
 * </pre>
 *
 * <p>Input:
 *
 * <pre>
 * "response_types" : [ "code", "code id_token token", "code id_token" ]
 * </pre>
 *
 * <p>Result:
 *
 * <pre>
 * "response_types" : ["code", "code id_token"]
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 5.1.2.
 * </ul>
 */
public class SubsetOfOperation extends AbstractSetBasedOperation implements StringListOperation {
	
	
	public static final OperationName NAME = new OperationName("subset_of");
	
	
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
		
		SubsetOfOperation otherTyped = Utils.castForMerge(other, SubsetOfOperation.class);
		
		// intersect
		Set<String> combinedConfig = new LinkedHashSet<>(setConfig);
		combinedConfig.retainAll(otherTyped.getStringListConfiguration());
		
		SubsetOfOperation mergedPolicy = new SubsetOfOperation();
		mergedPolicy.configure(new LinkedList<>(combinedConfig));
		return mergedPolicy;
	}
	
	
	@Override
	public List<String> apply(final List<String> stringList) {
	
		if (setConfig == null) {
			throw new IllegalStateException("The policy is not initialized");
		}
		
		if (stringList == null) {
			// TODO check with spec https://bitbucket.org/openid/connect/issues/1156/federation-411-subset_of-edge-cases
			return Collections.emptyList();
		}
		
		Set<String> setValue = new LinkedHashSet<>(stringList);
		setValue.retainAll(setConfig);
		return Collections.unmodifiableList(new LinkedList<>(setValue));
	}
}
