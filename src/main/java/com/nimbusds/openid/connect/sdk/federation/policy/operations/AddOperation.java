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


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONUtils;
import com.nimbusds.openid.connect.sdk.federation.policy.language.*;

import java.util.*;


/**
 * Add (add) operation.
 *
 * <p>Example policy:
 *
 * <pre>
 * "contacts" : { "add" : "support@federation.example.com" }
 * </pre>
 *
 * <p>Input:
 *
 * <pre>
 * "contacts" : "support@org.example.com"
 * </pre>
 *
 * <p>Result:
 *
 * <pre>
 * "contacts" : [ "support@org.example.com", "support@federation.example.com" ]
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 5.1.2.
 * </ul>
 */
public class AddOperation extends AbstractSetBasedOperation implements StringConfiguration, StringListOperation {
	
	
	public static final OperationName NAME = new OperationName("add");
	
	
	@Override
	public OperationName getOperationName() {
		return NAME;
	}
	
	
	@Override
	public void configure(final String parameter) {
		configType = ConfigurationType.STRING;
		configure(Collections.singletonList(parameter));
	}
	
	
	@Override
	public void parseConfiguration(final Object jsonEntity) throws ParseException {
		
		if (jsonEntity instanceof String) {
			configure(JSONUtils.toString(jsonEntity));
		} else {
			// String list
			super.parseConfiguration(jsonEntity);
		}
	}
	
	
	@Override
	public Map.Entry<String,Object> toJSONObjectEntry() {
		if (configType == null) {
			throw new IllegalStateException("The policy is not initialized");
		}
		Object value;
		if (configType.equals(ConfigurationType.STRING_LIST)) {
			if (getStringListConfiguration().size() > 1) {
				value = getStringListConfiguration();
			} else {
				value = getStringListConfiguration().get(0);
			}
		} else if (configType.equals(ConfigurationType.STRING)) {
			value = getStringConfiguration();
		} else {
			throw new IllegalStateException("Unsupported configuration type: " + configType);
		}
		return new AbstractMap.SimpleImmutableEntry<>(getOperationName().getValue(), value);
	}
	
	
	@Override
	public String getStringConfiguration() {
		return getStringListConfiguration().get(0);
	}
	
	
	@Override
	public PolicyOperation merge(final PolicyOperation other)
		throws PolicyViolationException {
		
		AddOperation otherTyped = Utils.castForMerge(other, AddOperation.class);
		
		List<String> combined = new LinkedList<>();
		combined.addAll(getStringListConfiguration());
		combined.addAll(otherTyped.getStringListConfiguration());
		
		AddOperation mergedPolicy = new AddOperation();
		mergedPolicy.configure(combined);
		return mergedPolicy;
	}
	
	
	@Override
	public List<String> apply(final List<String> value) {
		
		if (setConfig == null) {
			throw new IllegalStateException("The policy is not initialized");
		}
		
		if (value == null) {
			return Collections.unmodifiableList(new LinkedList<>(setConfig));
		}
		
		List<String> result = new LinkedList<>(value);
		for (String s: setConfig) {
			if (! value.contains(s)) {
				result.add(s);
			}
		}
		return result;
	}
}
