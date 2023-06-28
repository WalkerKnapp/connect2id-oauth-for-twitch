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


import java.util.AbstractMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONUtils;
import com.nimbusds.openid.connect.sdk.federation.policy.language.*;


/**
 * Default (default) value operation.
 *
 * <p>Example policy:
 *
 * <pre>
 * "require_auth_time": { "default" : true }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 5.1.2.
 * </ul>
 */
public class DefaultOperation implements PolicyOperation,
	BooleanConfiguration, StringConfiguration, StringListConfiguration,
	UntypedOperation {
	
	
	public static final OperationName NAME = new OperationName("default");
	
	
	private ConfigurationType configType;
	
	
	private boolean booleanValue;
	
	
	private String stringValue;
	
	
	private List<String> stringListValue;
	
	
	@Override
	public OperationName getOperationName() {
		return NAME;
	}
	
	
	@Override
	public void configure(final boolean parameter) {
		configType = ConfigurationType.BOOLEAN;
		this.booleanValue = parameter;
	}
	
	
	@Override
	public void configure(final String parameter) {
		configType = ConfigurationType.STRING;
		this.stringValue = parameter;
	}
	
	
	@Override
	public void configure(final List<String> parameter) {
		configType = ConfigurationType.STRING_LIST;
		this.stringListValue = parameter;
	}
	
	
	@Override
	public void parseConfiguration(final Object jsonEntity) throws ParseException {
		if (jsonEntity instanceof Boolean) {
			configure(JSONUtils.toBoolean(jsonEntity));
		} else if (jsonEntity instanceof String) {
			configure(JSONUtils.toString(jsonEntity));
		} else {
			configure(JSONUtils.toStringList(jsonEntity));
		}
	}
	
	
	@Override
	public Map.Entry<String,Object> toJSONObjectEntry() {
		if (configType == null) {
			throw new IllegalStateException("The policy is not initialized");
		}
		Object value;
		if (configType.equals(ConfigurationType.BOOLEAN)) {
			value = getBooleanConfiguration();
		} else if (configType.equals(ConfigurationType.STRING_LIST)) {
			value = getStringListConfiguration();
		} else if (configType.equals(ConfigurationType.STRING)) {
			value = getStringConfiguration();
		} else {
			throw new IllegalStateException("Unsupported configuration type: " + configType);
		}
		return new AbstractMap.SimpleImmutableEntry<>(getOperationName().getValue(), value);
	}
	
	
	@Override
	public boolean getBooleanConfiguration() {
		return booleanValue;
	}
	
	
	@Override
	public String getStringConfiguration() {
		return stringValue;
	}
	
	
	@Override
	public List<String> getStringListConfiguration() {
		return stringListValue;
	}
	
	
	@Override
	public PolicyOperation merge(final PolicyOperation other)
		throws PolicyViolationException {
		
		DefaultOperation otherTyped = Utils.castForMerge(other, DefaultOperation.class);
		
		if (configType == null || otherTyped.configType == null) {
			throw new PolicyViolationException("The default operation is not initialized");
		}
		
		if (configType.equals(ConfigurationType.STRING_LIST)) {
			
			if (getStringListConfiguration() != null && getStringListConfiguration().equals(otherTyped.getStringListConfiguration())) {
				DefaultOperation copy = new DefaultOperation();
				copy.configure(getStringListConfiguration());
				return copy;
			}
		}
		
		if (configType.equals(ConfigurationType.STRING)) {
			
			if (getStringConfiguration() != null && getStringConfiguration().equals(otherTyped.getStringConfiguration())) {
				DefaultOperation copy = new DefaultOperation();
				copy.configure(getStringConfiguration());
				return copy;
			}
			
		}
		
		if (configType.equals(ConfigurationType.BOOLEAN)) {
			
			if (getBooleanConfiguration() == otherTyped.getBooleanConfiguration()) {
				DefaultOperation copy = new DefaultOperation();
				copy.configure(getBooleanConfiguration());
				return copy;
			}
		}
		
		throw new PolicyViolationException("Default value mismatch");
	}
	
	
	@Override
	public Object apply(final Object value) {
		
		if (configType == null) {
			throw new IllegalStateException("The policy is not initialized");
		}
		
		if (value != null) {
			return value;
		}
		
		// Return default value
		
		if (stringListValue != null) {
			return stringListValue;
		}
		if (stringValue != null) {
			return stringValue;
		}
		return booleanValue;
	}
}
