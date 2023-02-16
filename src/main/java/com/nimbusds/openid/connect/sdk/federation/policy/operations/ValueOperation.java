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

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONUtils;
import com.nimbusds.openid.connect.sdk.federation.policy.language.*;


/**
 * Values set (value) operation.
 *
 * <p>Example policy:
 *
 * <pre>
 * "require_auth_time" : { "value": true }
 * </pre>
 *
 * <p>Input:
 *
 * <pre>
 * "require_auth_time" : false
 * </pre>
 *
 * <p>Result:
 *
 * <pre>
 * "require_auth_time" : true
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 4.1.5.
 * </ul>
 */
public class ValueOperation implements PolicyOperation,
	BooleanConfiguration, NumberConfiguration, StringConfiguration, StringListConfiguration, JSONObjectConfiguration,
	UntypedOperation {
	
	
	public static final OperationName NAME = new OperationName("value");
	
	
	private ConfigurationType configType;
	
	
	private boolean booleanValue;
	
	
	private Number numberValue = null;
	
	
	private String stringValue;
	
	
	private List<String> stringListValue;
	
	
	private JSONObject jsonObjectValue;
	
	
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
	public void configure(final Number parameter) {
		configType = ConfigurationType.NUMBER;
		this.numberValue = parameter;
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
	public void configure(final JSONObject parameter) {
		configType = ConfigurationType.JSON_OBJECT;
		this.jsonObjectValue = parameter;
	}
	
	
	@Override
	public void parseConfiguration(final Object jsonEntity) throws ParseException {
		if (jsonEntity instanceof Boolean) {
			configure(JSONUtils.toBoolean(jsonEntity));
		} else if (jsonEntity instanceof Number) {
			configure(JSONUtils.toNumber(jsonEntity));
		} else if (jsonEntity instanceof String) {
			configure(JSONUtils.toString(jsonEntity));
		} else if (jsonEntity instanceof JSONObject) {
			configure(JSONUtils.to(jsonEntity, JSONObject.class));
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
		} else if (configType.equals(ConfigurationType.NUMBER)) {
			value = getNumberConfiguration();
		} else if (configType.equals(ConfigurationType.STRING)) {
			value = getStringConfiguration();
		} else if (configType.equals(ConfigurationType.STRING_LIST)) {
			value = getStringListConfiguration();
		} else if (configType.equals(ConfigurationType.JSON_OBJECT)) {
			value = getJSONObjectConfiguration();
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
	public Number getNumberConfiguration() {
		return numberValue;
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
	public JSONObject getJSONObjectConfiguration() {
		return jsonObjectValue;
	}
	
	
	@Override
	public PolicyOperation merge(final PolicyOperation other)
		throws PolicyViolationException {
		
		ValueOperation otherTyped = Utils.castForMerge(other, ValueOperation.class);
		
		if (configType == null ||  otherTyped.configType == null) {
			throw new PolicyViolationException("The value operation is not initialized");
		}
		
		if (configType.equals(ConfigurationType.STRING_LIST)) {
			
			if (getStringListConfiguration() != null && getStringListConfiguration().equals(otherTyped.getStringListConfiguration())) {
				ValueOperation copy = new ValueOperation();
				copy.configure(getStringListConfiguration());
				return copy;
			}
		}
		
		if (configType.equals(ConfigurationType.STRING)) {
			
			if (getStringConfiguration() != null && getStringConfiguration().equals(otherTyped.getStringConfiguration())) {
				ValueOperation copy = new ValueOperation();
				copy.configure(getStringConfiguration());
				return copy;
			}
		}
		
		if (configType.equals(ConfigurationType.BOOLEAN)) {
			
			if (getBooleanConfiguration() == otherTyped.getBooleanConfiguration()) {
				ValueOperation copy = new ValueOperation();
				copy.configure(getBooleanConfiguration());
				return copy;
			}
		}
		
		if (configType.equals(ConfigurationType.NUMBER)) {
			
			if (getNumberConfiguration() != null && getNumberConfiguration().equals(otherTyped.getNumberConfiguration())) {
				ValueOperation copy = new ValueOperation();
				copy.configure(getNumberConfiguration());
				return copy;
			}
		}
		
		if (configType.equals(ConfigurationType.JSON_OBJECT)) {
			
			if (getJSONObjectConfiguration() == otherTyped.getJSONObjectConfiguration()) {
				ValueOperation copy = new ValueOperation();
				copy.configure(getJSONObjectConfiguration());
				return copy;
			}
		}
		
		throw new PolicyViolationException("Value mismatch");
	}
	
	
	@Override
	public Object apply(final Object value) {
		
		if (configType == null) {
			throw new IllegalStateException("The policy is not initialized");
		}
		
		if (configType.equals(ConfigurationType.BOOLEAN)) {
			return booleanValue;
		}
		if (configType.equals(ConfigurationType.NUMBER)) {
			return numberValue;
		}
		if (configType.equals(ConfigurationType.STRING)) {
			return stringValue;
		}
		if (configType.equals(ConfigurationType.JSON_OBJECT)) {
			return jsonObjectValue;
		}
		return stringListValue;
	}
}
