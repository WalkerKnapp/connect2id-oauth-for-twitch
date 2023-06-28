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
 * "tos_uri" : { "essential" : true }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 5.1.2.
 * </ul>
 */
public class EssentialOperation implements PolicyOperation, BooleanConfiguration, UntypedOperation {
	
	
	public static final OperationName NAME = new OperationName("essential");
	
	
	private boolean enable = false;
	
	
	@Override
	public OperationName getOperationName() {
		return NAME;
	}
	
	
	@Override
	public void configure(final boolean enable) {
		this.enable = enable;
	}
	
	
	@Override
	public void parseConfiguration(final Object jsonEntity) throws ParseException {
		
		configure(JSONUtils.toBoolean(jsonEntity));
	}
	
	
	@Override
	public Map.Entry<String,Object> toJSONObjectEntry() {
		return new AbstractMap.SimpleImmutableEntry<>(getOperationName().getValue(), (Object) getBooleanConfiguration());
	}
	
	
	@Override
	public boolean getBooleanConfiguration() {
		return enable;
	}
	
	
	@Override
	public PolicyOperation merge(final PolicyOperation other)
		throws PolicyViolationException {
		
		EssentialOperation otherTyped = Utils.castForMerge(other, EssentialOperation.class);
		
		if (getBooleanConfiguration() == otherTyped.getBooleanConfiguration()) {
			EssentialOperation copy = new EssentialOperation();
			copy.configure(getBooleanConfiguration());
			return copy;
		}
		
		throw new PolicyViolationException("Essential value mismatch");
	}
	
	
	@Override
	public Object apply(final Object value) throws PolicyViolationException {
	
		if (enable && value == null) {
			throw new PolicyViolationException("Essential parameter not present");
		}
		
		return value;
	}
}
