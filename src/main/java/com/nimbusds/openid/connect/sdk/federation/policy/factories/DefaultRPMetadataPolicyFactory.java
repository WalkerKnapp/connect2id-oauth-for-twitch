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

package com.nimbusds.openid.connect.sdk.federation.policy.factories;


import java.util.*;

import net.jcip.annotations.ThreadSafe;
import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.sdk.federation.policy.MetadataPolicy;
import com.nimbusds.openid.connect.sdk.federation.policy.MetadataPolicyEntry;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.ValueOperation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;


/**
 * The default OpenID relying party metadata policy factory.
 *
 * @deprecated Explicit client registration in OpenID Connect Federation 1.0 no
 * longer uses metadata policies in the explicit client registration response.
 */
@ThreadSafe
@Deprecated
public class DefaultRPMetadataPolicyFactory implements RPMetadataPolicyFactory {
	
	
	@Override
	public MetadataPolicy create(final OIDCClientMetadata initialMetadata, final OIDCClientInformation target)
		throws PolicyFormulationException {
		
		MetadataPolicy policy = new MetadataPolicy();
		
		JSONObject initialJSONObject = initialMetadata.toJSONObject();
		
		for (Map.Entry<String,Object> en: target.toJSONObject().entrySet()) {
			
			if (en.equals(new AbstractMap.SimpleImmutableEntry<>(en.getKey(), initialJSONObject.get(en.getKey())))) {
				// No policy entry needed
				continue;
			}
			
			// Set (override) value
			MetadataPolicyEntry policyEntry = new MetadataPolicyEntry(
				en.getKey(),
				Collections.singletonList((PolicyOperation) createValueOperation(en))
			);
			
			policy.put(policyEntry);
		}
		
		return policy;
	}
	
	
	private static ValueOperation createValueOperation(final Map.Entry<String,Object> objectEntry)
		throws PolicyFormulationException {
		
		ValueOperation valueOperation = new ValueOperation();
		
		if (objectEntry.getValue() instanceof String) {
			valueOperation.configure((String)objectEntry.getValue());
			
		} else if (objectEntry.getValue() instanceof Boolean) {
			valueOperation.configure((Boolean)objectEntry.getValue());
			
		} else if (objectEntry.getValue() instanceof Number) {
			valueOperation.configure((Number)objectEntry.getValue());
			
		} else if (objectEntry.getValue() instanceof List) {
			// assume string list
			List<String> stringList = new LinkedList<>();
			
			for (Object item : (List<?>) objectEntry.getValue()) {
				if (item instanceof String) {
					stringList.add((String) item);
				} else {
					stringList.add(null);
				}
			}
			valueOperation.configure(stringList);
		} else if (objectEntry.getValue() == null) {
			valueOperation.configure((String)null);
		} else {
			throw new PolicyFormulationException("Unsupported type for " + objectEntry.getKey() + ": " + objectEntry.getValue().getClass() + ": " + objectEntry.getValue());
		}
		
		return valueOperation;
	}
	
}
