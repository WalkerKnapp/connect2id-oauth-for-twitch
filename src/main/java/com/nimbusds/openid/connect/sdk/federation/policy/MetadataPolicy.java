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

package com.nimbusds.openid.connect.sdk.federation.policy;


import java.util.*;

import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.DefaultPolicyOperationCombinationValidator;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.DefaultPolicyOperationFactory;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.PolicyOperationCombinationValidator;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.PolicyOperationFactory;


/**
 * Policy for a federation entity metadata.
 *
 * <p>Example:
 *
 * <pre>
 * {
 *   "scopes" : {
 *       "subset_of"   : [ "openid", "eduperson", "phone" ],
 *       "superset_of" : [ "openid" ],
 *       "default"     : [ "openid", "eduperson" ]
 *   },
 *   "id_token_signed_response_alg" : {
 *       "one_of" : [ "ES256", "ES384", "ES512" ]
 *   },
 *   "contacts" : {
 *       "add" : "helpdesk@federation.example.org"
 *   },
 *   "application_type" : { "value": "web"
 *   }
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 5.1.
 * </ul>
 */
public class MetadataPolicy implements JSONAware {
	
	
	/**
	 * The policy entries, keyed by metadata parameter name.
	 */
	private final Map<String,List<PolicyOperation>> entries = new LinkedHashMap<>();
	
	
	/**
	 * Applies this policy to the specified metadata.
	 *
	 * @param metadata The metadata as JSON object. May be {@code null}.
	 *
	 * @return The resulting metadata, {@code null} if not specified.
	 *
	 * @throws PolicyViolationException On a policy violation.
	 */
	public JSONObject apply(final JSONObject metadata)
		throws PolicyViolationException {
		
		if (metadata == null) {
			return null;
		}
		
		JSONObject out = new JSONObject();
		
		// Copy params not subject to policy
		for (String key: metadata.keySet()) {
			if (! entries.containsKey(key)) {
				out.put(key, metadata.get(key));
			}
		}
		
		// Apply policy
		for (String key: entries.keySet()) {
			
			Object metadataValue = metadata.get(key);
			MetadataPolicyEntry en = getEntry(key);
			
			Object outputValue = en.apply(metadataValue);
			
			if (outputValue != null) {
				out.put(key, outputValue);
			}
		}
		
		return out;
	}
	
	
	/**
	 * Puts a policy entry for a metadata parameter.
	 *
	 * @param parameterName   The parameter name. Must not be {@code null}.
	 * @param policyOperation The policy operation for the parameter,
	 *                        {@code null} if none.
	 */
	public void put(final String parameterName, final PolicyOperation policyOperation) {
		put(new MetadataPolicyEntry(parameterName, Collections.singletonList(policyOperation)));
	}
	
	
	/**
	 * Puts a policy entry for a metadata parameter.
	 *
	 * @param parameterName    The parameter name. Must not be {@code null}.
	 * @param policyOperations The ordered policy operations for the
	 *                         parameter, {@code null} if none.
	 */
	public void put(final String parameterName, final List<PolicyOperation> policyOperations) {
		put(new MetadataPolicyEntry(parameterName, policyOperations));
	}
	
	
	/**
	 * Puts a policy entry for a metadata parameter.
	 *
	 * @param entry The policy entry. Must not be {@code null}.
	 */
	public void put(final MetadataPolicyEntry entry) {
		entries.put(entry.getKey(), entry.getValue());
	}
	
	
	/**
	 * Gets the policy operations for the specified metadata parameter
	 * name.
	 *
	 * @param parameterName The parameter name. Must not be {@code null}.
	 *
	 * @return The ordered policy operations for the parameter,
	 *         {@code null} if none.
	 */
	public List<PolicyOperation> get(final String parameterName) {

		return entries.get(parameterName);
	}
	
	
	/**
	 * Gets the policy entry for the specified metadata parameter name.
	 *
	 * @param parameterName The parameter name. Must not be {@code null}.
	 *
	 * @return The policy entry for the parameter, {@code null} if none.
	 */
	public MetadataPolicyEntry getEntry(final String parameterName) {
		
		List<PolicyOperation> policyOperations = entries.get(parameterName);
		
		if (policyOperations == null) {
			return null;
		}
		
		return new MetadataPolicyEntry(parameterName, policyOperations);
	}
	
	
	/**
	 * Gets the policy entries set.
	 *
	 * @return The policy entries set.
	 */
	public Set<MetadataPolicyEntry> entrySet() {
		
		Set<MetadataPolicyEntry> set = new LinkedHashSet<>();
		for (Map.Entry<String,List<PolicyOperation>> en: entries.entrySet()) {
			set.add(new MetadataPolicyEntry(en.getKey(), en.getValue()));
		}
		return set;
	}
	
	
	/**
	 * Removes a policy entry.
	 *
	 * @param parameterName The parameter name. Must not be {@code null}.
	 *
	 * @return The ordered policy operations for the removed parameter,
	 *         {@code null} if not found.
	 */
	public List<PolicyOperation> remove(final String parameterName) {
		
		return entries.remove(parameterName);
	}
	
	
	/**
	 * Returns a JSON object representation of this metadata policy.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		
		JSONObject jsonObject = new JSONObject();
		
		for (MetadataPolicyEntry en: entrySet()) {
			JSONObject policyEntryJSONObject = en.toJSONObject();
			if (policyEntryJSONObject == null) {
				continue; // skip
			}
			jsonObject.put(en.getKey(), en.toJSONObject());
		}
		
		return jsonObject;
	}
	
	
	@Override
	public String toJSONString() {
		return toJSONObject().toJSONString();
	}
	
	
	@Override
	public String toString() {
		return toJSONString();
	}
	
	
	/**
	 * Combines the specified list of metadata policies. Uses the
	 * {@link DefaultPolicyOperationCombinationValidator default policy
	 * combination validator}.
	 *
	 * @param policies The metadata policies. Must not be empty or
	 *                 {@code null}.
	 *
	 * @return The new combined metadata policy.
	 *
	 * @throws PolicyViolationException On a policy violation.
	 */
	public static MetadataPolicy combine(final List<MetadataPolicy> policies)
		throws PolicyViolationException {
		
		return combine(policies, MetadataPolicyEntry.DEFAULT_POLICY_COMBINATION_VALIDATOR);
	}
	
	
	/**
	 * Combines the specified list of metadata policies.
	 *
	 * @param policies             The metadata policies. Must not be empty
	 *                             or {@code null}.
	 * @param combinationValidator The policy operation combination
	 *                             validator. Must not be {@code null}.
	 *
	 * @return The new combined metadata policy.
	 *
	 * @throws PolicyViolationException On a policy violation.
	 */
	public static MetadataPolicy combine(final List<MetadataPolicy> policies,
					     final PolicyOperationCombinationValidator combinationValidator)
		throws PolicyViolationException {
		
		MetadataPolicy out = new MetadataPolicy();
		
		for (MetadataPolicy p: policies) {
			for (MetadataPolicyEntry entry: p.entrySet()) {
				MetadataPolicyEntry existingEntry = out.getEntry(entry.getParameterName());
				if (existingEntry == null) {
					// add
					out.put(entry);
				} else {
					// merge
					out.put(existingEntry.combine(entry, combinationValidator));
				}
			}
		}
		
		return out;
	}
	
	
	/**
	 * Parses a policy for a federation entity metadata. This method is
	 * intended for policies with standard {@link PolicyOperation}s only.
	 * Uses the default {@link DefaultPolicyOperationFactory policy
	 * operation} and {@link DefaultPolicyOperationCombinationValidator
	 * policy combination validator} factories.
	 *
	 * @param policySpec The JSON object string for the policy
	 *                   specification. Must not be {@code null}.
	 *
	 * @return The metadata policy.
	 *
	 * @throws ParseException           On JSON parsing exception.
	 * @throws PolicyViolationException On a policy violation.
	 */
	public static MetadataPolicy parse(final JSONObject policySpec)
		throws ParseException, PolicyViolationException {
		
		return parse(policySpec,
			MetadataPolicyEntry.DEFAULT_POLICY_OPERATION_FACTORY,
			MetadataPolicyEntry.DEFAULT_POLICY_COMBINATION_VALIDATOR);
	}
	
	
	/**
	 * Parses a policy for a federation entity metadata. This method is
	 * intended for policies including non-standard
	 * {@link PolicyOperation}s.
	 *
	 * @param policySpec           The JSON object for the policy
	 *                             specification. Must not be {@code null}.
	 * @param factory              The policy operation factory. Must not
	 *                             be {@code null}.
	 * @param combinationValidator The policy operation combination
	 *                             validator. Must not be {@code null}.
	 *
	 * @return The metadata policy.
	 *
	 * @throws ParseException           On JSON parsing exception.
	 * @throws PolicyViolationException On a policy violation.
	 */
	public static MetadataPolicy parse(final JSONObject policySpec,
					   final PolicyOperationFactory factory,
					   final PolicyOperationCombinationValidator combinationValidator)
		throws ParseException, PolicyViolationException {
		
		MetadataPolicy metadataPolicy = new MetadataPolicy();
		
		for (String parameterName: policySpec.keySet()) {
			JSONObject entrySpec = JSONObjectUtils.getJSONObject(policySpec, parameterName);
			metadataPolicy.put(MetadataPolicyEntry.parse(parameterName, entrySpec, factory, combinationValidator));
		}
		
		return metadataPolicy;
	}
	
	
	/**
	 * Parses a policy for a federation entity metadata. This method is
	 * intended for policies with standard {@link PolicyOperation}s only.
	 * Uses the default {@link DefaultPolicyOperationFactory policy
	 * operation} and {@link DefaultPolicyOperationCombinationValidator
	 * policy combination validator} factories.
	 *
	 * @param policySpec The JSON object string for the policy
	 *                   specification. Must not be {@code null}.
	 *
	 * @return The metadata policy.
	 *
	 * @throws ParseException           On JSON parsing exception.
	 * @throws PolicyViolationException On a policy violation.
	 */
	public static MetadataPolicy parse(final String policySpec)
		throws ParseException, PolicyViolationException {
		
		return parse(policySpec,
			MetadataPolicyEntry.DEFAULT_POLICY_OPERATION_FACTORY,
			MetadataPolicyEntry.DEFAULT_POLICY_COMBINATION_VALIDATOR);
	}
	
	
	/**
	 * Parses a policy for a federation entity metadata. This method is
	 * intended for policies including non-standard
	 * {@link PolicyOperation}s.
	 *
	 * @param policySpec           The JSON object for the policy
	 *                             specification. Must not be {@code null}.
	 * @param factory              The policy operation factory. Must not
	 *                             be {@code null}.
	 * @param combinationValidator The policy operation combination
	 *                             validator. Must not be {@code null}.
	 *
	 * @return The metadata policy.
	 *
	 * @throws ParseException           On JSON parsing exception.
	 * @throws PolicyViolationException On a policy violation.
	 */
	public static MetadataPolicy parse(final String policySpec,
					   final PolicyOperationFactory factory,
					   final PolicyOperationCombinationValidator combinationValidator)
		throws ParseException, PolicyViolationException {
		
		return parse(JSONObjectUtils.parse(policySpec), factory, combinationValidator);
	}
}
