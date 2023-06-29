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


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.openid.connect.sdk.federation.policy.language.OperationName;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyOperationApplication;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.*;
import net.minidev.json.JSONObject;

import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;


/**
 * Policy entry for a metadata parameter.
 *
 * @see MetadataPolicy
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 5.1.
 * </ul>
 */
public class MetadataPolicyEntry implements Map.Entry<String, List<PolicyOperation>> {
	
	
	/**
	 * The default policy operation factory.
	 */
	public final static PolicyOperationFactory DEFAULT_POLICY_OPERATION_FACTORY = new DefaultPolicyOperationFactory();
	
	
	/**
	 * The default policy operation combination validator.
	 */
	public final static PolicyOperationCombinationValidator DEFAULT_POLICY_COMBINATION_VALIDATOR = new DefaultPolicyOperationCombinationValidator();
	
	
	/**
	 * The parameter name.
	 */
	private final String parameterName;
	
	
	/**
	 * The policy operations, empty list if none.
	 */
	private final List<PolicyOperation> policyOperations;
	
	
	/**
	 * Creates a new policy entry for a metadata parameter.
	 *
	 * @param parameterName    The parameter name. Must not be
	 *                         {@code null}.
	 * @param policyOperations The policy operations, empty list or
	 *                         {@code null} if none.
	 */
	public MetadataPolicyEntry(final String parameterName, final List<PolicyOperation> policyOperations) {
		if (StringUtils.isBlank(parameterName)) {
			throw new IllegalArgumentException("The parameter name must not be null or empty");
		}
		this.parameterName = parameterName;
		this.policyOperations = policyOperations;
	}
	
	
	/**
	 * Returns the parameter name.
	 * @see #getKey()
	 *
	 * @return The parameter name.
	 */
	public String getParameterName() {
		return getKey();
	}
	
	
	/**
	 * @see #getParameterName()
	 */
	@Override
	public String getKey() {
		return parameterName;
	}
	
	
	/**
	 * Returns the policy operations.
	 * @see #getValue()
	 *
	 * @return The policy operations, empty list if none.
	 */
	public List<PolicyOperation> getPolicyOperations() {
		return getValue();
	}
	
	
	/**
	 * @see #getPolicyOperations()
	 */
	@Override
	public List<PolicyOperation> getValue() {
		return policyOperations;
	}
	
	
	@Override
	public List<PolicyOperation> setValue(final List<PolicyOperation> policyOperations) {
		throw new UnsupportedOperationException();
	}
	
	
	/**
	 * Returns a map of the operations for this policy entry, in their
	 * {@link StandardOperations#NAMES_IN_APPLICATION_ORDER standard
	 * execution order}. Non-standard (custom) policy operations will be
	 * put at the end, in no particular order between them.
	 *
	 * @return The map, empty if no operations.
	 */
	public Map<OperationName,PolicyOperation> getOperationsMap() {
		
		Map<OperationName,PolicyOperation> map = new LinkedHashMap<>();
		
		if (getPolicyOperations() == null) {
			return map;
		}

		for (OperationName opName: StandardOperations.NAMES_IN_APPLICATION_ORDER) {
			for (PolicyOperation op: getPolicyOperations()) {
				if (opName.equals(op.getOperationName())) {
					map.put(opName, op);
				}
			}
		}

		// Append any custom operations
		for (PolicyOperation op: getPolicyOperations()) {
			if (! StandardOperations.NAMES_IN_APPLICATION_ORDER.contains(op.getOperationName())) {
				map.put(op.getOperationName(), op);
			}
		}
		
		return map;
	}
	
	
	/**
	 * Combines this policy entry with another one for the same parameter
	 * name. Uses the {@link DefaultPolicyOperationCombinationValidator
	 * default policy combination validator}.
	 *
	 * @param other The other policy entry. Must not be {@code null}.
	 *
	 * @return The new combined policy entry.
	 *
	 * @throws PolicyViolationException If the parameter names don't match
	 *                                  or another violation was
	 *                                  encountered.
	 */
	public MetadataPolicyEntry combine(final MetadataPolicyEntry other)
		throws PolicyViolationException {
		
		return combine(other, DEFAULT_POLICY_COMBINATION_VALIDATOR);
	}
	
	
	/**
	 * Combines this policy entry with another one for the same parameter
	 * name.
	 *
	 * @param other                The other policy entry. Must not be
	 *                             {@code null}.
	 * @param combinationValidator The policy operation combination
	 *                             validator. Must not be {@code null}.
	 *
	 * @return The new combined policy entry.
	 *
	 * @throws PolicyViolationException If the parameter names don't match
	 *                                  or another violation was
	 *                                  encountered.
	 */
	public MetadataPolicyEntry combine(final MetadataPolicyEntry other,
					   final PolicyOperationCombinationValidator combinationValidator)
		throws PolicyViolationException {
		
		if (! getParameterName().equals(other.getParameterName())) {
			throw new PolicyViolationException("The parameter name of the other policy doesn't match: " + other.getParameterName());
		}
		
		List<PolicyOperation> combinedOperations = new LinkedList<>();
		
		Map<OperationName,PolicyOperation> en1Map = getOperationsMap();
		Map<OperationName,PolicyOperation> en2Map = other.getOperationsMap();
		
		// Copy operations not present in either
		for (OperationName name: en1Map.keySet()) {
			if (! en2Map.containsKey(name)) {
				combinedOperations.add(en1Map.get(name));
			}
		}
		for (OperationName name: en2Map.keySet()) {
			if (! en1Map.containsKey(name)) {
				combinedOperations.add(en2Map.get(name));
			}
		}
		
		// Merge operations present in both entries
		for (OperationName opName: en1Map.keySet()) {
			if (en2Map.containsKey(opName)) {
				PolicyOperation op1 = en1Map.get(opName);
				combinedOperations.add(op1.merge(en2Map.get(opName)));
			}
		}
		
		List<PolicyOperation> validatedOperations = combinationValidator.validate(combinedOperations);
		
		return new MetadataPolicyEntry(getParameterName(), validatedOperations);
	}
	
	
	/**
	 * Applies this policy entry for a metadata parameter to the specified
	 * value.
	 *
	 * @param value The parameter value, {@code null} if not specified.
	 *
	 * @return The resulting value, can be {@code null}.
	 *
	 * @throws PolicyViolationException On a policy violation.
	 */
	public Object apply(final Object value)
		throws PolicyViolationException {
		
		if (CollectionUtils.isEmpty(getValue())) {
			// no ops
			return value;
		}

		// Apply policy operations in list
		Object updatedValue = value;

		boolean valueIsEssential = false;

		for (Map.Entry<OperationName, PolicyOperation> en: getOperationsMap().entrySet()) {

			if (value == null && ! valueIsEssential) {

				if (OneOfOperation.NAME.equals(en.getKey())
				||
				SubsetOfOperation.NAME.equals(en.getKey())
				||
				SupersetOfOperation.NAME.equals(en.getKey())
				) {
					continue; // skip
				}
			}

			updatedValue = PolicyOperationApplication.apply(en.getValue(), updatedValue);

			if (ValueOperation.NAME.equals(en.getKey())) {
				// Stop after "value"
				return updatedValue;
			}

			if (EssentialOperation.NAME.equals(en.getKey())) {

				if (((EssentialOperation)en.getValue()).getBooleanConfiguration()) {
					valueIsEssential = true;
				} else if (updatedValue == null) {
					// Skip further value checks
					return null;
				}
			}
		}
		return updatedValue;
	}
	
	
	/**
	 * Returns a JSON object representation of the policy operations for
	 * this entry.
	 *
	 * @return The JSON object keeping the ordering of the members.
	 */
	public JSONObject toJSONObject() {
		
		if (CollectionUtils.isEmpty(getValue())) {
			return null;
		}
		
		JSONObject jsonObject = new JSONObject();
		for (PolicyOperation operation: getValue()) {
			// E.g. "subset_of": ["code", "code token", "code id_token"]}
			Map.Entry<String,Object> en = operation.toJSONObjectEntry();
			jsonObject.put(en.getKey(), en.getValue());
		}
		
		return jsonObject;
	}
	
	
	/**
	 * Parses a policy entry for a metadata parameter. This method is
	 * intended for policies with standard {@link PolicyOperation}s only.
	 * Uses the default {@link DefaultPolicyOperationFactory policy
	 * operation} and {@link DefaultPolicyOperationCombinationValidator
	 * policy combination validator} factories.
	 *
	 * @param parameterName The parameter name. Must not be {@code null}.
	 * @param entrySpec     The JSON object entry specification, must not
	 *                      be {@code null}.
	 *
	 * @return The policy entry for the metadata parameter.
	 *
	 * @throws ParseException           On JSON parsing exception.
	 * @throws PolicyViolationException On a policy violation.
	 */
	public static MetadataPolicyEntry parse(final String parameterName,
						final JSONObject entrySpec)
		throws ParseException, PolicyViolationException {
		
		return parse(parameterName, entrySpec, DEFAULT_POLICY_OPERATION_FACTORY, DEFAULT_POLICY_COMBINATION_VALIDATOR);
	}
	
	
	/**
	 * Parses a policy entry for a metadata parameter. This method is
	 * intended for policies including non-standard
	 * {@link PolicyOperation}s.
	 *
	 * @param parameterName        The parameter name. Must not be
	 *                             {@code null}.
	 * @param entrySpec            The JSON object entry specification,
	 *                             must not be {@code null}.
	 * @param factory              The policy operation factory. Must not
	 *                             be {@code null}.
	 * @param combinationValidator The policy operation combination
	 *                             validator. Must not be {@code null}.
	 *
	 * @return The policy entry for the metadata parameter.
	 *
	 * @throws ParseException           On JSON parsing exception.
	 * @throws PolicyViolationException On a policy violation.
	 */
	public static MetadataPolicyEntry parse(final String parameterName,
						final JSONObject entrySpec,
						final PolicyOperationFactory factory,
						final PolicyOperationCombinationValidator combinationValidator)
		throws ParseException, PolicyViolationException {
		
		if (entrySpec == null) {
			throw new IllegalArgumentException("The entry spec must not be null");
		}
		
		List<PolicyOperation> policyOperations = new LinkedList<>();
		
		for (String opName: entrySpec.keySet()) {
			PolicyOperation op = factory.createForName(new OperationName(opName));
			if (op == null) {
				throw new PolicyViolationException("Unsupported policy operation: " + opName);
			}
			op.parseConfiguration(entrySpec.get(opName));
			policyOperations.add(op);
		}
		
		List<PolicyOperation> validatedPolicyOperations = combinationValidator.validate(policyOperations);
		
		return new MetadataPolicyEntry(parameterName, validatedPolicyOperations);
	}
}
