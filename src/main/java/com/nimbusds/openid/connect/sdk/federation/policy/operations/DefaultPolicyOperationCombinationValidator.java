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

package com.nimbusds.openid.connect.sdk.federation.policy.operations;


import java.util.LinkedList;
import java.util.List;

import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.openid.connect.sdk.federation.policy.language.OperationName;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyOperation;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;


/**
 * Validates the permitted combinations of known policy operations for a given
 * metadata parameter.
 *
 * <p>Supports all standard OpenID Connect federation policy operations:
 *
 * <ul>
 *     <li>{@link SubsetOfOperation subset_of}
 *     <li>{@link OneOfOperation one_of}
 *     <li>{@link SupersetOfOperation superset_of}
 *     <li>{@link AddOperation add}
 *     <li>{@link ValueOperation value}
 *     <li>{@link DefaultOperation default}
 *     <li>{@link EssentialOperation essential}
 * </ul>
 *
 * <p>Override the {@link #validate(List)} method to support additional custom
 * policies.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 5.1.4.
 * </ul>
 */
public class DefaultPolicyOperationCombinationValidator implements PolicyOperationCombinationValidator {
	
	
	@Override
	public List<PolicyOperation> validate(final List<PolicyOperation> policyOperations)
		throws PolicyViolationException {
		
		if (CollectionUtils.isEmpty(policyOperations) || policyOperations.size() == 1) {
			// Empty or one policy operation always pass
			return policyOperations;
		}
		
		List<PolicyOperation> currentOpList = new LinkedList<>(policyOperations);
		
		currentOpList = validateCombinationsOfEssential(currentOpList);
		currentOpList = validateCombinationsOfAdd(currentOpList);
		currentOpList = validateCombinationsOfDefault(currentOpList);
		currentOpList = validateCombinationsOfSupersetOf(currentOpList);
		currentOpList = validateCombinationsOfSubsetOf(currentOpList);
		currentOpList = validateCombinationsOfValue(currentOpList);
		
		return currentOpList;
	}
	
	
	private static List<PolicyOperation> validateCombinationsOfEssential(final List<PolicyOperation> ops) {
		// Can be combined with all the others. If essential is not present
		// that is the same as stating essential=true.
		return ops;
	}
	
	
	private static List<PolicyOperation> validateCombinationsOfAdd(final List<PolicyOperation> ops) {
		// No official spec about "add"
		return ops;
	}
	
	
	private static List<PolicyOperation> validateCombinationsOfDefault(final List<PolicyOperation> ops)
		throws PolicyViolationException {
		// Can be combined with one_of, subset_of and superset_of. If a
		// default policy is combined with one_of, subset_of or superset_of
		// and it is not a subset of the subset_of policy or the one_of
		// policy or a superset of the superset_of policy then an error MUST
		// be raised.
		DefaultOperation o = Utils.getPolicyOperationByType(ops, DefaultOperation.class);
		
		if (o == null) {
			return ops;
		}
		
		if (o.getStringListConfiguration() != null) {
			ensureSatisfiedBySubsetOf(ops, o.getStringListConfiguration());
			ensureSatisfiedBySupersetOf(ops, o.getStringListConfiguration());
		} else if (o.getStringConfiguration() != null) {
			ensureSatisfiedByOneOf(ops, o.getStringConfiguration());
		}
		
		if (Utils.getPolicyOperationByType(ops, ValueOperation.class) != null) {
			throw new PolicyViolationException("Policies default and value cannot be combined");
		}
		
		return ops;
	}
	
	
	private static List<PolicyOperation> validateCombinationsOfSupersetOf(final List<PolicyOperation> ops)
		throws PolicyViolationException {
		// Can be combined with subset_of. If subset_of and superset_of both
		// appears in a metadata_policy statement subset_of MUST be a superset
		// of superset_of.
		SupersetOfOperation o = Utils.getPolicyOperationByType(ops, SupersetOfOperation.class);
		if (o == null) {
			return ops;
		}
		
		SubsetOfOperation subsetOfOperation = Utils.getPolicyOperationByType(ops, SubsetOfOperation.class);
		if (subsetOfOperation != null) {
			ensureSatisfied(o, subsetOfOperation.getStringListConfiguration());
		}
		
		return ops;
	}
	
	
	private static List<PolicyOperation> validateCombinationsOfSubsetOf(final List<PolicyOperation> ops)
		throws PolicyViolationException {
		// Can be combined with superset_of. If superset_of and subset_of both
		// appears in a metadata_policy statement for a claim subset_of MUST be
		// a superset of superset_of.
		SubsetOfOperation o = Utils.getPolicyOperationByType(ops, SubsetOfOperation.class);
		if (o == null) {
			return ops;
		}
		
		SupersetOfOperation supersetOfOperation = Utils.getPolicyOperationByType(ops, SupersetOfOperation.class);
		if (supersetOfOperation != null) {
			ensureSatisfied(supersetOfOperation, o.getStringListConfiguration());
		}
		
		return ops;
	}
	
	
	// See https://bitbucket.org/openid/connect/issues/1163/federation-metadata-policy-current-spec
	private static List<PolicyOperation> validateCombinationsOfValue(final List<PolicyOperation> ops)
		throws PolicyViolationException {
		// https://bitbucket.org/openid/connect/issues/1163/federation-metadata-policy-current-spec
		// value must not be combined with other policy types, raise an error if this condition is detected.
		ValueOperation o = Utils.getPolicyOperationByType(ops, ValueOperation.class);
		if (o == null) {
			return ops;
		}
		
		List<OperationName> violating = new LinkedList<>();
		for (PolicyOperation op: ops) {
			if (op instanceof ValueOperation) {
				// ok
			} else if (op instanceof EssentialOperation) {
				// ok
			} else {
				violating.add(op.getOperationName());
			}
		}
		
		if (! violating.isEmpty()) {
			throw new PolicyViolationException("Policy operation " + ValueOperation.NAME + " must not be combined with: " + violating);
		}
		
		return ops;
	}
	
	
	private static void ensureSatisfied(final SubsetOfOperation op, final List<String> values)
		throws PolicyViolationException {
		if (! op.getStringListConfiguration().containsAll(values))
			throw new PolicyViolationException("Not in " + SubsetOfOperation.NAME + " " + op.getStringListConfiguration() + ": " + values);
	}
	
	
	private static void ensureSatisfiedBySubsetOf(final List<PolicyOperation> policyOperations, final List<String> values)
		throws PolicyViolationException {
		SubsetOfOperation op = Utils.getPolicyOperationByType(policyOperations, SubsetOfOperation.class);
		if (op != null) {
			ensureSatisfied(op, values);
		}
	}
	
	
	private static void ensureSatisfied(final SupersetOfOperation op, final List<String> values)
		throws PolicyViolationException {
		if (! values.containsAll(op.getStringListConfiguration()))
			throw new PolicyViolationException("Not in " + SupersetOfOperation.NAME + " " + op.getStringListConfiguration() + ": " + values);
	}
	
	
	private static void ensureSatisfiedBySupersetOf(final List<PolicyOperation> policyOperations, final List<String> values)
		throws PolicyViolationException {
		SupersetOfOperation op = Utils.getPolicyOperationByType(policyOperations, SupersetOfOperation.class);
		if (op != null) {
			ensureSatisfied(op, values);
		}
	}
	
	
	private static void ensureSatisfiedByOneOf(final List<PolicyOperation> policyOperations, final String value)
		throws PolicyViolationException {
		OneOfOperation op = Utils.getPolicyOperationByType(policyOperations, OneOfOperation.class);
		if (op == null) return;
		if (! op.getStringListConfiguration().contains(value))
			throw new PolicyViolationException("Not in " + OneOfOperation.NAME + " " + op.getStringListConfiguration() + ": " + value);
	}
}
