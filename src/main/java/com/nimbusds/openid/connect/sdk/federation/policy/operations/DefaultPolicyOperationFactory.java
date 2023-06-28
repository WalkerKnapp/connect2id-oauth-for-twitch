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


import com.nimbusds.openid.connect.sdk.federation.policy.language.OperationName;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyOperation;


/**
 * The default policy operation factory.
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
 * <p>Override the {@link #createForName} method to support additional custom
 * policies.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 5.1.
 * </ul>
 */
public class DefaultPolicyOperationFactory implements PolicyOperationFactory {
	
	
	@Override
	public PolicyOperation createForName(final OperationName name) {
		
		if (SubsetOfOperation.NAME.equals(name)) {
			return new SubsetOfOperation();
		} else if (OneOfOperation.NAME.equals(name)) {
			return new OneOfOperation();
		} else if (SupersetOfOperation.NAME.equals(name)) {
			return new SupersetOfOperation();
		} else if (AddOperation.NAME.equals(name)) {
			return new AddOperation();
		} else if (ValueOperation.NAME.equals(name)) {
			return new ValueOperation();
		} else if (DefaultOperation.NAME.equals(name)) {
			return new DefaultOperation();
		} else if (EssentialOperation.NAME.equals(name)) {
			return new EssentialOperation();
		} else {
			return null;
		}
	}
}
