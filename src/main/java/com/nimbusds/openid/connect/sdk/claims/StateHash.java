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

package com.nimbusds.openid.connect.sdk.claims;


import net.jcip.annotations.Immutable;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.oauth2.sdk.id.State;


/**
 * State hash ({@code s_hash}).
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Financial Services – Financial API - Part 2: Read and Write API
 *         Security Profile
 * </ul>
 */
@Immutable
public class StateHash extends HashClaim {
	
	
	private static final long serialVersionUID = 6043322975168115376L;
	
	
	/**
	 * Creates a new state hash with the specified value.
	 *
	 * @param value The state hash value. Must not be {@code null}.
	 */
	public StateHash(final String value) {
		
		super(value);
	}
	
	
	/**
	 * Computes the hash for the specified state and reference JSON
	 * Web Signature (JWS) algorithm.
	 *
	 * @param state The state. Must not be {@code null}.
	 * @param alg   The reference JWS algorithm. Must not be {@code null}.
	 *
	 * @return The state hash, or {@code null} if the JWS algorithm is not
	 *         supported.
	 *
	 * @deprecated Use {@link #compute(State, JWSAlgorithm, Curve)}
	 * instead.
	 */
	@Deprecated
	public static StateHash compute(final State state, final JWSAlgorithm alg) {
		
		String value = computeValue(state, alg);
		
		if (value == null)
			return null;
		
		return new StateHash(value);
	}
	
	
	/**
	 * Computes the hash for the specified state and reference JSON
	 * Web Signature (JWS) algorithm.
	 *
	 * @param state The state. Must not be {@code null}.
	 * @param alg   The reference JWS algorithm. Must not be {@code null}.
	 * @param crv   The JWK curve used with the JWS algorithm, {@code null}
	 *              if not applicable.
	 *
	 * @return The state hash, or {@code null} if the JWS algorithm is not
	 *         supported.
	 */
	public static StateHash compute(final State state,
					final JWSAlgorithm alg,
					final Curve crv) {
		
		String value = computeValue(state, alg, crv);
		
		if (value == null)
			return null;
		
		return new StateHash(value);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof StateHash &&
			this.toString().equals(object.toString());
	}
}
