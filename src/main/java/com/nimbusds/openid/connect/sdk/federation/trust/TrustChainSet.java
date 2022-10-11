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

package com.nimbusds.openid.connect.sdk.federation.trust;


import java.util.HashSet;

import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.constraints.TrustChainConstraints;


/**
 * {@link TrustChain Trust chain} set with methods to {@link #getShortest get
 * the shortest chain} and {@link #filter filter the chains according to path
 * length and entity ID constraints}.
 */
public class TrustChainSet extends HashSet<TrustChain> {
	
	
	private static final long serialVersionUID = -2449324224888772451L;
	
	
	/**
	 * Returns the shortest trust chain in this set.
	 *
	 * @return The (first) shortest chain, {@code null} for an empty set.
	 */
	public TrustChain getShortest() {
		
		TrustChain shortest = null;
		
		for (TrustChain chain: this) {
			if (chain.length() == 1) {
				return chain; // return immediately
			} else if (shortest == null) {
				shortest = chain; // record first
			} else if (chain.length() < shortest.length()) {
				shortest = chain;
			}
		}
		
		return shortest;
	}
	
	
	/**
	 * Returns a filtered trust chain set according to constraints.
	 *
	 * @param constraints The constraints. Must not be {@code null}.
	 *
	 * @return The filtered trust chain set.
	 */
	public TrustChainSet filter(final TrustChainConstraints constraints) {
		
		TrustChainSet permitted = new TrustChainSet();
		
		for (TrustChain chain: this) {
			
			if (constraints.getMaxPathLength() < 0 || chain.length() -1 <= constraints.getMaxPathLength()) {
				
				boolean foundNonPermitted = false;
				
				for (EntityStatement stmt: chain.getSuperiorStatements()) {
					
					if (! constraints.isPermitted(stmt.getClaimsSet().getIssuerEntityID())) {
						foundNonPermitted = true;
						break;
					}
				}
				
				if (! foundNonPermitted) {
					permitted.add(chain);
				}
			}
		}
		
		return permitted;
	}
}
