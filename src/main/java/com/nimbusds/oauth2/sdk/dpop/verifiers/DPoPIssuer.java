/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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

package com.nimbusds.oauth2.sdk.dpop.verifiers;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Unique identifier for a DPoP issuer. Typically the DPoP
 * {@link com.nimbusds.oauth2.sdk.id.ClientID}.
 */
@Immutable
public class DPoPIssuer extends Identifier {
	
	
	private static final long serialVersionUID = 2801103134383988309L;
	
	
	/**
	 * Creates a new DPoP issuer identifier.
	 *
	 * @param value The identifier value. Must not be empty, blank or
	 *              {@code null}.
	 */
	public DPoPIssuer(final String value) {
		super(value);
	}
	
	
	/**
	 * Creates a new DPoP issuer identifier from the specified client ID.
	 *
	 * @param clientID The client ID. Must not be {@code null}.
	 */
	public DPoPIssuer(final ClientID clientID) {
		super(clientID.getValue());
	}
	
	
	@Override
	public boolean equals(final Object o) {
		return o instanceof DPoPIssuer && this.toString().equals(o.toString());
	}
}
