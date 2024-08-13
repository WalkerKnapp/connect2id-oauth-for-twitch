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

package com.nimbusds.openid.connect.sdk.assurance.evidences;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Vouch type.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 *     <li>https://bitbucket.org/openid/ekyc-ida/wiki/identifiers
 * </ul>
 */
@Immutable
public final class VouchType extends Identifier {
	
	
	private static final long serialVersionUID = -701546295133681157L;
	
	
	/**
	 * A written / printed statement / letter from a recognised person or
	 * authority regarding the identity of the user.
	 */
	public static final VouchType WRITTEN_ATTESTATION = new VouchType("written_attestation");
	
	
	/**
	 * A statement from a recognised person or authority regarding the
	 * identity of the user that was made and stored electronically.
	 */
	public static final VouchType DIGITAL_ATTESTATION = new VouchType("digital_attestation");
	
	
	/**
	 * Creates a new vouch type.
	 *
	 * @param value The vouch type value. Must not be {@code null}.
	 */
	public VouchType(final String value) {
		super(value);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof VouchType &&
			this.toString().equals(object.toString());
	}
}
