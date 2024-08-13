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

package com.nimbusds.openid.connect.sdk.assurance;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Identity assurance level.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
@Immutable
public final class IdentityAssuranceLevel extends Identifier {
	
	
	private static final long serialVersionUID = 378614456182831323L;
	
	
	/**
	 * Very low confidence/assurance in the identity.
	 */
	public static final IdentityAssuranceLevel VERY_LOW = new IdentityAssuranceLevel("very_low");
	
	
	/**
	 * Low confidence/assurance in the identity. Used in eIDAS &amp; UK
	 * TFIDA.
	 */
	public static final IdentityAssuranceLevel LOW = new IdentityAssuranceLevel("low");
	
	
	/**
	 * Medium confidence/assurance in the identity. Used in UK TFIDA.
	 */
	public static final IdentityAssuranceLevel MEDIUM = new IdentityAssuranceLevel("medium");
	
	
	/**
	 * Substantial confidence/assurance in the identity. Used in eIDAS.
	 */
	public static final IdentityAssuranceLevel SUBSTANTIAL = new IdentityAssuranceLevel("substantial");
	
	
	/**
	 * High confidence/assurance in the identity. Used in eIDAS &amp; UK
	 * TFIDA.
	 */
	public static final IdentityAssuranceLevel HIGH = new IdentityAssuranceLevel("high");
	
	
	/**
	 * Very high confidence/assurance in the identity. Used in UK TFIDA.
	 */
	public static final IdentityAssuranceLevel VERY_HIGH = new IdentityAssuranceLevel("very_high");
	
	
	/**
	 * No link between the user and a specific real-life identity. Used in US NIST-800-63-3.
	 */
	public static final IdentityAssuranceLevel IAL1 = new IdentityAssuranceLevel("ial1");
	
	
	/**
	 * A real-world existence of the claimed identity and verifies that the
	 * user is appropriately associated with it. Used in US NIST-800-63-3.
	 */
	public static final IdentityAssuranceLevel IAL2 = new IdentityAssuranceLevel("ial2");
	
	
	/**
	 * Identity of the user proven by physical presence by an authorized
	 * and trained representative. Used in US NIST-800-63-3.
	 */
	public static final IdentityAssuranceLevel IAL3 = new IdentityAssuranceLevel("ial3");
	
	
	/**
	 * An assurance level that is, or equivalent to, a one-time code sent
	 * via mail to the address of the owner of the claims. Used in SE
	 * BankID.
	 */
	public static final IdentityAssuranceLevel AL2 = new IdentityAssuranceLevel("al2");
	
	
	/**
	 * An assurance level that is, or equivalent to, a in person
	 * verification with an ID document, but provided remotely. Used in SE
	 * BankID.
	 */
	public static final IdentityAssuranceLevel AL3 = new IdentityAssuranceLevel("al3");
	
	
	/**
	 * Creates a new identity assurance level.
	 *
	 * @param value The identity assurance level value. Must not be
	 *              {@code null}.
	 */
	public IdentityAssuranceLevel(final String value) {
		super(value);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof IdentityAssuranceLevel &&
			this.toString().equals(object.toString());
	}
}
