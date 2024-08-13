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

package com.nimbusds.openid.connect.sdk.assurance.evidences;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * The type of method used to validate the authenticity of an evidence.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 *     <li>https://bitbucket.org/openid/ekyc-ida/wiki/identifiers
 * </ul>
 */
@Immutable
public final class ValidationMethodType extends Identifier {
	
	
	private static final long serialVersionUID = -6994497310463726386L;
	
	
	/**
	 * Validation that physical evidence is genuine through inspection of
	 * its physical properties in person.
	 */
	public static final ValidationMethodType VPIP = new ValidationMethodType("vpip");
	
	
	/**
	 * Validation that physical evidence is genuine through inspection of
	 * its physical properties in person including its optical
	 * characteristics under non-visible light.
	 */
	public static final ValidationMethodType VPIRUV = new ValidationMethodType("vpiruv");
	
	
	/**
	 * Validation that physical evidence is genuine through the inspection
	 * of an image taken remotely under visible light.
	 */
	public static final ValidationMethodType VRI = new ValidationMethodType("vri");
	
	
	/**
	 * Validation that digital/electronic evidence is genuine by the
	 * inspection of its properties and content.
	 */
	public static final ValidationMethodType VDIG = new ValidationMethodType("vdig");
	
	
	/**
	 * Validation the cryptographic security features of the evidence are
	 * intact and correct.
	 */
	public static final ValidationMethodType VCRYPT = new ValidationMethodType("vcrypt");
	
	
	/**
	 * Found an existing electronic record that matches the claims made by
	 * the user.
	 */
	public static final ValidationMethodType DATA = new ValidationMethodType("data");
	
	
	/**
	 * Creates a new validation method type.
	 *
	 * @param value The validation method type value. Must not be
	 *              {@code null}.
	 */
	public ValidationMethodType(final String value) {
		super(value);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof ValidationMethodType &&
			this.toString().equals(object.toString());
	}
}
