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
 * The type of method used to verify that a person is the owner of a set of
 * claims.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 *     <li>https://bitbucket.org/openid/ekyc-ida/wiki/identifiers
 * </ul>
 */
@Immutable
public final class VerificationMethodType extends Identifier {
	
	
	private static final long serialVersionUID = 93318875234167356L;
	
	
	/**
	 * Verifying the user is the owner of the claims by use of an
	 * electronic authentication process that is linked to the owner of the
	 * claims.
	 */
	public static final VerificationMethodType AUTH = new VerificationMethodType("auth");
	
	
	/**
	 * Verifying the user is the owner of the claims by use of an
	 * electronic authentication token such as hardware token or smartcard
	 * that is linked and issued to the owner of the claims.
	 */
	public static final VerificationMethodType TOKEN= new VerificationMethodType("token");
	
	
	/**
	 * Verifying the user is the owner of the claims by knowledge based
	 * challenges / questions that only the owner of the claims should know
	 * how to answer.
	 */
	public static final VerificationMethodType KBV = new VerificationMethodType("kbv");
	
	
	/**
	 * Physical verification in person by a qualified / authorised person,
	 * the comparison of a physical characteristic (such as face) of the
	 * user with a known image / template of the owner of the claims.
	 */
	public static final VerificationMethodType PVP = new VerificationMethodType("pvp");
	
	
	/**
	 * Physical verification by a qualified / authorised person when the
	 * user is remote, the comparison of a physical characteristic (such as
	 * face) from an image or video of the user with a known image /
	 * template of the owner of the claims.
	 */
	public static final VerificationMethodType PVR = new VerificationMethodType("pvr");
	
	
	/**
	 * Biometric verification by an automated system with the user
	 * physically present to the system and the verifier, the use of a
	 * biometric modality (such as face) to match the user with a known
	 * template of the owner of the claims.
	 */
	public static final VerificationMethodType BVP = new VerificationMethodType("bvp");
	
	
	/**
	 * Biometric verification by an automated system where the user and
	 * capture device is remote to the verifier, the use of a biometric
	 * modality (such as face) to match the user with a known template of
	 * the owner of the claims.
	 */
	public static final VerificationMethodType BVR = new VerificationMethodType("bvr");
	
	
	/**
	 * Creates a new verification method type.
	 *
	 * @param value The verification method type value. Must not be
	 *              {@code null}.
	 */
	public VerificationMethodType(final String value) {
		super(value);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof VerificationMethodType &&
			this.toString().equals(object.toString());
	}
}
