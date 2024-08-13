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
 * Identity verification method.
 *
 * <p>Implementers should use a combination of a {@link ValidationMethod} and a
 * {@link VerificationMethod}, unless required to use this coarser method by
 * the {@link com.nimbusds.openid.connect.sdk.assurance.IdentityTrustFramework}.
 * Use of this parameter will eventually be deprecated.
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 *     <li>https://bitbucket.org/openid/ekyc-ida/wiki/identifiers
 * </ul>
 */
@Immutable
public final class IdentityVerificationMethod extends Identifier {
	
	
	private static final long serialVersionUID = -1448312497675040627L;
	
	
	/**
	 * Physical in-Person proofing.
	 */
	public static final IdentityVerificationMethod PIPP = new IdentityVerificationMethod("pipp");
	
	
	/**
	 * Supervised remote in-person proofing.
	 */
	public static final IdentityVerificationMethod SRIPP = new IdentityVerificationMethod("sripp");
	
	
	/**
	 * Online verification of an electronic ID card.
	 */
	public static final IdentityVerificationMethod EID = new IdentityVerificationMethod("eid");
	
	
	/**
	 * Unsupervised remote in-person proofing with video capture of the ID
	 * document, user self-portrait video and liveness checks.
	 */
	public static final IdentityVerificationMethod URIPP = new IdentityVerificationMethod("uripp");
	
	
	/**
	 * Electronic onsite reading of the document’s chip using an
	 * authorisation certificate and card access number.
	 */
	public static final IdentityVerificationMethod ONSITE = new IdentityVerificationMethod("onsite");
	
	
	/**
	 * Creates a new identity verification method.
	 *
	 * @param value The verification method value. Must not be
	 *              {@code null}.
	 */
	public IdentityVerificationMethod(final String value) {
		super(value);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof IdentityVerificationMethod &&
			this.toString().equals(object.toString());
	}
}
