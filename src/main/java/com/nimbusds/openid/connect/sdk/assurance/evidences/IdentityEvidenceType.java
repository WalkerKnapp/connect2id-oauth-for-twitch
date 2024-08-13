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
 * Identity evidence type.
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
@Immutable
public final class IdentityEvidenceType extends Identifier {
	
	
	private static final long serialVersionUID = -8665674793321133128L;
	
	
	/**
	 * Verification based on a physical or electronic document provided by
	 * the end-user.
	 */
	public static final IdentityEvidenceType DOCUMENT = new IdentityEvidenceType("document");
	
	
	/**
	 * Verification based on a government issued identity document.
	 *
	 * @deprecated Use {@link #DOCUMENT} instead.
	 */
	@Deprecated
	public static final IdentityEvidenceType ID_DOCUMENT = new IdentityEvidenceType("id_document");
	
	
	/**
	 * Verification based on data or information obtained electronically
	 * from an approved or recognised source.
	 */
	public static final IdentityEvidenceType ELECTRONIC_RECORD = new IdentityEvidenceType("electronic_record");
	
	
	/**
	 * Verification based on an attestation or reference given by an
	 * approved or recognised person declaring they believe to the best of
	 * their knowledge that the claim(s) are genuine and true.
	 */
	public static final IdentityEvidenceType VOUCH = new IdentityEvidenceType("vouch");
	
	
	/**
	 * Verification based on a utility bill.
	 */
	public static final IdentityEvidenceType UTILITY_BILL = new IdentityEvidenceType("utility_bill");
	
	
	/**
	 * Verification based on an electronic signature.
	 */
	public static final IdentityEvidenceType ELECTRONIC_SIGNATURE = new IdentityEvidenceType("electronic_signature");
	
	
	/**
	 * Verification based on a eIDAS Qualified Electronic Signature.
	 *
	 * @deprecated Use {@link #ELECTRONIC_SIGNATURE} instead.
	 */
	@Deprecated
	public static final IdentityEvidenceType QES = new IdentityEvidenceType("qes");
	
	
	/**
	 * Creates a new identity evidence type.
	 *
	 * @param value The identity evidence type value. Must not be
	 *              {@code null}.
	 */
	public IdentityEvidenceType(final String value) {
		super(value);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof IdentityEvidenceType &&
			this.toString().equals(object.toString());
	}
}
