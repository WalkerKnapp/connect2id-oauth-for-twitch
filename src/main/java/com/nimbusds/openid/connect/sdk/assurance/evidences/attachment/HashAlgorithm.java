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

package com.nimbusds.openid.connect.sdk.assurance.evidences.attachment;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Hash algorithm.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 *     <li>IANA Named Information Hash Algorithm Registry
 * </ul>
 */
@Immutable
public final class HashAlgorithm extends Identifier {
	
	
	private static final long serialVersionUID = -3699666147154820591L;
	
	
	/**
	 * SHA-256.
	 */
	public static final HashAlgorithm SHA_256 = new HashAlgorithm("sha-256");
	
	
	/**
	 * SHA-384.
	 */
	public static final HashAlgorithm SHA_384 = new HashAlgorithm("sha-384");
	
	
	/**
	 * SHA-512.
	 */
	public static final HashAlgorithm SHA_512 = new HashAlgorithm("sha-512");
	
	
	/**
	 * Creates a new hash algorithm with the specified name, normalised to
	 * lowercase.
	 *
	 * @param name The name. Must not be {@code null}.
	 */
	public HashAlgorithm(final String name) {
		super(name.toLowerCase());
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof HashAlgorithm &&
			this.toString().equals(object.toString());
	}
}
