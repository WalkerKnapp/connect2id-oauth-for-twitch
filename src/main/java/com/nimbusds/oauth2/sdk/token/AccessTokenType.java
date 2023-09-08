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

package com.nimbusds.oauth2.sdk.token;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Access token type.
 */
@Immutable
public final class AccessTokenType extends Identifier {
	
	
	private static final long serialVersionUID = 5636341646710940413L;
	
	
	/**
	 * Bearer, see OAuth 2.0 Bearer Token Usage (RFC 6750).
	 */
	public static final AccessTokenType BEARER = new AccessTokenType("Bearer");
	
	
	/**
	 * DPoP, see OAuth 2.0 Demonstrating Proof-of-Possession at the
	 * Application Layer (DPoP) (RFC 9449).
	 */
	public static final AccessTokenType DPOP = new AccessTokenType("DPoP");
	
	
	/**
	 * MAC, see OAuth 2.0 Message Authentication Code (MAC) Tokens
	 * (draft-ietf-oauth-v2-http-mac-05).
	 */
	public static final AccessTokenType MAC = new AccessTokenType("mac");
	
	
	/**
	 * Unknown.
	 */
	public static final AccessTokenType UNKNOWN = new AccessTokenType("unknown");

	/**
	 * Not applicable (N/A), see OAuth 2.0 Token Exchange (RFC 8693).
	 */
	public static final AccessTokenType N_A = new AccessTokenType("N_A");
	
	
	/**
	 * Creates a new access token type with the specified value.
	 *
	 * @param value The access token type value. Must not be {@code null} 
	 *              or empty string.
	 */
	public AccessTokenType(final String value) {

		super(value);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof AccessTokenType &&
		       this.toString().equalsIgnoreCase(object.toString());
	}
}
