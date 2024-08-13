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

package com.nimbusds.openid.connect.sdk.claims;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * OAuth 2.0 client authorized to use the ID Token as an OAuth access token, 
 * if different than the client that requested the ID Token ({@code azp}). It 
 * must contain the {@link com.nimbusds.oauth2.sdk.id.ClientID client 
 * identifier} of the authorised party.
 *
 * <p>The client identifier can be a URI or an arbitrary string.
 *
 * <p>See also {@link com.nimbusds.oauth2.sdk.id.ClientID}.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 *     <li>OAuth 2.0 (RFC 6749)
 * </ul>
 */
@Immutable
public final class AuthorizedParty extends Identifier {
	
	
	private static final long serialVersionUID = 3112051874363693975L;
	
	
	/**
	 * Creates a new authorised party identifier with the specified value.
	 *
	 * @param value The authorised party identifier value. Must not be 
	 *              {@code null}.
	 */
	public AuthorizedParty(final String value) {
	
		super(value);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof AuthorizedParty &&
		       this.toString().equals(object.toString());
	}
}
