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

package com.nimbusds.openid.connect.sdk;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.util.StringUtils;


/**
 * Nonce. This is a random, unique string value to associate a user-session 
 * with an ID Token and to mitigate replay attacks.
 *
 * <p>Example generation of a 16 byte random nonce:
 *
 * <pre>
 * Nonce nonce = new Nonce(16);
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 * </ul>
 */
@Immutable
public final class Nonce extends Identifier {
	
	
	private static final long serialVersionUID = 1484679928325180239L;
	
	
	/**
	 * Creates a new nonce with the specified value.
	 *
	 * @param value The nonce value. Must not be {@code null} or empty 
	 *              string.
	 */
	public Nonce(final String value) {
	
		super(value);
	}


	/**
	 * Creates a new nonce with a randomly generated value of the specified
	 * byte length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	public Nonce(final int byteLength) {
	
		super(byteLength);
	}
	
	
	/**
	 * Creates a new nonce with a randomly generated 256-bit (32-byte) 
	 * value, Base64URL-encoded.
	 */
	public Nonce() {

		super();
	}
	
	
	@Override
	public boolean equals(final Object object) {
	
		return object instanceof Nonce &&
		       this.toString().equals(object.toString());
	}
	
	
	/**
	 * Parses a nonce from the specified string.
	 *
	 * @param s The string to parse, {@code null} or empty if no nonce is
	 *          specified.
	 *
	 * @return The nonce, {@code null} if the parsed string was 
	 *         {@code null} or empty.
	 */
	public static Nonce parse(final String s) {
	
		if (StringUtils.isBlank(s))
			return null;
		
		return new Nonce(s);
	}
	
	
	/**
	 * Returns {@code true} if the specified OAuth 2.0 response type
	 * requires a nonce.
	 *
	 * @param responseType The response type. Must not be {@code null}.
	 *
	 * @return {@code true} if a nonce is required, {@code false} if not.
	 */
	public static boolean isRequired(final ResponseType responseType) {
		
		return
			// implicit https://openid.net/specs/openid-connect-core-1_0-27.html#ImplicitAuthRequest
			responseType.equals(ResponseType.IDTOKEN) || responseType.equals(ResponseType.IDTOKEN_TOKEN)
			
			||
			
			// hybrid https://openid.net/specs/openid-connect-core-1_0-27.html#HybridAuthRequest
			responseType.equals(ResponseType.CODE_IDTOKEN) || responseType.equals(ResponseType.CODE_IDTOKEN_TOKEN);
	}
}
