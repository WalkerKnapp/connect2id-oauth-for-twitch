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

package com.nimbusds.oauth2.sdk.id;


import net.jcip.annotations.Immutable;


/**
 * Client identifier.
 *
 * <p>Example of a client identifier created from string:
 *
 * <pre>
 * ClientID clientID = new ClientID("client-12345678");
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749)
 * </ul>
 */
@Immutable
public final class ClientID extends Identifier {
	
	
	private static final long serialVersionUID = 8098426263125084877L;
	
	
	/**
	 * Creates a new client identifier with the specified value.
	 *
	 * @param value The client identifier value. Must not be {@code null}
	 *              or empty string.
	 */
	public ClientID(final String value) {

		super(value);
	}


	/**
	 * Creates a new client identifier with the specified value.
	 *
	 * @param value The value. Must not be {@code null}.
	 */
	public ClientID(final Identifier value) {

		super(value.getValue());
	}


	/**
	 * Creates a new client identifier with a randomly generated value of 
	 * the specified byte length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	public ClientID(final int byteLength) {
	
		super(byteLength);
	}
	
	
	/**
	 * Creates a new client identifier with a randomly generated 256-bit 
	 * (32-byte) value, Base64URL-encoded.
	 */
	public ClientID() {

		super();
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof ClientID &&
		       this.toString().equals(object.toString());
	}
}