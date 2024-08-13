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

package com.nimbusds.oauth2.sdk.device;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Device code.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Device Authorization Grant (RFC 8628)
 * </ul>
 */
@Immutable
public final class DeviceCode extends Identifier {
	
	
	private static final long serialVersionUID = 5165818656410539254L;
	
	
	/**
	 * Creates a new device code with the specified value.
	 *
	 * @param value The code value. Must not be {@code null} or empty
	 *              string.
	 */
	public DeviceCode(final String value) {

		super(value);
	}


	/**
	 * Creates a new device code with a randomly generated value of the
	 * specified byte length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   greater than one.
	 */
	public DeviceCode(final int byteLength) {

		super(byteLength);
	}


	/**
	 * Creates a new device code with a randomly generated 256-bit (32-byte)
	 * value, Base64URL-encoded.
	 */
	public DeviceCode() {

		super();
	}


	@Override
	public boolean equals(final Object object) {

		return object instanceof DeviceCode && this.toString().equals(object.toString());
	}
}
