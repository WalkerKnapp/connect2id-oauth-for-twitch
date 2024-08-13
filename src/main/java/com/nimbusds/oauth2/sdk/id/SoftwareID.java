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

import java.util.UUID;


/**
 * Identifier for an OAuth 2.0 client software.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)
 * </ul>
 */
@Immutable
public final class SoftwareID extends Identifier {
	
	
	private static final long serialVersionUID = -5570812158568461305L;
	
	
	/**
	 * Creates a new OAuth 2.0 client software identifier with the
	 * specified value.
	 *
	 * @param value The software identifier value. Must not be {@code null}
	 *              or empty string.
	 */
	public SoftwareID(final String value) {

		super(value);
	}


	/**
	 * Creates a new OAuth 2.0 client software that is a type 4 UUID.
	 */
	public SoftwareID() {

		this(UUID.randomUUID().toString());
	}


	@Override
	public boolean equals(final Object object) {

		return object instanceof SoftwareID &&
		       this.toString().equals(object.toString());
	}
}
