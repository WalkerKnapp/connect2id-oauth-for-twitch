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
 * Version identifier for an OAuth 2.0 client software.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)
 * </ul>
 */
@Immutable
public final class SoftwareVersion extends Identifier {
	
	
	private static final long serialVersionUID = -7983464258144627949L;
	
	
	/**
	 * Creates a new OAuth 2.0 client software version identifier with the
	 * specified value.
	 *
	 * @param value The software version identifier value. Must not be
	 *              {@code null} or empty string.
	 */
	public SoftwareVersion(final String value) {

		super(value);
	}


	@Override
	public boolean equals(final Object object) {

		return object instanceof SoftwareVersion &&
		       this.toString().equals(object.toString());
	}
}
