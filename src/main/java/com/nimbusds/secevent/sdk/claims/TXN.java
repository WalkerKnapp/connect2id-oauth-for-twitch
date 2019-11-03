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

package com.nimbusds.secevent.sdk.claims;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Transaction identifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Security Event Token (SET) (RFC 8417), section 2.2.
 * </ul>
 * <p>See
 */
@Immutable
public final class TXN extends Identifier {
	
	
	/**
	 * Creates a new transaction identifier with the specified value.
	 *
	 * @param value The transaction identifier value. Must not be
	 *              {@code null}.
	 */
	public TXN(final String value) {
		super(value);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof TXN &&
			this.toString().equals(object.toString());
	}
}
