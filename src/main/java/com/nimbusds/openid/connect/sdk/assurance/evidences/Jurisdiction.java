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

package com.nimbusds.openid.connect.sdk.assurance.evidences;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Jurisdiction.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0, sections 5.1.1.1 and
 *         5.1.1.2.
 * </ul>
 */
@Immutable
public final class Jurisdiction extends Identifier {
	
	
	private static final long serialVersionUID = 7101336010692838093L;
	
	
	/**
	 * Creates a new jurisdiction.
	 *
	 * @param value The jurisdiction value. Must not be {@code null} or
	 *              empty string.
	 */
	public Jurisdiction(final String value) {
		super(value);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof Jurisdiction &&
			this.toString().equals(object.toString());
	}
}
