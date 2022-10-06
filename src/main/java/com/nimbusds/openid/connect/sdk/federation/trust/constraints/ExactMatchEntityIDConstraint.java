/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.federation.trust.constraints;


import java.util.Objects;

import net.jcip.annotations.Immutable;

import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;


/**
 * Exact match entity ID constraint.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 5.5.2.
 *     <li>RFC 5280, section 4.2.1.10.
 * </ul>
 */
@Immutable
public final class ExactMatchEntityIDConstraint extends EntityIDConstraint {
	
	
	/**
	 * The exact entity ID to match.
	 */
	private final EntityID entityID;
	
	
	/**
	 * Creates a new exact match entity ID constraint.
	 *
	 * @param entityID The exact entity ID to match. Must not be
	 *                 {@code null}.
	 */
	public ExactMatchEntityIDConstraint(final EntityID entityID) {
		if (entityID == null) {
			throw new IllegalArgumentException("The entity ID must not be null");
		}
		this.entityID = entityID;
	}
	
	
	@Override
	public boolean matches(final EntityID entityID) {
		return this.entityID.equals(entityID);
	}
	
	
	@Override
	public String toString() {
		return entityID.getValue();
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof ExactMatchEntityIDConstraint)) return false;
		ExactMatchEntityIDConstraint that = (ExactMatchEntityIDConstraint) o;
		return entityID.equals(that.entityID);
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(entityID);
	}
}
