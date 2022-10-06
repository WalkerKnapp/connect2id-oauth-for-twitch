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

package com.nimbusds.openid.connect.sdk.federation.trust.constraints;


import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;


/**
 * Leaf entity type constraint.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 5.2.3.
 * </ul>
 */
@Immutable
public final class LeafEntityTypeConstraint {
	
	
	/**
	 * Any leaf entity types allowed constant.
	 */
	public static final LeafEntityTypeConstraint ANY = new LeafEntityTypeConstraint(null);
	
	
	/**
	 * The allowed leaf entity types, {@code null} or empty for any.
	 */
	private final Set<EntityType> allowed;
	
	
	/**
	 * Creates a new leaf entity type constraint.
	 *
	 * @param allowed The allowed leaf entity types, {@code null} or empty
	 *                for any.
	 */
	public LeafEntityTypeConstraint(final Set<EntityType> allowed) {
		this.allowed = CollectionUtils.isNotEmpty(allowed) ? allowed : null;
	}
	
	
	/**
	 * Returns {@code true} if any leaf entity types are allowed.
	 *
	 * @return {@code true} if any leaf entity types are allowed.
	 */
	public boolean allowsAny() {
		return CollectionUtils.isEmpty(allowed);
	}
	
	
	/**
	 * Returns the allowed leaf entity types.
	 *
	 * @return The allowed leaf entity types, {@code null} for any.
	 */
	public Set<EntityType> getAllowed() {
		return allowed;
	}
	
	
	/**
	 * Returns the allowed leaf entity types as a string list.
	 *
	 * @return The allowed leaf entity types as a string list, {@code null}
	 *         for any.
	 */
	public List<String> getAllowedAsStringList() {
		if (allowsAny()) {
			return null;
		}
		return Identifier.toStringList(allowed);
	}
	
	
	/**
	 * Returns {@code true} if the specified entity type is allowed for a
	 * leaf entity.
	 *
	 * @param type The entity type.
	 *
	 * @return {@code true} if the entity type is allowed, else
	 *         {@code false}.
	 */
	public boolean isAllowed(final EntityType type) {
		return allowsAny() || allowed.contains(type);
	}
	
	
	@Override
	public String toString() {
		if (allowsAny()) {
			return "null";
		}
		return allowed.toString();
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof LeafEntityTypeConstraint)) return false;
		LeafEntityTypeConstraint that = (LeafEntityTypeConstraint) o;
		return Objects.equals(getAllowed(), that.getAllowed());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(getAllowed());
	}
	
	
	/**
	 * Parses a leaf entity type constraint.
	 *
	 * @param values The string values, {@code null} if not specified.
	 *
	 * @return The parsed leaf entity type constraint.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static LeafEntityTypeConstraint parse(final List<String> values)
		throws ParseException {
		
		if (CollectionUtils.isEmpty(values)) {
			return ANY;
		}
		
		Set<EntityType> types = new HashSet<>();
		
		for (String v: values) {
			types.add(new EntityType(v));
		}
		
		return new LeafEntityTypeConstraint(types);
	}
}
