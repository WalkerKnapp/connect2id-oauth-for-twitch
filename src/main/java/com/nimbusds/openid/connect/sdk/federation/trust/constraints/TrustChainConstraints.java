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


import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;


/**
 * Trust chain constraints.
 *
 * <p>Example JSON object:
 *
 * <pre>
 * {
 *   "max_path_length"    : 2,
 *   "naming_constraints" : {
 *   	"permitted" : [ "https://example.com" ],
 *   	"excluded"  : [ "https://east.example.com" ]
 *   },
 *   "allowed_leaf_entity_types" : [ "openid_provider", "openid_relying_party" ]
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 5.2.
 *     <li>RFC 5280, section 4.2.1.10.
 * </ul>
 */
@Immutable
public final class TrustChainConstraints implements JSONAware {
	
	
	/**
	 * No constraint instance.
	 */
	public static final TrustChainConstraints NO_CONSTRAINTS = new TrustChainConstraints();
	
	
	/**
	 * The max path length, -1 if not specified.
	 */
	private final int maxPathLength;
	
	
	/**
	 * The permitted entity IDs.
	 */
	private final List<EntityIDConstraint> permittedEntityIDs;
	
	
	/**
	 * The excluded entity IDs.
	 */
	private final List<EntityIDConstraint> excludedEntityIDs;
	
	
	/**
	 * The leaf entity type constraint.
	 */
	private final LeafEntityTypeConstraint leafEntityTypeConstraint;
	
	
	/**
	 * Creates a new no constraints instance.
	 */
	public TrustChainConstraints() {
		this(-1, null, null, LeafEntityTypeConstraint.ANY);
	}
	
	
	/**
	 * Creates a new trust chain constraints instance.
	 *
	 * @param maxPathLength The maximum number of entities between this and
	 *                      the last one in the chain, -1 if not specified.
	 */
	public TrustChainConstraints(final int maxPathLength) {
		this(maxPathLength, null, null, null);
	}
	
	
	/**
	 * Creates a new trust chain constraints instance.
	 *
	 * @param maxPathLength      The maximum number of entities between
	 *                           this and the last one in the chain, -1 if
	 *                           not specified.
	 * @param permittedEntityIDs The permitted entity IDs, {@code null} if
	 *                           not specified.
	 * @param excludedEntityIDs  The excluded entities, {@code null} if not
	 *                           specified.
	 */
	public TrustChainConstraints(final int maxPathLength,
				     final List<EntityIDConstraint> permittedEntityIDs,
				     final List<EntityIDConstraint> excludedEntityIDs,
				     final LeafEntityTypeConstraint leafEntityTypeConstraint) {
		this.maxPathLength = maxPathLength;
		this.permittedEntityIDs = permittedEntityIDs != null ? permittedEntityIDs : Collections.<EntityIDConstraint>emptyList();
		this.excludedEntityIDs = excludedEntityIDs != null ? excludedEntityIDs : Collections.<EntityIDConstraint>emptyList();
		this.leafEntityTypeConstraint = leafEntityTypeConstraint != null ? leafEntityTypeConstraint : LeafEntityTypeConstraint.ANY;
	}
	
	
	/**
	 * Checks if the given number of intermediates is permitted.
	 *
	 * @param numIntermediatesInPath The number of intermediate entities
	 *                               between the entity specifying the
	 *                               constraints and the specified entity.
	 *                               Must be zero or greater.
	 *
	 * @return {@code true} if permitted, else {@code false}.
	 */
	public boolean isPermitted(final int numIntermediatesInPath) {
		
		if (numIntermediatesInPath < 0) {
			throw new IllegalArgumentException("The path length must not be negative");
		}
		
		return getMaxPathLength() <= -1 || numIntermediatesInPath <= getMaxPathLength();
	}
	
	
	/**
	 * Checks if the specified entity ID is permitted.
	 *
	 * @param entityID The entity ID. Must not be {@code null}.
	 *
	 * @return {@code true} if permitted, else {@code false}.
	 */
	public boolean isPermitted(final EntityID entityID) {
		
		if (getExcludedEntityIDs().isEmpty() && getPermittedEntityIDs().isEmpty()) {
			return true;
		}
		
		if (! getExcludedEntityIDs().isEmpty()) {
			
			for (EntityIDConstraint constraint: getExcludedEntityIDs()) {
				if (constraint.matches(entityID)) {
					return false;
				}
			}
		}
		
		if (! getPermittedEntityIDs().isEmpty()) {
			
			for (EntityIDConstraint constraint: getPermittedEntityIDs()) {
				if (constraint.matches(entityID)) {
					return true;
				}
			}
		} else {
			// If passed so far - always permitted
			return true;
		}
		
		return false;
	}
	
	
	/**
	 * Checks if the entity ID with the given number of intermediates is
	 * allowed.
	 *
	 * @param numIntermediatesInPath The number of intermediate entities
	 *                               between the entity specifying the
	 *                               constraints and the specified entity.
	 *                               Must be zero or greater.
	 *
	 * @param entityID               The entity ID. Must not be
	 *                               {@code null}.
	 *
	 * @return {@code true} if allowed, else {@code false}.
	 */
	public boolean isPermitted(final int numIntermediatesInPath, final EntityID entityID) {
		
		return isPermitted(numIntermediatesInPath) && isPermitted(entityID);
	}
	
	
	/**
	 * Returns the maximum number of entities between this and the last one
	 * in the chain.
	 *
	 * @return The maximum number of entities between this and the last one
	 *         in the chain, -1 if not specified.
	 */
	public int getMaxPathLength() {
		return maxPathLength;
	}
	
	
	/**
	 * Returns the allowed entity IDs.
	 *
	 * @return The allowed entity IDs, empty list if not specified.
	 */
	public List<EntityIDConstraint> getPermittedEntityIDs() {
		return permittedEntityIDs;
	}
	
	
	/**
	 * Returns the excluded entity IDs.
	 *
	 * @return The excluded entity IDs, empty list if not specified.
	 */
	public List<EntityIDConstraint> getExcludedEntityIDs() {
		return excludedEntityIDs;
	}
	
	
	/**
	 * Returns the leaf entity type constraint.
	 *
	 * @return The leaf entity type constraint.
	 */
	public LeafEntityTypeConstraint getLeafEntityTypeConstraint() {
		return leafEntityTypeConstraint;
	}
	
	
	/**
	 * Returns a JSON object representation of this trust chain
	 * constraints.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
	
		JSONObject o = new JSONObject();
		
		if (maxPathLength > -1) {
			o.put("max_path_length", maxPathLength);
		}
		
		JSONObject namingConstraints = new JSONObject();
		
		if (CollectionUtils.isNotEmpty(permittedEntityIDs)) {
			List<String> vals = new LinkedList<>();
			for (EntityIDConstraint v: permittedEntityIDs) {
				vals.add(v.toString());
			}
			namingConstraints.put("permitted", vals);
		}
		
		if (CollectionUtils.isNotEmpty(excludedEntityIDs)) {
			List<String> vals = new LinkedList<>();
			for (EntityIDConstraint v: excludedEntityIDs) {
				vals.add(v.toString());
			}
			namingConstraints.put("excluded", vals);
		}
		
		if (! namingConstraints.isEmpty()) {
			o.put("naming_constraints", namingConstraints);
		}
		
		if (! leafEntityTypeConstraint.allowsAny()) {
			o.put("allowed_leaf_entity_types", leafEntityTypeConstraint.getAllowedAsStringList());
		}
		
		return o;
	}
	
	
	@Override
	public String toJSONString() {
		return toJSONObject().toJSONString();
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof TrustChainConstraints)) return false;
		TrustChainConstraints that = (TrustChainConstraints) o;
		return getMaxPathLength() == that.getMaxPathLength() &&
			Objects.equals(getPermittedEntityIDs(), that.getPermittedEntityIDs()) &&
			Objects.equals(getExcludedEntityIDs(), that.getExcludedEntityIDs()) &&
			getLeafEntityTypeConstraint().equals(that.getLeafEntityTypeConstraint());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(getMaxPathLength(), getPermittedEntityIDs(), getExcludedEntityIDs(), getLeafEntityTypeConstraint());
	}
	
	
	/**
	 * Parses a trust chain constraints instance from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The trust chain constraints.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static TrustChainConstraints parse(final JSONObject jsonObject)
		throws ParseException {
		
		int maxPathLength = JSONObjectUtils.getInt(jsonObject, "max_path_length", -1);
		
		JSONObject namingConstraints = JSONObjectUtils.getJSONObject(jsonObject, "naming_constraints", new JSONObject());
		
		List<EntityIDConstraint> permitted = null;
		List<String> values = JSONObjectUtils.getStringList(namingConstraints, "permitted", null);
		if (values != null) {
			permitted = new LinkedList<>();
			for (String v: values) {
				if (v != null) {
					permitted.add(EntityIDConstraint.parse(v));
				}
			}
		}
		
		List<EntityIDConstraint> excluded = null;
		values = JSONObjectUtils.getStringList(namingConstraints, "excluded", null);
		if (values != null) {
			excluded = new LinkedList<>();
			for (String v: values) {
				if (v != null) {
					excluded.add(EntityIDConstraint.parse(v));
				}
			}
		}
		
		LeafEntityTypeConstraint leafEntityTypes = LeafEntityTypeConstraint.parse(
			JSONObjectUtils.getStringList(jsonObject, "allowed_leaf_entity_types", null)
		);
		
		return new TrustChainConstraints(maxPathLength, permitted, excluded, leafEntityTypes);
	}
}
