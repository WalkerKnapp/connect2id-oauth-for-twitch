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

package com.nimbusds.openid.connect.sdk.federation.trust;


import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;


/**
 * Federation entity metadata validator.
 */
public interface EntityMetadataValidator {
	
	
	/**
	 * Returns the entity type of the metadata that is validated.
	 *
	 * @return The federation entity type.
	 */
	EntityType getType();
	
	
	/**
	 * Validates the specified metadata.
	 *
	 * @param entityID The entity ID.
	 * @param metadata The metadata, {@code null} if none.
	 *
	 * @throws InvalidEntityMetadataException If validation failed.
	 */
	void validate(final EntityID entityID, final JSONObject metadata)
		throws InvalidEntityMetadataException;
}
