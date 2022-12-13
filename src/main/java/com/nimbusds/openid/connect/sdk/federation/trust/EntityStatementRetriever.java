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


import java.net.URI;

import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;


/**
 * Entity statement retriever for resolving trust chains.
 */
public interface EntityStatementRetriever {
	
	
	/**
	 * Fetches an entity configuration.
	 *
	 * @param target The entity ID. Must not be {@code null}.
	 *
	 * @return The entity statement.
	 *
	 * @throws ResolveException If fetching failed.
	 */
	EntityStatement fetchEntityConfiguration(final EntityID target)
		throws ResolveException;
	
	
	/**
	 * Fetches an entity statement.
	 *
	 * @param federationAPIEndpoint The federation API endpoint. Must not
	 *                              be {@code null}.
	 * @param issuer                The entity statement issuer, typically
	 *                              the ID of the entity operating the
	 *                              endpoint. Must not be {@code null}.
	 * @param subject               The entity statement subject. Must not
	 *                              be {@code null}.
	 *
	 * @return The entity statement.
	 *
	 * @throws ResolveException If fetching failed.
	 */
	EntityStatement fetchEntityStatement(final URI federationAPIEndpoint, final EntityID issuer, final EntityID subject)
		throws ResolveException;
}
