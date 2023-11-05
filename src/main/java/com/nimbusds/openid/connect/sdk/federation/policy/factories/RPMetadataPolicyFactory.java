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

package com.nimbusds.openid.connect.sdk.federation.policy.factories;


import com.nimbusds.openid.connect.sdk.federation.policy.MetadataPolicy;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;


/**
 * OpenID relying party metadata policy factory.
 */
@Deprecated
public interface RPMetadataPolicyFactory {
	
	
	/**
	 * Creates an OpenID relying party metadata policy for an explicit
	 * client registration.
	 *
	 * @param initialMetadata The initial metadata submitted by the relying
	 *                        party. Must not be {@code null}.
	 * @param target          The registered OpenID relying party
	 *                        information. Must not be {@code null}.
	 *
	 * @return The OpenID relying party metadata policy.
	 *
	 * @throws PolicyFormulationException If the metadata policy couldn't
	 *                                    be formulated.
	 */
	MetadataPolicy create(final OIDCClientMetadata initialMetadata, final OIDCClientInformation target)
		throws PolicyFormulationException;
}
