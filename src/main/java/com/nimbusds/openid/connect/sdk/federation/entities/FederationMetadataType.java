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

package com.nimbusds.openid.connect.sdk.federation.entities;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Federation metadata type.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 4.
 * </ul>
 */
@Immutable
public final class FederationMetadataType extends Identifier {
	
	
	private static final long serialVersionUID = 345842707286531482L;
	
	
	/**
	 * OpenID relying party ({@code openid_relying_party}).
	 */
	public static final FederationMetadataType OPENID_RELYING_PARTY = new FederationMetadataType("openid_relying_party");
	
	
	/**
	 * OpenID provider ({@code openid_provider}).
	 */
	public static final FederationMetadataType OPENID_PROVIDER = new FederationMetadataType("openid_provider");
	
	
	/**
	 * OAuth authorisation server ({@code oauth_authorization_server}).
	 */
	public static final FederationMetadataType OAUTH_AUTHORIZATION_SERVER = new FederationMetadataType("oauth_authorization_server");
	
	
	/**
	 * OAuth client ({@code oauth_client}).
	 */
	public static final FederationMetadataType OAUTH_CLIENT = new FederationMetadataType("oauth_client");
	
	
	/**
	 * OAuth protected resource ({@code oauth_resource}).
	 */
	public static final FederationMetadataType OAUTH_RESOURCE = new FederationMetadataType("oauth_resource");
	
	
	/**
	 * Federation entity ({@code federation_entity}).
	 */
	public static final FederationMetadataType FEDERATION_ENTITY = new FederationMetadataType("federation_entity");
	
	
	/**
	 * Trust mark issuer ({@code trust_mark_issuer}).
	 */
	public static final FederationMetadataType TRUST_MARK_ISSUER = new FederationMetadataType("trust_mark_issuer");
	
	
	/**
	 * Creates a new federation metadata type.
	 *
	 * @param value The metadata type value. Must not be {@code null}.
	 */
	public FederationMetadataType(final String value) {
		super(value);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof FederationMetadataType &&
			this.toString().equals(object.toString());
	}
}
