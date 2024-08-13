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

package com.nimbusds.openid.connect.sdk.op;


import java.net.URI;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.AbstractConfigurationRequest;
import com.nimbusds.oauth2.sdk.WellKnownPathComposeStrategy;
import com.nimbusds.oauth2.sdk.id.Issuer;


/**
 * OpenID Provider (OP) configuration request.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * GET /.well-known/openid-configuration HTTP/1.1
 * Host: example.com
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Discovery 1.0
 * </ul>
 */
@Immutable
public class OIDCProviderConfigurationRequest extends AbstractConfigurationRequest {
	
	
	/**
	 * The well-known path for OpenID Provider metadata.
	 */
	public static final String OPENID_PROVIDER_WELL_KNOWN_PATH = "/.well-known/openid-configuration";
	
	
	/**
	 * Creates a new OpenID Provider configuration request using the
	 * {@link WellKnownPathComposeStrategy#POSTFIX postfix well-known path
	 * composition strategy}.
	 *
	 * @param issuer The issuer. Must represent a valid URL.
	 */
	public OIDCProviderConfigurationRequest(final Issuer issuer) {
		this(issuer, WellKnownPathComposeStrategy.POSTFIX);
	}
	
	
	/**
	 * Creates a new OpenID Provider configuration request.
	 *
	 * @param issuer   The issuer. Must represent a valid URL.
	 * @param strategy The well-known path composition strategy. Must not
	 *                 be {@code null}.
	 *
	 */
	public OIDCProviderConfigurationRequest(final Issuer issuer, final WellKnownPathComposeStrategy strategy) {
		super(URI.create(issuer.getValue()), OPENID_PROVIDER_WELL_KNOWN_PATH, strategy);
	}
}
