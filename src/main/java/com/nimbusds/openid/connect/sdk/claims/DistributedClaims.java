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

package com.nimbusds.openid.connect.sdk.claims;


import java.net.URI;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import net.minidev.json.JSONObject;


/**
 * Distributed OpenID claims set.
 *
 * <p>Example distributed claims with an access token (included in a UserInfo
 * response):
 *
 * <pre>
 * {
 *   "_claim_names"   : { "credit_score" : "src1" },
 *   "_claim_sources" : { "src1" : { "endpoint"     : "https://creditagency.example.com/claims_here",
 *                                   "access_token" : "ksj3n283dke" } }
 * }
 * </pre>
 *
 * <p>Example distributed claims without a specified access token (included in
 * a UserInfo response):
 *
 * <pre>
 * {
 *   "_claim_names" : { "payment_info"     : "src2",
 *                      "shipping_address" : "src2" },
 *   "_claim_sources" : { "src2" : { "endpoint" : "https://bank.example.com/claim_source" } }
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 * </ul>
 */
public class DistributedClaims extends ExternalClaims {
	
	
	/**
	 * The claims source endpoint.
	 */
	private final URI sourceEndpoint;
	
	
	/**
	 * Access token for retrieving the claims at the source URI,
	 * {@code null} if not specified.
	 */
	private final AccessToken accessToken;
	
	
	/**
	 * Creates a new aggregated OpenID claims instance, the claims source
	 * identifier is set to a GUUID string.
	 *
	 * @param names          The claim names. Must not be {@code null} or
	 *                       empty.
	 * @param sourceEndpoint The claims source endpoint. Must not be
	 *                       {@code null}.
	 * @param accessToken    Access token for retrieving the claims at the
	 *                       source endpoint, {@code null} if not
	 *                       specified.
	 */
	public DistributedClaims(final Set<String> names, final URI sourceEndpoint, final AccessToken accessToken) {
		
		this(UUID.randomUUID().toString(), names, sourceEndpoint, accessToken);
	}
	
	
	/**
	 * Creates a new aggregated OpenID claims instance.
	 *
	 * @param sourceID       Identifier for the claims source. Must not be
	 *                       {@code null} or empty string.
	 * @param names          The claim names. Must not be {@code null} or
	 *                       empty.
	 * @param sourceEndpoint The claims source endpoint. Must not be
	 *                       {@code null}.
	 * @param accessToken    Access token for retrieving the claims at the
	 *                       source endpoint, {@code null} if not
	 *                       specified.
	 */
	public DistributedClaims(final String sourceID, final Set<String> names, final URI sourceEndpoint, final AccessToken accessToken) {
		
		super(sourceID, names);
		this.sourceEndpoint = Objects.requireNonNull(sourceEndpoint);
		this.accessToken = accessToken;
	}
	
	
	/**
	 * Returns the claims source endpoint.
	 *
	 * @return The claims source endpoint.
	 */
	public URI getSourceEndpoint() {
		
		return sourceEndpoint;
	}
	
	
	/**
	 * Returns the access token for retrieving the claims at the source
	 * endpoint.
	 *
	 * @return The access token for retrieving the claims at the source
	 *         endpoint, {@code null} if not specified.
	 */
	public AccessToken getAccessToken() {
		
		return accessToken;
	}
	
	
	@Override
	void mergeInto(final JSONObject jsonObject) {
		
		JSONObject claimNamesObject = new JSONObject();
		
		for (String name: getNames()) {
			claimNamesObject.put(name, getSourceID());
		}
		
		if (jsonObject.containsKey("_claim_names")) {
			((JSONObject) jsonObject.get("_claim_names")).putAll(claimNamesObject);
		} else {
			jsonObject.put("_claim_names", claimNamesObject);
		}
		
		JSONObject sourceSpec = new JSONObject();
		sourceSpec.put("endpoint", getSourceEndpoint().toString());
		if (getAccessToken() != null) {
			sourceSpec.put("access_token", getAccessToken().getValue());
		}
		JSONObject claimSourcesObject = new JSONObject();
		claimSourcesObject.put(getSourceID(), sourceSpec);
		
		if (jsonObject.containsKey("_claim_sources")) {
			((JSONObject) jsonObject.get("_claim_sources")).putAll(claimSourcesObject);
		} else {
			jsonObject.put("_claim_sources", claimSourcesObject);
		}
	}
}
