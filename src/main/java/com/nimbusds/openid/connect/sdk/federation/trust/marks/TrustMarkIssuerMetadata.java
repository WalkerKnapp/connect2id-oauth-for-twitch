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

package com.nimbusds.openid.connect.sdk.federation.trust.marks;


import java.net.URI;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Trust mark issuer metadata.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 4.8.
 * </ul>
 */
public class TrustMarkIssuerMetadata {
	
	
	/**
	 * The federation status endpoint.
	 */
	private final URI federationStatusEndpoint;
	
	
	/**
	 * Creates a new trust mark issuer metadata.
	 *
	 * @param federationStatusEndpoint The federation status endpoint,
	 *                                 {@code null} if not specified.
	 */
	public TrustMarkIssuerMetadata(final URI federationStatusEndpoint) {
		this.federationStatusEndpoint = federationStatusEndpoint;
	}
	
	
	/**
	 * Gets the federation status endpoint URI. Corresponds to the
	 * {@code federation_status_endpoint} metadata field.
	 *
	 * @return The federation status endpoint URI, {@code null} if not
	 *         specified.
	 */
	public URI getFederationStatusEndpointURI() {
		return federationStatusEndpoint;
	}
	
	
	/**
	 * Returns a JSON object representation of this trust mark issuer
	 * metadata.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "endpoint": "https://trust_marks_are_us.example.com/status"
	 * }
	 * </pre>
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		
		JSONObject o = new JSONObject();
		if (getFederationStatusEndpointURI() != null) {
			o.put("federation_status_endpoint", getFederationStatusEndpointURI().toString());
		}
		return o;
	}
	
	
	/**
	 * Parses a trust mark issuer metadata from the specified JSON object.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "endpoint": "https://trust_marks_are_us.example.com/status"
	 * }
	 * </pre>
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The trust mark issuer metadata.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static TrustMarkIssuerMetadata parse(final JSONObject jsonObject)
		throws ParseException {
		
		return new TrustMarkIssuerMetadata(
			JSONObjectUtils.getURI(jsonObject, "federation_status_endpoint", null)
		);
	}
	
	
	/**
	 * Parses a trust mark issuer metadata from the specified JSON object
	 * string.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "endpoint": "https://trust_marks_are_us.example.com/status"
	 * }
	 * </pre>
	 *
	 * @param json The JSON object string. Must not be {@code null}.
	 *
	 * @return The trust mark issuer metadata.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static TrustMarkIssuerMetadata parse(final String json)
		throws ParseException {
		
		return parse(JSONObjectUtils.parse(json));
	}
}
