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

package com.nimbusds.openid.connect.sdk.federation.entities;


import java.net.URI;
import java.util.List;

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Federation entity metadata.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 4.8.
 * </ul>
 */
public class FederationEntityMetadata {
	
	
	/**
	 * The federation fetch endpoint.
	 */
	private URI federationFetchEndpoint;
	
	
	/**
	 * The federation list endpoint.
	 */
	private URI federationListEndpoint;
	
	
	/**
	 * The federation resolve endpoint.
	 */
	private URI federationResolveEndpoint;
	
	
	/**
	 * The federation trust mark status endpoint.
	 */
	private URI federationTrustMarkStatusEndpoint;
	
	
	/**
	 * The organisation name.
	 */
	private String organizationName;
	
	
	/**
	 * The contacts.
	 */
	private List<String> contacts;
	
	
	/**
	 * The logo URI.
	 */
	private URI logoURI;
	
	
	/**
	 * The policy URI.
	 */
	private URI policyURI;
	
	
	/**
	 * The homepage URI.
	 */
	private URI homepageURI;
	
	
	/**
	 * Creates a new federation entity metadata.
	 */
	public FederationEntityMetadata() {}
	
	
	/**
	 * Creates a new federation entity metadata.
	 *
	 * @param federationFetchEndpoint The federation fetch endpoint,
	 *                                required for trust anchors and
	 *                                intermediate entities, optional for
	 *                                leaf entities.
	 */
	public FederationEntityMetadata(final URI federationFetchEndpoint) {
		this.federationFetchEndpoint = federationFetchEndpoint;
	}
	
	
	/**
	 * Gets the federation fetch endpoint. Corresponds to the
	 * {@code federation_fetch_endpoint} metadata field.
	 *
	 * @return The federation fetch endpoint, {@code null} if not
	 *         specified.
	 */
	public URI getFederationFetchEndpointURI() {
		return federationFetchEndpoint;
	}
	
	
	/**
	 * Sets the federation fetch endpoint. Corresponds to the
	 * {@code federation_fetch_endpoint} metadata field.
	 *
	 * @param federationFetchEndpoint The federation fetch endpoint,
	 *                                {@code null} if not specified.
	 */
	public void setFederationFetchEndpointURI(final URI federationFetchEndpoint) {
		this.federationFetchEndpoint = federationFetchEndpoint;
	}
	
	
	/**
	 * Gets the federation list endpoint. Corresponds to the
	 * {@code federation_list_endpoint} metadata field.
	 *
	 * @return The federation list endpoint, {@code null} if not specified.
	 */
	public URI getFederationListEndpointURI() {
		return federationListEndpoint;
	}
	
	
	/**
	 * Sets the federation list endpoint. Corresponds to the
	 * {@code federation_list_endpoint} metadata field.
	 *
	 * @param federationListEndpoint The federation list endpoint,
	 *                               {@code null} if not specified.
	 */
	public void setFederationListEndpointURI(final URI federationListEndpoint) {
		this.federationListEndpoint = federationListEndpoint;
	}
	
	
	/**
	 * Gets the federation resolve endpoint. Corresponds to the
	 * {@code federation_resolve_endpoint} metadata field.
	 *
	 * @return The federation resolve endpoint, {@code null} if not
	 *         specified.
	 */
	public URI getFederationResolveEndpointURI() {
		return federationResolveEndpoint;
	}
	
	
	/**
	 * Sets the federation resolve endpoint. Corresponds to the
	 * {@code federation_resolve_endpoint} metadata field.
	 *
	 * @param federationResolveEndpoint The federation resolve endpoint,
	 *                                  {@code null} if not specified.
	 */
	public void setFederationResolveEndpointURI(final URI federationResolveEndpoint) {
		this.federationResolveEndpoint = federationResolveEndpoint;
	}
	
	
	/**
	 * Gets the federation trust mark status endpoint.
	 *
	 * @return The federation trust mark status endpoint, {@code null} if
	 *         not specified.
	 */
	public URI getFederationTrustMarkStatusEndpointURI() {
		return federationTrustMarkStatusEndpoint;
	}
	
	
	/**
	 * Sets the federation trust mark status endpoint.
	 *
	 * @param federationTrustMarkStatusEndpoint The federation trust mark
	 *                                          status endpoint,
	 *                                          {@code null} if not
	 *                                          specified.
	 */
	public void setFederationTrustMarkStatusEndpointURI(final URI federationTrustMarkStatusEndpoint) {
		this.federationTrustMarkStatusEndpoint = federationTrustMarkStatusEndpoint;
	}
	
	
	/**
	 * Gets the organisation name. Corresponds to the
	 * {@code organization_name} metadata field.
	 *
	 * @return The organisation name, {@code null} if not specified.
	 */
	public String getOrganizationName() {
		return organizationName;
	}
	
	
	/**
	 * Sets the organisation name. Corresponds to the
	 * {@code organization_name} metadata field.
	 *
	 * @param organizationName The organisation name, {@code null} if not
	 *                         specified.
	 */
	public void setOrganizationName(final String organizationName) {
		this.organizationName = organizationName;
	}
	
	
	/**
	 * Gets the entity contacts. Corresponds to the {@code contacts}
	 * metadata field.
	 *
	 * @return The contacts, such as names, e-mail addresses and phone
	 *         numbers, {@code null} if not specified.
	 */
	public List<String> getContacts() {
		return contacts;
	}
	
	
	/**
	 * Sets the entity contacts. Corresponds to the {@code contacts}
	 * metadata field.
	 *
	 * @param contacts The contacts, such as names, e-mail addresses and
	 *                 phone numbers, {@code null} if not specified.
	 */
	public void setContacts(final List<String> contacts) {
		this.contacts = contacts;
	}
	
	
	/**
	 * Gets the logo URI. Corresponds to the {@code logo_uri} metadata
	 * field.
	 *
	 * @return The logo URI, {@code null} if not specified.
	 */
	public URI getLogoURI() {
		return logoURI;
	}
	
	
	/**
	 * Sets the logo URI. Corresponds to the {@code logo_uri} metadata
	 * field.
	 *
	 * @param logoURI The logo URI, {@code null} if not specified.
	 */
	public void setLogoURI(final URI logoURI) {
		this.logoURI = logoURI;
	}
	
	
	/**
	 * Gets the conditions and policies documentation URI. Corresponds to
	 * the {@code policy_uri} metadata field.
	 *
	 * @return The policy URI, {@code null} if not specified.
	 */
	public URI getPolicyURI() {
		return policyURI;
	}
	
	
	/**
	 * Sets the conditions and policies documentation URI. Corresponds to
	 * the {@code policy_uri} metadata field.
	 *
	 * @param policyURI The policy URI, {@code null} if not specified.
	 */
	public void setPolicyURI(final URI policyURI) {
		this.policyURI = policyURI;
	}
	
	
	/**
	 * Gets the homepage URI. Corresponds to the {@code homepage_uri}
	 * metadata field.
	 *
	 * @return The homepage URI, {@code null} if not specified.
	 */
	public URI getHomepageURI() {
		return homepageURI;
	}
	
	
	/**
	 * Sets the homepage URI. Corresponds to the {@code homepage_uri}
	 * metadata field.
	 *
	 * @param homepageURI The homepage URI, {@code null} if not specified.
	 */
	public void setHomepageURI(final URI homepageURI) {
		this.homepageURI = homepageURI;
	}
	
	
	/**
	 * Returns a JSON object representation of this federation entity
	 * metadata.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "federation_fetch_endpoint"             : "https://example.com/federation_fetch",
	 *   "federation_list_endpoint"              : "https://example.com/federation_list",
	 *   "federation_trust_mark_status_endpoint" : "https://example.com/federation_status",
	 *   "name"                                  : "The example cooperation",
	 *   "homepage_uri"                          : "https://www.example.com"
	 * }
	 * </pre>
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		
		JSONObject o = new JSONObject();
		if (getFederationFetchEndpointURI() != null) {
			o.put("federation_fetch_endpoint", getFederationFetchEndpointURI().toString());
		}
		if (getFederationListEndpointURI() != null) {
			o.put("federation_list_endpoint", getFederationListEndpointURI().toString());
		}
		if (getFederationResolveEndpointURI() != null) {
			o.put("federation_resolve_endpoint", getFederationResolveEndpointURI().toString());
		}
		if (getFederationTrustMarkStatusEndpointURI() != null) {
			o.put("federation_trust_mark_status_endpoint", getFederationTrustMarkStatusEndpointURI().toString());
		}
		if (getOrganizationName() != null) {
			o.put("organization_name", getOrganizationName());
		}
		if (getContacts() != null) {
			o.put("contacts", getContacts());
		}
		if (getLogoURI() != null) {
			o.put("logo_uri", getLogoURI().toString());
		}
		if (getPolicyURI() != null) {
			o.put("policy_uri", getPolicyURI().toString());
		}
		if (getHomepageURI() != null) {
			o.put("homepage_uri", getHomepageURI().toString());
		}
		return o;
	}
	
	
	/**
	 * Parses a federation entity metadata from the specified a JSON
	 * object.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "federation_fetch_endpoint" : "https://example.com/federation_fetch",
	 *   "federation_list_endpoint" : "https://example.com/federation_list",
	 *   "name"                     : "The example cooperation",
	 *   "homepage_uri"             : "https://www.example.com"
	 * }
	 * </pre>
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The federation entity metadata.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static FederationEntityMetadata parse(final JSONObject jsonObject)
		throws ParseException {
		
		FederationEntityMetadata metadata = new FederationEntityMetadata(JSONObjectUtils.getURI(jsonObject, "federation_fetch_endpoint", null));
		metadata.setFederationListEndpointURI(JSONObjectUtils.getURI(jsonObject, "federation_list_endpoint", null));
		metadata.setFederationResolveEndpointURI(JSONObjectUtils.getURI(jsonObject, "federation_resolve_endpoint", null));
		metadata.setFederationTrustMarkStatusEndpointURI(JSONObjectUtils.getURI(jsonObject, "federation_trust_mark_status_endpoint", null));
		metadata.setOrganizationName(JSONObjectUtils.getString(jsonObject, "organization_name", null));
		metadata.setContacts(JSONObjectUtils.getStringList(jsonObject, "contacts", null));
		metadata.setLogoURI(JSONObjectUtils.getURI(jsonObject, "logo_uri", null));
		metadata.setPolicyURI(JSONObjectUtils.getURI(jsonObject, "policy_uri", null));
		metadata.setHomepageURI(JSONObjectUtils.getURI(jsonObject, "homepage_uri", null));
		return metadata;
	}
	
	
	/**
	 * Parses a federation entity metadata from the specified JSON object
	 * string.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "federation_fetch_endpoint"             : "https://example.com/federation_fetch",
	 *   "federation_list_endpoint"              : "https://example.com/federation_list",
	 *   "federation_trust_mark_status_endpoint" : "https://example.com/federation_status",
	 *   "name"                                  : "The example cooperation",
	 *   "homepage_uri"                          : "https://www.example.com"
	 * }
	 * </pre>
	 *
	 * @param json The JSON object string. Must not be {@code null}.
	 *
	 * @return The federation entity metadata.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static FederationEntityMetadata parse(final String json)
		throws ParseException {
		
		return parse(JSONObjectUtils.parse(json));
	}
}
