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

package com.nimbusds.openid.connect.sdk.id;


import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ciba.BackChannelTokenDeliveryMode;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import java.io.IOException;
import java.net.URI;
import java.util.*;


/**
 * Sector identifier URI validator.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 *     <li>OpenID Connect Dynamic Client Registration 1.0
 *     <li>OpenID Connect CIBA Flow - Core 1.0
 * </ul>
 */
public class SectorIDURIValidator {
	

	/**
	 * The URL resource retriever.
	 */
	private final ResourceRetriever resourceRetriever;


	/**
	 * Creates a new sector ID URI validator.
	 *
	 * @param resourceRetriever The URL resource retriever to use. Must not
	 *                          be {@code null}.
	 */
	public SectorIDURIValidator(final ResourceRetriever resourceRetriever) {
		this.resourceRetriever = Objects.requireNonNull(resourceRetriever);
	}


	/**
	 * Returns the URL resource retriever.
	 *
	 * @return The resource retriever.
	 */
	public ResourceRetriever getResourceRetriever() {
		return resourceRetriever;
	}


	/**
	 * Validates the specified URIs for being present in a sector ID
	 * document.
	 *
	 * @param sectorURI      The sector ID URI. Must not be {@code null}.
	 * @param urisToValidate The client URIs to check for being present in
	 *                       the sector ID JSON document. Must not be
	 *                       {@code null}.
	 *
	 * @throws GeneralException If validation failed.
	 */
	public void validate(final URI sectorURI, final Set<URI> urisToValidate)
		throws GeneralException {

		Resource resource;
		try {
			resource = resourceRetriever.retrieveResource(sectorURI.toURL());
		} catch (IOException e) {
			throw new GeneralException("Couldn't retrieve the sector ID JSON document: " + e.getMessage(), e);
		}

		if (resource.getContentType() == null) {
			throw new GeneralException("Couldn't validate sector ID: Missing HTTP Content-Type");
		}

		if (! resource.getContentType().toLowerCase().startsWith("application/json")) {
			throw new GeneralException("Couldn't validate sector ID: HTTP Content-Type must be application/json, found " + resource.getContentType());
		}

		List<URI> uriList = JSONArrayUtils.toURIList(JSONArrayUtils.parse(resource.getContent()));

		for (URI uri: urisToValidate) {

			if (! uriList.contains(uri)) {
				throw new GeneralException("Sector ID validation failed: URI " + uri + " not present at sector ID URI " + sectorURI);
			}
		}
	}
	
	
	/**
	 * Collects the client URIs for sector ID validation.
	 *
	 * <p>For the OAuth 2.0 authorisation code and implicit grants:
	 * {@code redirect_uris}.
	 *
	 * <p>For the OAuth 2.0 CIBA grant: {@code jwks_uri} for the poll and
	 * ping token delivery modes,
	 * {@code backchannel_client_notification_endpoint} for the push mode.
	 *
	 * @param clientMetadata The client metadata. Must not be {@code null}.
	 *
	 * @return The URIs for sector ID validation, empty set if none.
	 */
	public static Set<URI> collectURIsForValidation(final OIDCClientMetadata clientMetadata) {
		
		Set<URI> uris = new HashSet<>();
		
		// Grant types code, implicit
		if (clientMetadata.getRedirectionURIs() != null) {
			uris.addAll(clientMetadata.getRedirectionURIs());
		}
		
		// Grant type CIBA
		if (BackChannelTokenDeliveryMode.POLL.equals(clientMetadata.getBackChannelTokenDeliveryMode()) ||
		    BackChannelTokenDeliveryMode.PING.equals(clientMetadata.getBackChannelTokenDeliveryMode())) {
		
			if (clientMetadata.getJWKSetURI() != null) {
				uris.add(clientMetadata.getJWKSetURI());
			}
		}
		if (BackChannelTokenDeliveryMode.PUSH.equals(clientMetadata.getBackChannelTokenDeliveryMode())) {
			
			if (clientMetadata.getBackChannelClientNotificationEndpoint() != null) {
				uris.add(clientMetadata.getBackChannelClientNotificationEndpoint());
			}
		}
		
		return Collections.unmodifiableSet(uris);
	}
}
