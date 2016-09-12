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

package com.nimbusds.oauth2.sdk.jose.jwk;


import java.io.IOException;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.http.DefaultResourceRetriever;
import com.nimbusds.oauth2.sdk.http.Resource;
import com.nimbusds.oauth2.sdk.http.RestrictedResourceRetriever;
import com.nimbusds.oauth2.sdk.id.Identifier;
import net.jcip.annotations.ThreadSafe;


/**
 * Remote JSON Web Key (JWK) set. Intended for a JWK set specified by URL
 * reference. The retrieved JWK set is cached.
 */
@ThreadSafe
@Deprecated
public class RemoteJWKSet extends AbstractJWKSource {


	/**
	 * The default HTTP connect timeout for JWK set retrieval, in
	 * milliseconds. Set to 250 milliseconds.
	 */
	public static final int DEFAULT_HTTP_CONNECT_TIMEOUT = 250;


	/**
	 * The default HTTP read timeout for JWK set retrieval, in
	 * milliseconds. Set to 250 milliseconds.
	 */
	public static final int DEFAULT_HTTP_READ_TIMEOUT = 250;


	/**
	 * The default HTTP entity size limit for JWK set retrieval, in bytes.
	 * Set to 50 KBytes.
	 */
	public static final int DEFAULT_HTTP_SIZE_LIMIT = 50 * 1024;


	/**
	 * The JWK set URL.
	 */
	private final URL jwkSetURL;
	

	/**
	 * The cached JWK set.
	 */
	private final AtomicReference<JWKSet> cachedJWKSet = new AtomicReference<>();


	/**
	 * The JWK set retriever.
	 */
	private final RestrictedResourceRetriever jwkSetRetriever;


	/**
	 * Creates a new remote JWK set.
	 *
	 * @param id                The JWK set owner identifier. Typically the
	 *                          OAuth 2.0 server issuer ID, or client ID.
	 *                          Must not be {@code null}.
	 * @param jwkSetURL         The JWK set URL. Must not be {@code null}.
	 * @param resourceRetriever The HTTP resource retriever to use,
	 *                          {@code null} to use the
	 *                          {@link DefaultResourceRetriever default
	 *                          one}.
	 */
	public RemoteJWKSet(final Identifier id,
			    final URL jwkSetURL,
			    final RestrictedResourceRetriever resourceRetriever) {
		super(id);

		if (jwkSetURL == null) {
			throw new IllegalArgumentException("The JWK set URL must not be null");
		}
		this.jwkSetURL = jwkSetURL;

		if (resourceRetriever != null) {
			jwkSetRetriever = resourceRetriever;
		} else {
			jwkSetRetriever = new DefaultResourceRetriever(DEFAULT_HTTP_CONNECT_TIMEOUT, DEFAULT_HTTP_READ_TIMEOUT, DEFAULT_HTTP_SIZE_LIMIT);
		}

		Thread t = new Thread() {
			public void run() {
				updateJWKSetFromURL();
			}
		};
		t.setName("initial-jwk-set-retriever["+ jwkSetURL +"]");
		t.start();
	}


	/**
	 * Updates the cached JWK set from the configured URL.
	 *
	 * @return The updated JWK set, {@code null} if retrieval failed.
	 */
	private JWKSet updateJWKSetFromURL() {
		JWKSet jwkSet;
		try {
			Resource res = jwkSetRetriever.retrieveResource(jwkSetURL);
			jwkSet = JWKSet.parse(res.getContent());
		} catch (IOException | java.text.ParseException e) {
			return null;
		}
		cachedJWKSet.set(jwkSet);
		return jwkSet;
	}


	/**
	 * Returns the JWK set URL.
	 *
	 * @return The JWK set URL.
	 */
	public URL getJWKSetURL() {
		return jwkSetURL;
	}


	/**
	 * Returns the HTTP resource retriever.
	 *
	 * @return The HTTP resource retriever.
	 */
	public RestrictedResourceRetriever getResourceRetriever() {

		return jwkSetRetriever;
	}


	/**
	 * Returns the cached JWK set.
	 *
	 * @return The cached JWK set, {@code null} if none.
	 */
	public JWKSet getJWKSet() {
		JWKSet jwkSet = cachedJWKSet.get();
		if (jwkSet != null) {
			return jwkSet;
		}
		return updateJWKSetFromURL();
	}


	/**
	 * Returns the first specified key ID (kid) for a JWK matcher.
	 *
	 * @param jwkMatcher The JWK matcher. Must not be {@code null}.
	 *
	 * @return The first key ID, {@code null} if none.
	 */
	protected static String getFirstSpecifiedKeyID(final JWKMatcher jwkMatcher) {

		Set<String> keyIDs = jwkMatcher.getKeyIDs();

		if (keyIDs == null || keyIDs.isEmpty()) {
			return null;
		}

		for (String id: keyIDs) {
			if (id != null) {
				return id;
			}
		}
		return null; // No kid in matcher
	}


	@Override
	public List<JWK> get(final Identifier id, final JWKSelector jwkSelector) {
		if (! getOwner().equals(id)) {
			return Collections.emptyList();
		}

		// Get the JWK set, may necessitate a cache update
		JWKSet jwkSet = getJWKSet();
		if (jwkSet == null) {
			// Retrieval has failed
			return Collections.emptyList();
		}
		List<JWK> matches = jwkSelector.select(jwkSet);

		if (! matches.isEmpty()) {
			// Success
			return matches;
		}

		// Refresh the JWK set if the sought key ID is not in the cached JWK set
		String soughtKeyID = getFirstSpecifiedKeyID(jwkSelector.getMatcher());
		if (soughtKeyID == null) {
			// No key ID specified, return no matches
			return matches;
		}
		if (jwkSet.getKeyByKeyId(soughtKeyID) != null) {
			// The key ID exists in the cached JWK set, matching
			// failed for some other reason, return no matches
			return matches;
		}
		// Make new HTTP GET to the JWK set URL
		jwkSet = updateJWKSetFromURL();
		if (jwkSet == null) {
			// Retrieval has failed
			return null;
		}
		// Repeat select, return final result (success or no matches)
		return jwkSelector.select(jwkSet);
	}
}
