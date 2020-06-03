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

package com.nimbusds.oauth2.sdk;


import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.URIUtils;


/**
 * The base abstract class for OAuth 2.0 and OpenID Connect configuration
 * requests.
 */
public abstract class AbstractConfigurationRequest extends AbstractRequest {
	
	
	/**
	 * Creates a new base abstract request.
	 *
	 * @param baseURI       The base URI. Must not be {@code null}.
	 * @param wellKnownPath The well known path to prepend to any existing
	 *                      path component in the base URI. Must not be
	 *                      {@code null}.
	 */
	public AbstractConfigurationRequest(final URI baseURI, final String wellKnownPath) {
		
		super(URIUtils.prependPath(baseURI, wellKnownPath));
	}
	
	
	@Override
	public HTTPRequest toHTTPRequest() {
		
		URL url;
		try {
			url = getEndpointURI().toURL();
		} catch (IllegalArgumentException | MalformedURLException e) {
			throw new SerializeException(e.getMessage(), e);
		}
		
		return new HTTPRequest(HTTPRequest.Method.GET, url);
	}
}
