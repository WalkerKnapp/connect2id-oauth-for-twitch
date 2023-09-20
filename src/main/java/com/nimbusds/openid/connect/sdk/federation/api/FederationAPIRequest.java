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

package com.nimbusds.openid.connect.sdk.federation.api;


import java.net.URI;
import java.util.List;
import java.util.Map;

import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.URLUtils;


/**
 * Federation API request.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 7.
 * </ul>
 */
public abstract class FederationAPIRequest extends AbstractRequest {
	
	
	/**
	 * Creates a new federation API request.
	 *
	 * @param endpoint The federation API endpoint. Must not be
	 *                 {@code null}.
	 */
	public FederationAPIRequest(final URI endpoint) {
		super(endpoint);
	}
	
	
	/**
	 * Returns the request parameters.
	 *
	 * @return The request parameters.
	 */
	public abstract Map<String, List<String>> toParameters();
	
	
	@Override
	public HTTPRequest toHTTPRequest() {
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, getEndpointURI());
		httpRequest.appendQueryParameters(toParameters());
		return httpRequest;
	}
}
