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


import java.net.URI;


/**
 * The base abstract class for requests.
 */
public abstract class AbstractRequest implements Request {
	
	
	/**
	 * The request endpoint.
	 */
	private final URI endpoint;
	
	
	/**
	 * Creates a new base abstract request.
	 *
	 * @param endpoint The URI of the endpoint. May be {@code null} if the
	 *                 {@link #toHTTPRequest} method is not going to be
	 *                 used.
	 */
	protected AbstractRequest(final URI endpoint) {
		this.endpoint = endpoint;
	}
	
	
	@Override
	public URI getEndpointURI() {
		return endpoint;
	}
}
