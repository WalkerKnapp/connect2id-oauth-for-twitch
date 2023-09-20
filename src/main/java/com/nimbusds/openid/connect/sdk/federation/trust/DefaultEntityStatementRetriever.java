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

package com.nimbusds.openid.connect.sdk.federation.trust;


import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.WellKnownPathComposeStrategy;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.openid.connect.sdk.federation.api.FetchEntityStatementRequest;
import com.nimbusds.openid.connect.sdk.federation.api.FetchEntityStatementResponse;
import com.nimbusds.openid.connect.sdk.federation.config.FederationEntityConfigurationRequest;
import com.nimbusds.openid.connect.sdk.federation.config.FederationEntityConfigurationResponse;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;

import java.io.IOException;
import java.net.URI;
import java.util.LinkedList;
import java.util.List;


/**
 * The default entity statement retriever for resolving trust chains. Supports
 * the {@link WellKnownPathComposeStrategy#POSTFIX postfix} and
 * {@link WellKnownPathComposeStrategy#INFIX infix} well-known path composition
 * strategies.
 */
public class DefaultEntityStatementRetriever implements EntityStatementRetriever {
	
	
	/**
	 * The HTTP connect timeout in milliseconds.
	 */
	private final int httpConnectTimeoutMs;
	
	
	/**
	 * The HTTP read timeout in milliseconds.
	 */
	private final int httpReadTimeoutMs;
	
	
	/**
	 * The default HTTP connect timeout in milliseconds.
	 */
	public static final int DEFAULT_HTTP_CONNECT_TIMEOUT_MS = 1000;
	
	
	/**
	 * The default HTTP read timeout in milliseconds.
	 */
	public static final int DEFAULT_HTTP_READ_TIMEOUT_MS = 1000;
	
	
	/**
	 * Running list of the recorded HTTP requests.
	 */
	private final List<URI> recordedRequests = new LinkedList<>();
	
	
	/**
	 * Creates a new entity statement retriever using the default HTTP
	 * timeout settings.
	 */
	public DefaultEntityStatementRetriever() {
		this(DEFAULT_HTTP_CONNECT_TIMEOUT_MS, DEFAULT_HTTP_READ_TIMEOUT_MS);
	}
	
	
	/**
	 * Creates a new entity statement retriever.
	 *
	 * @param httpConnectTimeoutMs The HTTP connect timeout in
	 *                             milliseconds, zero means timeout
	 *                             determined by the underlying HTTP client.
	 * @param httpReadTimeoutMs    The HTTP read timeout in milliseconds,
	 *                             zero means timeout determined by the
	 *                             underlying HTTP client.
	 */
	public DefaultEntityStatementRetriever(final int httpConnectTimeoutMs,
					       final int httpReadTimeoutMs) {
		this.httpConnectTimeoutMs = httpConnectTimeoutMs;
		this.httpReadTimeoutMs = httpReadTimeoutMs;
	}
	
	
	/**
	 * Returns the configured HTTP connect timeout.
	 *
	 * @return The configured HTTP connect timeout in milliseconds, zero
	 *         means timeout determined by the underlying HTTP client.
	 */
	public int getHTTPConnectTimeout() {
		return httpConnectTimeoutMs;
	}
	
	
	/**
	 * Returns the configured HTTP read timeout.
	 *
	 * @return The configured HTTP read timeout in milliseconds, zero
	 *         means timeout determined by the underlying HTTP client.
	 */
	public int getHTTPReadTimeout() {
		return httpReadTimeoutMs;
	}
	
	
	void applyTimeouts(final HTTPRequest httpRequest) {
		httpRequest.setConnectTimeout(httpConnectTimeoutMs);
		httpRequest.setReadTimeout(httpReadTimeoutMs);
	}
	
	
	@Override
	public EntityStatement fetchEntityConfiguration(final EntityID target)
		throws ResolveException {
		
		FederationEntityConfigurationRequest request = new FederationEntityConfigurationRequest(target);
		HTTPRequest httpRequest = request.toHTTPRequest();
		applyTimeouts(httpRequest);
		
		record(httpRequest);
		
		HTTPResponse httpResponse;
		try {
			httpResponse = httpRequest.send();
		} catch (IOException e) {
			throw new ResolveException("Couldn't retrieve entity configuration for " + httpRequest.getURL() + ": " + e.getMessage(), e);
		}
		
		if (StringUtils.isNotBlank(target.toURI().getPath()) && HTTPResponse.SC_NOT_FOUND == httpResponse.getStatusCode()) {
			// We have a path in the entity ID URL, try infix strategy
			request = new FederationEntityConfigurationRequest(target, WellKnownPathComposeStrategy.INFIX);
			httpRequest = request.toHTTPRequest();
			applyTimeouts(httpRequest);
			
			record(httpRequest);
			
			try {
				httpResponse = httpRequest.send();
			} catch (IOException e) {
				throw new ResolveException("Couldn't retrieve entity configuration for " + httpRequest.getURL() + ": " + e.getMessage(), e);
			}
		}
		
		FederationEntityConfigurationResponse response;
		try {
			response = FederationEntityConfigurationResponse.parse(httpResponse);
		} catch (ParseException e) {
			throw new ResolveException("Error parsing entity configuration response from " + httpRequest.getURL() + ": " + e.getMessage(), e);
		}
		
		if (! response.indicatesSuccess()) {
			ErrorObject errorObject = response.toErrorResponse().getErrorObject();
			throw new ResolveException("Entity configuration error response from " + httpRequest.getURL() + ": " +
				errorObject.getHTTPStatusCode() +
				(errorObject.getCode() != null ? " " + errorObject.getCode() : ""),
				errorObject);
		}
		
		return response.toSuccessResponse().getEntityStatement();
	}
	
	
	@Override
	public EntityStatement fetchEntityStatement(final URI federationAPIEndpoint, final EntityID issuer, final EntityID subject)
		throws ResolveException {
		
		FetchEntityStatementRequest request = new FetchEntityStatementRequest(federationAPIEndpoint, issuer, subject);
		HTTPRequest httpRequest = request.toHTTPRequest();
		applyTimeouts(httpRequest);
		
		record(httpRequest);
		
		HTTPResponse httpResponse;
		try {
			httpResponse = httpRequest.send();
		} catch (IOException e) {
			throw new ResolveException("Couldn't fetch entity statement from " + issuer + " at " + federationAPIEndpoint + ": " + e.getMessage(), e);
		}
		
		FetchEntityStatementResponse response;
		try {
			response = FetchEntityStatementResponse.parse(httpResponse);
		} catch (ParseException e) {
			throw new ResolveException("Error parsing entity statement response from " + issuer + " at " + federationAPIEndpoint + ": " + e.getMessage(), e);
		}
		
		if (! response.indicatesSuccess()) {
			ErrorObject errorObject = response.toErrorResponse().getErrorObject();
			throw new ResolveException("Entity statement error response from " + issuer + " at " + federationAPIEndpoint + ": " +
				errorObject.getHTTPStatusCode() +
				(errorObject.getCode() != null ? " " + errorObject.getCode() : ""),
				errorObject);
		}
		
		return response.toSuccessResponse().getEntityStatement();
	}
	
	
	private void record(final HTTPRequest httpRequest) {
		
		recordedRequests.add(httpRequest.getURI());
	}
	
	
	/**
	 * Returns the running list of the recorded HTTP requests.
	 *
	 * @return The HTTP request URIs (with query parameters), empty if
	 *         none.
	 */
	public List<URI> getRecordedRequests() {
		return recordedRequests;
	}
}
