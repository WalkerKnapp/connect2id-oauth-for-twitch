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

package com.nimbusds.oauth2.sdk.auth;


import java.security.cert.X509Certificate;
import java.util.Map;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils;
import org.apache.commons.lang3.StringUtils;


/**
 * Base abstract class for client authentication at the Token endpoint.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 2.3.
 *     <li>Mutual TLS Profile for OAuth 2.0 (draft-ietf-oauth-mtls-03), section
 *         2.1.
 * </ul>
 */
public abstract class ClientAuthentication {
	
	
	/**
	 * The client authentication method.
	 */
	private final ClientAuthenticationMethod method;


	/**
	 * The client ID.
	 */
	private final ClientID clientID;
	
	
	/**
	 * Creates a new abstract client authentication.
	 *
	 * @param method   The client authentication method. Must not be
	 *                 {@code null}.
	 * @param clientID The client identifier. Must not be {@code null}.
	 */
	protected ClientAuthentication(final ClientAuthenticationMethod method, final ClientID clientID) {
	
		if (method == null)
			throw new IllegalArgumentException("The client authentication method must not be null");
		
		this.method = method;


		if (clientID == null)
			throw new IllegalArgumentException("The client identifier must not be null");

		this.clientID = clientID;
	}
	
	
	/**
	 * Gets the client authentication method.
	 *
	 * @return The client authentication method.
	 */
	public ClientAuthenticationMethod getMethod() {
	
		return method;
	}


	/**
	 * Gets the client identifier.
	 *
	 * @return The client identifier.
	 */
	public ClientID getClientID() {

		return clientID;
	}
	
	
	/**
	 * Parses the specified HTTP request for a supported client 
	 * authentication (see {@link ClientAuthenticationMethod}). This method
	 * is intended to aid parsing of authenticated 
	 * {@link com.nimbusds.oauth2.sdk.TokenRequest}s.
	 *
	 * @param httpRequest The HTTP request to parse. Must not be 
	 *                    {@code null}.
	 *
	 * @return The client authentication method, {@code null} if none or 
	 *         the method is not supported.
	 *
	 * @throws ParseException If the inferred client authentication 
	 *                        couldn't be parsed.
	 */
	public static ClientAuthentication parse(final HTTPRequest httpRequest)
		throws ParseException {
	
		// Check for client secret basic
		if (httpRequest.getAuthorization() != null && 
		    httpRequest.getAuthorization().startsWith("Basic")) {
			
			return ClientSecretBasic.parse(httpRequest);
		}
		
		// The other methods require HTTP POST with URL-encoded params
		if (httpRequest.getMethod() != HTTPRequest.Method.POST &&
		    ! httpRequest.getContentType().match(CommonContentTypes.APPLICATION_URLENCODED)) {
			return null; // no auth
		}
		
		Map<String,String> params = httpRequest.getQueryParameters();
		
		// We have client secret post
		if (StringUtils.isNotBlank(params.get("client_id")) && StringUtils.isNotBlank(params.get("client_secret"))) {
			return ClientSecretPost.parse(httpRequest);
		}
		
		// Do we have a signed JWT assertion?
		if (StringUtils.isNotBlank(params.get("client_assertion")) && StringUtils.isNotBlank(params.get("client_assertion_type"))) {
			return JWTAuthentication.parse(httpRequest);
		}
		
		// Client TLS?
		if (StringUtils.isNotBlank(params.get("client_id")) && httpRequest.getClientX509Certificate() != null) {
			
			X509Certificate clientCert = httpRequest.getClientX509Certificate();
			
			if (X509CertificateUtils.hasMatchingIssuerAndSubject(clientCert)) {
				// Don't do expensive public key / signature check,
				// assume self-signed certificate if issuer and subject DNs match
				return PublicKeyTLSClientAuthentication.parse(httpRequest);
			} else {
				// CA-issued certificate
				return TLSClientAuthentication.parse(httpRequest);
			}
		}
		
		return null; // no auth
	}
	
	
	/**
	 * Applies the authentication to the specified HTTP request by setting 
	 * its Authorization header and/or POST entity-body parameters 
	 * (according to the implemented client authentication method).
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 */
	public abstract void applyTo(final HTTPRequest httpRequest);
}
