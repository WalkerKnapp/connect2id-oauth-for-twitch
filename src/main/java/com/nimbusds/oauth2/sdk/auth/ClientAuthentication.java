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


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;

import javax.security.auth.x500.X500Principal;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;


/**
 * Base abstract class for client authentication at the Token endpoint.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749)
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523)
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (RFC 8705)
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
	
		this.method = Objects.requireNonNull(method);
		this.clientID = Objects.requireNonNull(clientID);
	}
	
	
	/**
	 * Returns the client authentication method.
	 *
	 * @return The client authentication method.
	 */
	public ClientAuthenticationMethod getMethod() {
	
		return method;
	}


	/**
	 * Returns the client identifier.
	 *
	 * @return The client identifier.
	 */
	public ClientID getClientID() {

		return clientID;
	}
	
	
	/**
	 * Returns the name of the form parameters, if such are used by the
	 * authentication method.
	 *
	 * @return The form parameter names, empty set if none.
	 */
	public abstract Set<String> getFormParameterNames();
	
	
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
		    ! httpRequest.getEntityContentType().matches(ContentType.APPLICATION_URLENCODED)) {
			return null; // no auth
		}
		
		Map<String,List<String>> params = httpRequest.getBodyAsFormParameters();
		
		// We have client secret post
		if (StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, "client_id")) && StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, "client_secret"))) {
			return ClientSecretPost.parse(httpRequest);
		}
		
		// Do we have a signed JWT assertion?
		if (StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, "client_assertion")) && StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, "client_assertion_type"))) {
			return JWTAuthentication.parse(httpRequest);
		}
		
		// Client TLS?
		if (httpRequest.getClientX509Certificate() != null && StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, "client_id"))) {
			
			// Check for self-issued first (not for self-signed (too expensive in terms of CPU time)
			
			X500Principal issuer = httpRequest.getClientX509Certificate().getIssuerX500Principal();
			X500Principal subject = httpRequest.getClientX509Certificate().getSubjectX500Principal();
			
			if (issuer != null && issuer.equals(subject)) {
				// Additional checks
				if (httpRequest.getClientX509CertificateRootDN() != null) {
					// If TLS proxy set issuer header it must match the certificate's
					if (! httpRequest.getClientX509CertificateRootDN().equalsIgnoreCase(issuer.toString())) {
						throw new ParseException("Client X.509 certificate issuer DN doesn't match HTTP request metadata");
					}
				}
				if (httpRequest.getClientX509CertificateSubjectDN() != null) {
					// If TLS proxy set subject header it must match the certificate's
					if (! httpRequest.getClientX509CertificateSubjectDN().equalsIgnoreCase(subject.toString())) {
						throw new ParseException("Client X.509 certificate subject DN doesn't match HTTP request metadata");
					}
				}
				
				// Self-issued (assumes self-signed)
				return SelfSignedTLSClientAuthentication.parse(httpRequest);
			} else {
				// PKI bound
				return PKITLSClientAuthentication.parse(httpRequest);
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
