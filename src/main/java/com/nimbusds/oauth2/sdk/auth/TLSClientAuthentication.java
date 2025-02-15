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
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.URLUtils;

import javax.net.ssl.SSLSocketFactory;
import java.security.cert.X509Certificate;
import java.util.*;


/**
 * The base abstract class for mutual TLS client authentication at the Token
 * endpoint.
 */
public abstract class TLSClientAuthentication extends ClientAuthentication {
	
	
	/**
	 * The validated client X.509 certificate from the received HTTPS
	 * request, {@code null} for an outgoing HTTPS request.
	 */
	protected final X509Certificate certificate;
	
	
	/**
	 * The SSL socket factory for an outgoing HTTPS request, {@code null}
	 * to use the default one.
	 */
	private final SSLSocketFactory sslSocketFactory;
	
	
	/**
	 * Creates a new abstract mutual TLS client authentication. This
	 * constructor is intended for an outgoing token request.
	 *
	 * @param method           The client authentication method. Must not
	 *                         be {@code null}.
	 * @param clientID         The client identifier. Must not be
	 *                         {@code null}.
	 * @param sslSocketFactory The SSL socket factory to use for the
	 *                         outgoing HTTPS request and to present the
	 *                         client certificate(s), {@code null} to use
	 *                         the default one.
	 */
	protected TLSClientAuthentication(final ClientAuthenticationMethod method,
					  final ClientID clientID,
					  final SSLSocketFactory sslSocketFactory) {
		
		super(method, clientID);
		this.sslSocketFactory = sslSocketFactory;
		certificate = null;
	}
	
	
	/**
	 * Creates a new abstract mutual TLS client authentication. This
	 * constructor is intended for a received token request.
	 *
	 * @param method      The client authentication method. Must not be
	 *                    {@code null}.
	 * @param clientID    The client identifier. Must not be {@code null}.
	 * @param certificate The validated client X.509 certificate from the
	 *                    received HTTPS request. Should not be
	 *                    {@code null}.
	 */
	protected TLSClientAuthentication(final ClientAuthenticationMethod method,
					  final ClientID clientID,
					  final X509Certificate certificate) {
		super(method, clientID);
		sslSocketFactory = null;
		this.certificate = certificate;
	}
	
	
	/**
	 * Returns the SSL socket factory to use for an outgoing HTTPS request
	 * and to present the client certificate(s).
	 *
	 * @return The SSL socket factory, {@code null} to use the default one.
	 */
	public SSLSocketFactory getSSLSocketFactory() {
		
		return sslSocketFactory;
	}
	
	
	/**
	 * The validated client X.509 certificate from the received HTTPS
	 * request.
	 *
	 * @return The validated client X.509 certificate from the received
	 *         HTTPS request, {@code null} for an outgoing HTTPS request.
	 */
	public X509Certificate getClientX509Certificate() {
		
		return certificate;
	}
	
	
	@Override
	public Set<String> getFormParameterNames() {
		
		return Collections.singleton("client_id");
	}
	
	
	@Override
	public void applyTo(final HTTPRequest httpRequest) {
		
		if (httpRequest.getMethod() != HTTPRequest.Method.POST)
			throw new SerializeException("The HTTP request method must be POST");
		
		ContentType ct = httpRequest.getEntityContentType();
		
		if (ct == null)
			throw new SerializeException("Missing HTTP Content-Type header");
		
		if (ct.matches(ContentType.APPLICATION_JSON)) {
			
			// Possibly request object POST request, nothing to set
			
		} else if (ct.matches(ContentType.APPLICATION_URLENCODED)) {
			
			// Token or similar request
			Map<String, List<String>> params;
			try {
				params = new LinkedHashMap<>(httpRequest.getBodyAsFormParameters());
			} catch (ParseException e) {
				throw new SerializeException(e.getMessage(), e);
			}
			params.put("client_id", Collections.singletonList(getClientID().getValue()));
			httpRequest.setBody(URLUtils.serializeParameters(params));

		} else {
			throw new SerializeException("The HTTP Content-Type header must be " + ContentType.APPLICATION_URLENCODED);
		}
		
		// If set for an outgoing request
		httpRequest.setSSLSocketFactory(sslSocketFactory);
	}
}
