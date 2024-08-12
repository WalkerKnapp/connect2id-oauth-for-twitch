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


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.auth.PKITLSClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.SelfSignedTLSClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.TLSClientAuthentication;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import java.net.URI;
import java.util.Objects;


/**
 * Request object POST request.
 *
 * <p>Example request object POST request:
 *
 * <pre>
 * POST /requests HTTP/1.1
 * Host: c2id.com
 * Content-Type: application/jws
 * Content-Length: 1288
 *
 * eyJhbGciOiJSUzI1NiIsImtpZCI6ImsyYmRjIn0.ew0KICJpc3MiOiA
 * (... abbreviated for brevity ...)
 * zCYIb_NMXvtTIVc1jpspnTSD7xMbpL-2QgwUsAlMGzw
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Financial-grade API - Part 2: Read and Write API Security Profile,
 *         section 7.
 *     <li>The OAuth 2.0 Authorization Framework: JWT Secured Authorization
 *         Request (JAR) (RFC 9101).
 * </ul>
 */
@Deprecated
@Immutable
public final class RequestObjectPOSTRequest extends AbstractOptionallyAuthenticatedRequest {
	
	
	/**
	 * The request object as JWT, {@code null} for a
	 * {@link #requestJSONObject plain JSON object}.
	 */
	private final JWT requestObject;
	
	
	/**
	 * The request parameters as plain JSON object, {@code null} for
	 * {@link #requestObject JWT}.
	 */
	private final JSONObject requestJSONObject;
	
	
	/**
	 * Creates a new request object POST request.
	 *
	 * @param endpoint      The URI of the request object endpoint. May be
	 *                      {@code null} if the {@link #toHTTPRequest}
	 *                      method is not going to be used.
	 * @param requestObject The request object. Must not be {@code null}.
	 */
	public RequestObjectPOSTRequest(final URI endpoint,
					final JWT requestObject) {
		
		super(endpoint, null);
		
		this.requestObject = Objects.requireNonNull(requestObject);

		if (requestObject instanceof PlainJWT) {
			throw new IllegalArgumentException("The request object must not be an unsecured JWT (alg=none)");
		}
		
		requestJSONObject = null;
	}
	
	
	/**
	 * Creates a new request object POST request where the parameters are
	 * submitted as plain JSON object, and the client authenticates by
	 * means of mutual TLS. TLS also ensures the integrity and
	 * confidentiality of the request parameters. This method is not
	 * standard.
	 *
	 * @param endpoint          The URI of the request object endpoint. May
	 *                          be {@code null} if the
	 *                          {@link #toHTTPRequest} method is not going
	 *                          to be used.
	 * @param tlsClientAuth     The mutual TLS client authentication. Must
	 *                          not be {@code null}.
	 * @param requestJSONObject The request parameters as plain JSON
	 *                          object. Must not be {@code null}.
	 */
	public RequestObjectPOSTRequest(final URI endpoint,
					final TLSClientAuthentication tlsClientAuth,
					final JSONObject requestJSONObject) {
		
		super(endpoint, Objects.requireNonNull(tlsClientAuth));
		this.requestJSONObject = Objects.requireNonNull(requestJSONObject);
		requestObject = null;
	}
	
	
	/**
	 * Returns the request object as JWT.
	 *
	 * @return The request object as JWT, {@code null} if the request
	 *         parameters are specified as {@link #getRequestJSONObject()
	 *         plain JSON object} instead.
	 */
	public JWT getRequestObject() {
		
		return requestObject;
	}
	
	
	/**
	 * Returns the request object as plain JSON object.
	 *
	 * @return The request parameters as plain JSON object, {@code null}
	 *         if the request object is specified as a
	 *         {@link #getRequestObject() JWT}.
	 */
	public JSONObject getRequestJSONObject() {
		
		return requestJSONObject;
	}
	
	
	/**
	 * Returns the mutual TLS client authentication.
	 *
	 * @return The mutual TLS client authentication.
	 */
	public TLSClientAuthentication getTLSClientAuthentication() {
		
		return (TLSClientAuthentication) getClientAuthentication();
	}
	
	
	@Override
	public HTTPRequest toHTTPRequest() {
		
		if (getEndpointURI() == null)
			throw new SerializeException("The endpoint URI is not specified");
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, getEndpointURI());
		
		if (getRequestObject() != null) {
			httpRequest.setEntityContentType(ContentType.APPLICATION_JWT);
			httpRequest.setBody(getRequestObject().serialize());
		} else if (getRequestJSONObject() != null) {
			httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);
			httpRequest.setBody(getRequestJSONObject().toJSONString());
			getTLSClientAuthentication().applyTo(httpRequest);
		}
		
		return httpRequest;
	}
	
	
	/**
	 * Parses a request object POST request from the specified HTTP
	 * request.
	 *
	 * @param httpRequest The HTTP request. Must not be {@code null}.
	 *
	 * @return The request object POST request.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to a
	 *                        request object POST request.
	 */
	public static RequestObjectPOSTRequest parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		// Only HTTP POST accepted
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		
		if (httpRequest.getEntityContentType() == null) {
			throw new ParseException("Missing Content-Type");
		}
		
		if (
			ContentType.APPLICATION_JOSE.matches(httpRequest.getEntityContentType()) ||
			ContentType.APPLICATION_JWT.matches(httpRequest.getEntityContentType())) {
			
			// Signed or signed and encrypted request object
			
			JWT requestObject;
			try {
				requestObject = JWTParser.parse(httpRequest.getQuery());
			} catch (java.text.ParseException e) {
				throw new ParseException("Invalid request object JWT: " + e.getMessage());
			}
			
			if (requestObject instanceof PlainJWT) {
				throw new ParseException("The request object is an unsecured JWT (alg=none)");
			}
			
			return new RequestObjectPOSTRequest(httpRequest.getURI(), requestObject);
			
		} else if (ContentType.APPLICATION_JSON.matches(httpRequest.getEntityContentType())) {
			
			JSONObject jsonObject = httpRequest.getQueryAsJSONObject();
			
			if (jsonObject.get("client_id") == null) {
				throw new ParseException("Missing client_id in JSON object");
			}
			
			ClientID clientID = new ClientID(JSONObjectUtils.getString(jsonObject, "client_id"));
			
			TLSClientAuthentication tlsClientAuth;
			if (httpRequest.getClientX509Certificate() != null && httpRequest.getClientX509CertificateSubjectDN() != null &&
					httpRequest.getClientX509CertificateSubjectDN().equals(httpRequest.getClientX509CertificateRootDN())) {
				tlsClientAuth = new SelfSignedTLSClientAuthentication(clientID, httpRequest.getClientX509Certificate());
			} else if (httpRequest.getClientX509Certificate() != null) {
				tlsClientAuth = new PKITLSClientAuthentication(clientID, httpRequest.getClientX509Certificate());
			} else {
				throw new ParseException("Missing mutual TLS client authentication");
			}
			
			return new RequestObjectPOSTRequest(httpRequest.getURI(), tlsClientAuth, jsonObject);
			
		} else {
			
			throw new ParseException("Unexpected Content-Type: " + httpRequest.getEntityContentType());
		}
	}
}
