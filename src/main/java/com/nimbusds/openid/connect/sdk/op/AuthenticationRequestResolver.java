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

package com.nimbusds.openid.connect.sdk.op;


import java.io.IOException;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.JWTProcessor;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JWTClaimsSetUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;


/**
 * Resolves the final OpenID Connect authentication request by superseding its
 * parameters with those found in the optional OpenID Connect request object.
 * The request object is encoded as a JSON Web Token (JWT) and can be specified 
 * directly (inline) using the {@code request} parameter, or by URL using the 
 * {@code request_uri} parameter.
 *
 * <p>To process signed and optionally encrypted request objects a
 * {@link JWTProcessor JWT processor} for the expected JWS / JWE algorithms
 * must be provided at construction time.
 *
 * <p>To fetch OpenID Connect request objects specified by URL a
 * {@link ResourceRetriever JWT retriever} must be provided, otherwise only
 * inlined request objects can be processed.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 6.
 * </ul>
 */
@ThreadSafe
public class AuthenticationRequestResolver<C extends SecurityContext> {


	/**
	 * The JWT processor.
	 */
	private final JWTProcessor<C> jwtProcessor;


	/**
	 * Optional retriever for request objects passed by URL.
	 */
	private final ResourceRetriever jwtRetriever;


	/**
	 * Creates a new minimal OpenID Connect authentication request
	 * resolver. It will not process OpenID Connect request objects and
	 * will throw a {@link ResolveException} if the authentication request
	 * includes a {@code request} or {@code request_uri} parameter.
	 */
	public AuthenticationRequestResolver() {
		jwtProcessor = null;
		jwtRetriever = null;
	}
	
	
	/**
	 * Creates a new OpenID Connect authentication request resolver that
	 * supports OpenID Connect request objects passed by value (using the
	 * authentication {@code request} parameter). It will throw a
	 * {@link ResolveException} if the authentication request includes a
	 * {@code request_uri} parameter.
	 *
	 * @param jwtProcessor A configured JWT processor providing JWS
	 *                     validation and optional JWE decryption of the
	 *                     request objects. Must not be {@code null}.
	 */
	public AuthenticationRequestResolver(final JWTProcessor<C> jwtProcessor) {
		if (jwtProcessor == null)
			throw new IllegalArgumentException("The JWT processor must not be null");
		this.jwtProcessor = jwtProcessor;
		jwtRetriever = null;
	}
	
	
	/**
	 * Creates a new OpenID Connect request object resolver that supports
	 * OpenID Connect request objects passed by value (using the
	 * authentication {@code request} parameter) or by reference (using the
	 * authentication {@code request_uri} parameter).
	 * 
	 * @param jwtProcessor A configured JWT processor providing JWS
	 *                     validation and optional JWE decryption of the
	 *                     request objects. Must not be {@code null}.
	 * @param jwtRetriever A configured JWT retriever for OpenID Connect
	 *                     request objects passed by URI. Must not be
	 *                     {@code null}.
	 */
	public AuthenticationRequestResolver(final JWTProcessor<C> jwtProcessor,
					     final ResourceRetriever jwtRetriever) {
		if (jwtProcessor == null)
			throw new IllegalArgumentException("The JWT processor must not be null");
		this.jwtProcessor = jwtProcessor;

		if (jwtRetriever == null)
			throw new IllegalArgumentException("The JWT retriever must not be null");
		this.jwtRetriever = jwtRetriever;
	}
	
	
	/**
	 * Returns the JWT processor.
	 *
	 * @return The JWT processor, {@code null} if not specified.
	 */
	public JWTProcessor<C> getJWTProcessor() {
	
		return jwtProcessor;
	}


	/**
	 * Returns the JWT retriever.
	 *
	 * @return The JWT retriever, {@code null} if not specified.
	 */
	public ResourceRetriever getJWTRetriever() {
	
		return jwtRetriever;
	}


	/**
	 * Reformats the specified JWT claims set to a
	 * {@literal java.util.Map} instance.
	 *
	 * @param claimsSet The JWT claims set to reformat. Must not be
	 *                  {@code null}.
	 *
	 * @return The JWT claims set as an unmodifiable map of string keys / 
	 *         string values.
	 *
	 * @deprecated Use {@link JWTClaimsSetUtils#toJWTClaimsSet}.
	 */
	@Deprecated
	public static Map<String,List<String>> reformatClaims(final JWTClaimsSet claimsSet) {

		return JWTClaimsSetUtils.toMultiValuedParameters(claimsSet);
	}


	/**
	 * Resolves the specified OpenID Connect authentication request by
	 * superseding its parameters with those found in the optional OpenID
	 * Connect request object (if any).
	 *
	 * @param request         The OpenID Connect authentication request.
	 *                        Must not be {@code null}.
	 * @param securityContext Optional security context to pass to the JWT
	 *                        processor, {@code null} if not specified.
	 *
	 * @return The resolved authentication request, or the original
	 *         unmodified request if no OpenID Connect request object was
	 *         specified.
	 *
	 * @throws ResolveException If the request couldn't be resolved.
	 * @throws JOSEException    If an invalid request JWT is found.
	 */
	public AuthenticationRequest resolve(final AuthenticationRequest request,
					     final C securityContext)
		throws ResolveException, JOSEException {

		if (! request.specifiesRequestObject()) {
			// Return unmodified
			return request;
		}

		final JWT jwt;

		if (request.getRequestURI() != null) {

			// Check if request_uri is supported
			if (jwtRetriever == null || jwtProcessor == null) {
				throw new ResolveException(OAuth2Error.REQUEST_URI_NOT_SUPPORTED, request);
			}

			// Download request object
			try {
				jwt = JWTParser.parse(jwtRetriever.retrieveResource(request.getRequestURI().toURL()).getContent());
			} catch (MalformedURLException e) {
				throw new ResolveException(OAuth2Error.INVALID_REQUEST_URI.setDescription("Malformed URL"), request);
			} catch (IOException e) {
				// Most likely client problem, possible causes: bad URL, timeout, network down
				throw new ResolveException("Couldn't retrieve request_uri: " + e.getMessage(),
					"Network error, check the request_uri", // error_description for client, hide details
					request, e);
			} catch (java.text.ParseException e) {
				throw new ResolveException(OAuth2Error.INVALID_REQUEST_URI.setDescription("Invalid JWT"), request);
			}

		} else {
			// Check if request by value is supported
			if (jwtProcessor == null) {
				throw new ResolveException(OAuth2Error.REQUEST_NOT_SUPPORTED, request);
			}

			// Request object inlined
			jwt = request.getRequestObject();
		}

		final JWTClaimsSet jwtClaims;

		try {
			jwtClaims = jwtProcessor.process(jwt, securityContext);
		} catch (BadJOSEException e) {
			throw new ResolveException("Invalid request object: " + e.getMessage(),
				"Bad JWT / signature / HMAC / encryption", // error_description for client, hide details
				request, e);
		}

		Map<String,List<String>> finalParams = new HashMap<>();
		finalParams.putAll(request.toParameters());
		finalParams.putAll(JWTClaimsSetUtils.toMultiValuedParameters(jwtClaims)); // Merge params from request object
		finalParams.remove("request"); // make sure request object is deleted
		finalParams.remove("request_uri"); // make sure request_uri is deleted

		// Create new updated OpenID auth request
		try {
			return AuthenticationRequest.parse(request.getEndpointURI(), finalParams);
		} catch (ParseException e) {
			// E.g. missing OIDC required redirect_uri
			throw new ResolveException("Couldn't create final OpenID authentication request: " + e.getMessage(),
				"Invalid request object parameter(s): " + e.getMessage(), // error_description for client
				request, e);
		}
	}
}
