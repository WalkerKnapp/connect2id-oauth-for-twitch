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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionFactory;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import net.jcip.annotations.Immutable;

import java.net.URI;
import java.util.*;


/**
 * Client secret JWT authentication at the Token endpoint. Implements
 * {@link ClientAuthenticationMethod#CLIENT_SECRET_JWT}.
 *
 * <p>Supported signature JSON Web Algorithms (JWAs) by this implementation:
 *
 * <ul>
 *     <li>HS256
 *     <li>HS384
 *     <li>HS512
 * </ul>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Assertion Framework for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7521).
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523).
 * </ul>
 */
@Immutable
public final class ClientSecretJWT extends JWTAuthentication {


	/**
	 * Returns the supported signature JSON Web Algorithms (JWAs).
	 *
	 * @return The supported JSON Web Algorithms (JWAs).
	 */
	public static Set<JWSAlgorithm> supportedJWAs() {
		
		return Collections.unmodifiableSet(new HashSet<>(JWSAlgorithm.Family.HMAC_SHA));
	}


	/**
	 * Creates a new client secret JWT authentication. The expiration
	 * time (exp) is set to five minutes from the current system time.
	 * Generates a default identifier (jti) for the JWT. The issued-at
	 * (iat) and not-before (nbf) claims are not set.
	 *
	 * @param clientID      The client identifier. Must not be
	 *                      {@code null}.
	 * @param endpoint      The endpoint URI where the client will submit
	 *                      the JWT authentication, for example the token
	 *                      endpoint. Must not be {@code null}.
	 * @param jwsAlgorithm  The expected HMAC algorithm (HS256, HS384 or
	 *                      HS512) for the client secret JWT assertion.
	 *                      Must be supported and not {@code null}.
	 * @param clientSecret  The client secret. Must be at least 256-bits
	 *                      long.
	 *
	 * @throws JOSEException If the client secret is too short, or HMAC
	 *                       computation failed.
	 */
	public ClientSecretJWT(final ClientID clientID,
			       final URI endpoint,
			       final JWSAlgorithm jwsAlgorithm,
			       final Secret clientSecret)
		throws JOSEException {

		this(new Issuer(clientID), clientID, endpoint, jwsAlgorithm, clientSecret);
	}


	/**
	 * Creates a new client secret JWT authentication. The expiration
	 * time (exp) is set to five minutes from the current system time.
	 * Generates a default identifier (jti) for the JWT. The issued-at
	 * (iat) and not-before (nbf) claims are not set.
	 *
	 * @param iss           The issuer. May be different from the client
	 *                      identifier. Must not be {@code null}.
	 * @param clientID      The client identifier. Must not be
	 *                      {@code null}.
	 * @param endpoint      The endpoint URI where the client will submit
	 *                      the JWT authentication, for example the token
	 *                      endpoint. Must not be {@code null}.
	 * @param jwsAlgorithm  The expected HMAC algorithm (HS256, HS384 or
	 *                      HS512) for the client secret JWT assertion.
	 *                      Must be supported and not {@code null}.
	 * @param clientSecret  The client secret. Must be at least 256-bits
	 *                      long.
	 *
	 * @throws JOSEException If the client secret is too short, or HMAC
	 *                       computation failed.
	 */
	public ClientSecretJWT(final Issuer iss,
			       final ClientID clientID,
			       final URI endpoint,
			       final JWSAlgorithm jwsAlgorithm,
			       final Secret clientSecret)
		throws JOSEException {

		this(JWTAssertionFactory.create(
			new JWTAuthenticationClaimsSet(iss, clientID, new Audience(endpoint.toString())),
			jwsAlgorithm,
			clientSecret));
	}


	/**
	 * Creates a new client secret JWT authentication.
	 *
	 * @param clientAssertion The client assertion, corresponding to the
	 *                        {@code client_assertion_parameter}, as a
	 *                        supported HMAC-protected JWT. Must be signed
	 *                        and not {@code null}.
	 */
	public ClientSecretJWT(final SignedJWT clientAssertion) {

		super(ClientAuthenticationMethod.CLIENT_SECRET_JWT, clientAssertion);

		if (! JWSAlgorithm.Family.HMAC_SHA.contains(clientAssertion.getHeader().getAlgorithm()))
			throw new IllegalArgumentException("The client assertion JWT must be HMAC-signed (HS256, HS384 or HS512)");
	}
	
	
	/**
	 * Parses the specified parameters map for a client secret JSON Web 
	 * Token (JWT) authentication. Note that the parameters must not be
	 * {@code application/x-www-form-urlencoded} encoded.
	 *
	 * @param params The parameters map to parse. The client secret JSON
	 *               Web Token (JWT) parameters must be keyed under 
	 *               "client_assertion" and "client_assertion_type". The 
	 *               map must not be {@code null}.
	 *
	 * @return The client secret JSON Web Token (JWT) authentication.
	 *
	 * @throws ParseException If the parameters map couldn't be parsed to a 
	 *                        client secret JSON Web Token (JWT) 
	 *                        authentication.
	 */
	public static ClientSecretJWT parse(final Map<String,List<String>> params)
		throws ParseException {
	
		JWTAuthentication.ensureClientAssertionType(params);
		
		SignedJWT clientAssertion = JWTAuthentication.parseClientAssertion(params);

		ClientSecretJWT clientSecretJWT;
		try {
			clientSecretJWT = new ClientSecretJWT(clientAssertion);
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage(), e);
		}

		// Check that the top level client_id matches the assertion subject + issuer
		
		ClientID clientID = JWTAuthentication.parseClientID(params);

		if (clientID != null) {

			if (! clientID.equals(clientSecretJWT.getClientID()))
				throw new ParseException("Invalid client secret JWT authentication: The client identifier doesn't match the client assertion subject");
		}

		return clientSecretJWT;
	}
	
	
	/**
	 * Parses a client secret JSON Web Token (JWT) authentication from the 
	 * specified {@code application/x-www-form-urlencoded} encoded 
	 * parameters string.
	 *
	 * @param paramsString The parameters string to parse. The client secret
	 *                     JSON Web Token (JWT) parameters must be keyed 
	 *                     under "client_assertion" and 
	 *                     "client_assertion_type". The string must not be 
	 *                     {@code null}.
	 *
	 * @return The client secret JSON Web Token (JWT) authentication.
	 *
	 * @throws ParseException If the parameters string couldn't be parsed 
	 *                        to a client secret JSON Web Token (JWT) 
	 *                        authentication.
	 */
	public static ClientSecretJWT parse(final String paramsString)
		throws ParseException {
		
		Map<String,List<String>> params = URLUtils.parseParameters(paramsString);
		
		return parse(params);
	}
	
	
	/**
	 * Parses the specified HTTP POST request for a client secret JSON Web 
	 * Token (JWT) authentication.
	 *
	 * @param httpRequest The HTTP POST request to parse. Must not be 
	 *                    {@code null} and must contain a valid 
	 *                    {@code application/x-www-form-urlencoded} encoded 
	 *                    parameters string in the entity body. The client 
	 *                    secret JSON Web Token (JWT) parameters must be 
	 *                    keyed under "client_assertion" and 
	 *                    "client_assertion_type".
	 *
	 * @return The client secret JSON Web Token (JWT) authentication.
	 *
	 * @throws ParseException If the HTTP request header couldn't be parsed
	 *                        to a client secret JSON Web Token (JWT) 
	 *                        authentication.
	 */
	public static ClientSecretJWT parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		httpRequest.ensureMethod(HTTPRequest.Method.POST);
		httpRequest.ensureEntityContentType(ContentType.APPLICATION_URLENCODED);
		
		return parse(httpRequest.getBodyAsFormParameters());
	}
}
