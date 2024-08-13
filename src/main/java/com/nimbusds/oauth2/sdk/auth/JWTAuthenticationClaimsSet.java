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


import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.assertions.jwt.JWTAssertionDetails;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.minidev.json.JSONObject;

import java.util.Date;
import java.util.List;


/**
 * JWT client authentication claims set, serialisable to a JSON object and JWT 
 * claims set.
 *
 * <p>Used for {@link ClientSecretJWT client secret JWT} and
 * {@link PrivateKeyJWT private key JWT} authentication at the Token endpoint.
 *
 * <p>Example client authentication claims set:
 *
 * <pre>
 * {
 *   "iss" : "https://client.example.com",
 *   "sub" : "https://client.example.com",
 *   "aud" : [ "https://idp.example.com/token" ],
 *   "jti" : "d396036d-c4d9-40d8-8e98-f7e8327002d9",
 *   "exp" : 1311281970,
 *   "iat" : 1311280970
 * }
 * </pre>
 *
 * <p>Example client authentication claims set where the issuer is a 3rd party:
 *
 * <pre>
 * {
 *   "iss" : "https://sts.example.com",
 *   "sub" : "https://client.example.com",
 *   "aud" : [ "https://idp.example.com/token" ],
 *   "jti" : "d396036d-c4d9-40d8-8e98-f7e8327002d9",
 *   "exp" : 1311281970,
 *   "iat" : 1311280970
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749)
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523)
 * </ul>
 */
public class JWTAuthenticationClaimsSet extends JWTAssertionDetails {


	/**
	 * Creates a new JWT client authentication claims set. The expiration
	 * time (exp) is set to 1 minute from the current system time.
	 * Generates a default identifier (jti) for the JWT. The issued-at
	 * (iat) and not-before (nbf) claims are not set.
	 *
	 * @param clientID The client identifier. Used to specify the issuer
	 *                 and the subject. Must not be {@code null}.
	 * @param aud      The audience identifier, typically the URI of the
	 *                 authorisation server's Token endpoint. Must not be
	 *                 {@code null}.
	 */
	public JWTAuthenticationClaimsSet(final ClientID clientID,
					  final Audience aud) {

		this(clientID, aud.toSingleAudienceList(), new Date(new Date().getTime() + 60_000L), null, null, new JWTID());
	}


	/**
	 * Creates a new JWT client authentication claims set. The expiration
	 * time (exp) is set to 1 minute from the current system time.
	 * Generates a default identifier (jti) for the JWT. The issued-at
	 * (iat) and not-before (nbf) claims are not set.
	 *
	 * @param iss      The issuer. May be different from the client
	 *                 identifier that is used to specify the subject. Must
	 *                 not be {@code null}.
	 * @param clientID The client identifier. Used to specify the issuer
	 *                 and the subject. Must not be {@code null}.
	 * @param aud      The audience identifier, typically the URI of the
	 *                 authorisation server's Token endpoint. Must not be
	 *                 {@code null}.
	 */
	public JWTAuthenticationClaimsSet(final Issuer iss,
					  final ClientID clientID,
					  final Audience aud) {

		this(iss, clientID, aud.toSingleAudienceList(), new Date(new Date().getTime() + 60_000L), null, null, new JWTID());
	}

	
	/**
	 * Creates a new JWT client authentication claims set.
	 *
	 * @param clientID The client identifier. Used to specify the issuer 
	 *                 and the subject. Must not be {@code null}.
	 * @param aud      The audience, typically including the URI of the
	 *                 authorisation server's Token endpoint. Must not be 
	 *                 {@code null}.
	 * @param exp      The expiration time. Must not be {@code null}.
	 * @param nbf      The time before which the token must not be 
	 *                 accepted for processing, {@code null} if not
	 *                 specified.
	 * @param iat      The time at which the token was issued, 
	 *                 {@code null} if not specified.
	 * @param jti      Unique identifier for the JWT, {@code null} if
	 *                 not specified.
	 */
	public JWTAuthenticationClaimsSet(final ClientID clientID,
					  final List<Audience> aud,
					  final Date exp,
					  final Date nbf,
					  final Date iat,
					  final JWTID jti) {

		super(new Issuer(clientID.getValue()), new Subject(clientID.getValue()), aud, exp, nbf, iat, jti, null);
	}

	
	/**
	 * Creates a new JWT client authentication claims set.
	 *
	 * @param iss      The issuer. May be different from the client
	 *                 identifier that is used to specify the subject. Must
	 *                 not be {@code null}.
	 * @param clientID The client identifier. Used to specify the subject.
	 *                 Must not be {@code null}.
	 * @param aud      The audience, typically including the URI of the
	 *                 authorisation server's Token endpoint. Must not be
	 *                 {@code null}.
	 * @param exp      The expiration time. Must not be {@code null}.
	 * @param nbf      The time before which the token must not be
	 *                 accepted for processing, {@code null} if not
	 *                 specified.
	 * @param iat      The time at which the token was issued,
	 *                 {@code null} if not specified.
	 * @param jti      Unique identifier for the JWT, {@code null} if
	 *                 not specified.
	 */
	public JWTAuthenticationClaimsSet(final Issuer iss,
					  final ClientID clientID,
					  final List<Audience> aud,
					  final Date exp,
					  final Date nbf,
					  final Date iat,
					  final JWTID jti) {

		super(iss, new Subject(clientID.getValue()), aud, exp, nbf, iat, jti, null);
	}


	/**
	 * Gets the client identifier. Corresponds to the {@code sub} claim.
	 *
	 * @return The client identifier.
	 */
	public ClientID getClientID() {

		return new ClientID(getSubject());
	}
	
	/**
	 * Parses a JWT client authentication claims set from the specified 
	 * JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The client authentication claims set.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a 
	 *                        client authentication claims set.
	 */
	public static JWTAuthenticationClaimsSet parse(final JSONObject jsonObject)
		throws ParseException {
		
		JWTAssertionDetails assertion = JWTAssertionDetails.parse(jsonObject);

		return new JWTAuthenticationClaimsSet(
			assertion.getIssuer(),
			new ClientID(assertion.getSubject()),
			assertion.getAudience(),
			assertion.getExpirationTime(),
			assertion.getNotBeforeTime(),
			assertion.getIssueTime(),
			assertion.getJWTID());
	}


	/**
	 * Parses a JWT client authentication claims set from the specified JWT 
	 * claims set.
	 *
	 * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
	 *
	 * @return The client authentication claims set.
	 *
	 * @throws ParseException If the JWT claims set couldn't be parsed to a 
	 *                        client authentication claims set.
	 */
	public static JWTAuthenticationClaimsSet parse(final JWTClaimsSet jwtClaimsSet)
		throws ParseException {
		
		return parse(JSONObjectUtils.toJSONObject(jwtClaimsSet));
	}
}
