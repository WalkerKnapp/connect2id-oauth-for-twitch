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

package com.nimbusds.oauth2.sdk.jarm;


import com.nimbusds.jwt.*;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;

import java.util.*;


/**
 * JWT Secured Authorization Response Mode for OAuth 2.0 (JARM) utilities.
 */
public final class JARMUtils {
	
	
	/**
	 * The JARM response modes.
	 */
	public static final Set<ResponseMode> RESPONSE_MODES = new HashSet<>(Arrays.asList(
		ResponseMode.JWT,
		ResponseMode.QUERY_JWT,
		ResponseMode.FRAGMENT_JWT,
		ResponseMode.FORM_POST_JWT
	));
	
	
	/**
	 * Returns {@code true} if JARM is supported for the specified OpenID
	 * provider / Authorisation server metadata.
	 *
	 * @param asMetadata The OpenID provider / Authorisation server
	 *                   metadata. Must not be {@code null}.
	 *
	 * @return {@code true} if JARM is supported, else {@code false}.
	 */
	public static boolean supportsJARM(final AuthorizationServerMetadata asMetadata) {
		
		if (CollectionUtils.isEmpty(asMetadata.getAuthorizationJWSAlgs())) {
			return false;
		}
		
		if (CollectionUtils.isEmpty(asMetadata.getResponseModes())) {
			return false;
		}
		
		for (ResponseMode responseMode: JARMUtils.RESPONSE_MODES) {
			if (asMetadata.getResponseModes().contains(responseMode)) {
				return true;
			}
		}
		
		return false;
	}
	
	
	/**
	 * Creates a JSON Web Token (JWT) claims set for the specified
	 * authorisation success response.
	 *
	 * @param iss      The OAuth 2.0 authorisation server issuer. Must not
	 *                 be {@code null}.
	 * @param aud      The client ID. Must not be {@code null}.
	 * @param exp      The JWT expiration time. Must not be {@code null}.
	 * @param response The plain authorisation response to use its
	 *                 parameters. If it specifies an {@code iss} (issuer)
	 *                 parameter its value must match the JWT {@code iss}
	 *                 claim. Must not be {@code null}.
	 *
	 * @return The JWT claims set.
	 */
	public static JWTClaimsSet toJWTClaimsSet(final Issuer iss,
						  final ClientID aud,
						  final Date exp,
						  final AuthorizationResponse response) {
	
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
			.issuer(iss.getValue())
			.audience(aud.getValue())
			.expirationTime(Objects.requireNonNull(exp));
		
		for (Map.Entry<String, ?> en: MultivaluedMapUtils.toSingleValuedMap(response.toParameters()).entrySet()) {
			
			if ("response".equals(en.getKey())) {
				continue; // own JARM parameter, skip
			}
			
			if ("iss".equals(en.getKey())) {
				if (! iss.getValue().equals(en.getValue())) {
					throw new IllegalArgumentException("Authorization response iss doesn't match JWT iss claim: " + en.getValue());
				}
			}
			
			builder = builder.claim(en.getKey(), en.getValue() + ""); // force string
		}
		
		return builder.build();
	}
	
	
	/**
	 * Returns a multi-valued map representation of the specified JWT
	 * claims set.
	 *
	 * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
	 *
	 * @return The multi-valued map.
	 */
	public static Map<String,List<String>> toMultiValuedStringParameters(final JWTClaimsSet jwtClaimsSet) {
		
		Map<String,List<String>> params = new HashMap<>();
		
		for (Map.Entry<String,Object> en: jwtClaimsSet.getClaims().entrySet()) {
			params.put(en.getKey(), Collections.singletonList(en.getValue() + ""));
		}
		
		return params;
	}
	
	
	/**
	 * Returns {@code true} if the specified JWT-secured authorisation
	 * response implies an error response. Note that the JWT is not
	 * validated in any way!
	 *
	 * @param jwtString The JWT-secured authorisation response string. Must
	 *                  not be {@code null}.
	 *
	 * @return {@code true} if an error is implied by the presence of the
	 *         {@code error} claim, else {@code false} (also for encrypted
	 *         JWTs which payload cannot be inspected without decrypting
	 *         first).
	 *
	 * @throws ParseException If the JWT is invalid or plain (unsecured).
	 */
	public static boolean impliesAuthorizationErrorResponse(final String jwtString)
		throws ParseException  {
		
		try {
			return impliesAuthorizationErrorResponse(JWTParser.parse(jwtString));
		} catch (java.text.ParseException e) {
			throw new ParseException("Invalid JWT-secured authorization response: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Returns {@code true} if the specified JWT-secured authorisation
	 * response implies an error response. Note that the JWT is not
	 * validated in any way!
	 *
	 * @param jwt The JWT-secured authorisation response. Must not be
	 *            {@code null}.
	 *
	 * @return {@code true} if an error is implied by the presence of the
	 *         {@code error} claim, else {@code false} (also for encrypted
	 *         JWTs which payload cannot be inspected without decrypting
	 *         first).
	 *
	 * @throws ParseException If the JWT is plain (unsecured).
	 */
	public static boolean impliesAuthorizationErrorResponse(final JWT jwt)
		throws ParseException  {
		
		if (jwt instanceof PlainJWT) {
			throw new ParseException("Invalid JWT-secured authorization response: The JWT must not be plain (unsecured)");
		}
		
		if (jwt instanceof EncryptedJWT) {
			// Cannot peek into payload
			return false;
		}
		
		if (jwt instanceof SignedJWT) {
			
			SignedJWT signedJWT = (SignedJWT)jwt;
			
			try {
				return signedJWT.getJWTClaimsSet().getStringClaim("error") != null;
			} catch (java.text.ParseException e) {
				throw new ParseException("Invalid JWT claims set: " + e.getMessage());
			}
		}
		
		throw new ParseException("Unexpected JWT type");
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private JARMUtils() {}
}
