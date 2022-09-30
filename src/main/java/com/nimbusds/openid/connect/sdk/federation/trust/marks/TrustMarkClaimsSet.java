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

package com.nimbusds.openid.connect.sdk.federation.trust.marks;


import java.net.URI;
import java.util.Date;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.claims.CommonClaimsSet;


/**
 * Federation trust mark claims set, serialisable to a JSON object.
 *
 * <p>Example claims set:
 *
 * <pre>
 * {
 *   "iss" : "https://swamid.sunet.se",
 *   "sub" : "https://umu.se/op",
 *   "iat" : 1577833200,
 *   "exp" : 1609369200,
 *   "id"  : "https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 5.3.
 * </ul>
 */
public class TrustMarkClaimsSet extends CommonClaimsSet {
	
	
	/**
	 * The identifier claim name.
	 */
	public static final String ID_CLAIM_NAME = "id";
	
	
	/**
	 * The mark / logo URI name.
	 */
	public static final String LOGO_URI_CLAIM_NAME = "logo_uri";
	
	
	/**
	 * The expiration time claim name.
	 */
	public static final String EXP_CLAIM_NAME = "exp";
	
	
	/**
	 * The reference claim name.
	 */
	public static final String REF_CLAIM_NAME = "ref";
	
	
	/**
	 * Creates a new trust mark claims set with the minimum required
	 * claims.
	 *
	 * @param iss  The issuer. Corresponds to the {@code iss} claim. Must
	 *             not be {@code null}.
	 * @param sub  The subject. Corresponds to the {@code sub} claim. Must
	 *             not be {@code null}.
	 * @param id   The identifier. Corresponds to the {@code id} claim.
	 *             Must not be {@code null}.
	 * @param iat  The issue time. Corresponds to the {@code iat} claim.
	 *             Must not be {@code null}.
	 */
	public TrustMarkClaimsSet(final Issuer iss,
				  final Subject sub,
				  final Identifier id,
				  final Date iat) {
		
		setClaim(ISS_CLAIM_NAME, iss.getValue());
		setClaim(SUB_CLAIM_NAME, sub.getValue());
		setClaim(ID_CLAIM_NAME, id.getValue());
		setDateClaim(IAT_CLAIM_NAME, iat);
	}
	
	
	/**
	 * Creates a new trust mark claims set from the specified JWT claims
	 * set.
	 *
	 * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
	 *
	 * @throws ParseException If the JWT claims set doesn't represent a
	 * 	                  valid trust mark claims set.
	 */
	public TrustMarkClaimsSet(final JWTClaimsSet jwtClaimsSet)
		throws ParseException {
		
		super(JSONObjectUtils.toJSONObject(jwtClaimsSet));
		
		validateRequiredClaimsPresence();
	}
	
	
	/**
	 * Validates this claims set for having all minimum required claims for
	 * a trust mark.
	 *
	 * @throws ParseException If the validation failed and a required claim
	 *                        is missing.
	 */
	public void validateRequiredClaimsPresence()
		throws ParseException {
		
		if (getIssuer() == null) {
			throw new ParseException("Missing iss (issuer) claim");
		}
		
		if (getSubject() == null) {
			throw new ParseException("Missing sub (subject) claim");
		}
		
		if (getID() == null) {
			throw new ParseException("Missing id (identifier) claim");
		}
		
		if (getIssueTime() == null) {
			throw new ParseException("Missing iat (issued-at) claim");
		}
	}
	
	
	/**
	 * Returns the identifier. Corresponds to the {@code id} claim.
	 *
	 * @return The identifier.
	 */
	public Identifier getID() {
		
		return new Identifier(getStringClaim(ID_CLAIM_NAME));
	}
	
	
	/**
	 * Gets the mark / logo URI. Corresponds to the {@code logo_uri} claim.
	 *
	 * @return The mark / logo URI, {@code null} if not specified or
	 *         parsing failed.
	 */
	public URI getLogoURI() {
		
		return getURIClaim(LOGO_URI_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the mark / logo URI. Corresponds to the {@code logo_uri} claim.
	 *
	 * @param markURI The mark / logo URI, {@code null} if not specified.
	 */
	public void setMark(final URI markURI) {
		
		setURIClaim(LOGO_URI_CLAIM_NAME, markURI);
	}
	
	
	/**
	 * Gets the expiration time. Corresponds to the {@code exp} claim.
	 *
	 * @return The expiration time, {@code null} if not specified or
	 *         parsing failed.
	 */
	public Date getExpirationTime() {
		
		return getDateClaim(EXP_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the expiration time. Corresponds to the {@code exp} claim.
	 *
	 * @param exp The expiration time, {@code null} if not specified.
	 */
	public void setExpirationTime(final Date exp) {
		
		setDateClaim(EXP_CLAIM_NAME, exp);
	}
	
	
	/**
	 * Gets the reference URI. Corresponds to the {@code ref} claim.
	 *
	 * @return The reference URI, {@code null} if not specified or parsing
	 *         failed.
	 */
	public URI getReference() {
		
		return getURIClaim(REF_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the reference URI. Corresponds to the {@code ref} claim.
	 *
	 * @param refURI The reference URI, {@code null} if not specified.
	 */
	public void setReference(final URI refURI) {
		
		setURIClaim(REF_CLAIM_NAME, refURI);
	}
}
