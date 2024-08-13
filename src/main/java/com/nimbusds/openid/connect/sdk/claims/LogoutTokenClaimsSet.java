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

package com.nimbusds.openid.connect.sdk.claims;


import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import java.util.*;


/**
 * Back-channel logout token claims set, serialisable to a JSON object.
 *
 * <p>Example logout token claims set:
 *
 * <pre>
 * {
 *   "iss"    : "https://server.example.com",
 *   "sub"    : "248289761001",
 *   "aud"    : "s6BhdRkqt3",
 *   "iat"    : 1471566154,
 *   "exp"    : 1471569754,
 *   "jti"    : "bWJq",
 *   "sid"    : "08a5019c-17e1-4977-8f42-65a12843ea02",
 *   "events" : { "http://schemas.openid.net/event/backchannel-logout": { } }
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Back-Channel Logout 1.0
 *     <li>Security Event Token (SET) (RFC 8417)
 * </ul>
 */
public class LogoutTokenClaimsSet extends CommonOIDCTokenClaimsSet {
	
	
	/**
	 * The JWT ID claim name.
	 */
	public static final String JTI_CLAIM_NAME = "jti";
	
	
	/**
	 * The events claim name.
	 */
	public static final String EVENTS_CLAIM_NAME = "events";
	
	
	/**
	 * The OpenID logout event type.
	 */
	public static final String EVENT_TYPE = "http://schemas.openid.net/event/backchannel-logout";
	
	
	/**
	 * The names of the standard top-level logout token claims.
	 */
	private static final Set<String> STD_CLAIM_NAMES;
	
	
	static {
		Set<String> claimNames = new HashSet<>(CommonOIDCTokenClaimsSet.getStandardClaimNames());
		claimNames.add(JTI_CLAIM_NAME);
		claimNames.add(EVENTS_CLAIM_NAME);
		STD_CLAIM_NAMES = Collections.unmodifiableSet(claimNames);
	}
	
	
	/**
	 * Gets the names of the standard top-level logout token claims.
	 *
	 * @return The names of the standard top-level logout token claims
	 *         (read-only set).
	 */
	public static Set<String> getStandardClaimNames() {
		
		return STD_CLAIM_NAMES;
	}
	
	
	/**
	 * Creates a new logout token claims set. Either the subject or the
	 * session ID must be set, or both.
	 *
	 * @param iss The issuer. Must not be {@code null}.
	 * @param sub The subject. Must not be {@code null} unless the session
	 *            ID is set.
	 * @param aud The audience. Must not be {@code null}.
	 * @param iat The issue time. Must not be {@code null}.
	 * @param exp The expiration time. Must not be {@code null}.
	 * @param jti The JWT ID. Must not be {@code null}.
	 * @param sid The session ID. Must not be {@code null} unless the
	 *            subject is set.
	 */
	public LogoutTokenClaimsSet(final Issuer iss,
				    final Subject sub,
				    final List<Audience> aud,
				    final Date iat,
				    final Date exp,
				    final JWTID jti,
				    final SessionID sid) {
		
		if (sub == null && sid == null) {
			throw new IllegalArgumentException("Either the subject or the session ID must be set, or both");
		}
		
		setClaim(ISS_CLAIM_NAME, iss.getValue());
		
		if (sub != null) {
			setClaim(SUB_CLAIM_NAME, sub.getValue());
		}
		
		JSONArray audList = new JSONArray();
		
		for (Audience a: aud)
			audList.add(a.getValue());
		
		setClaim(AUD_CLAIM_NAME, audList);
		
		setDateClaim(IAT_CLAIM_NAME, iat);

		setDateClaim(EXP_CLAIM_NAME, exp);
		
		setClaim(JTI_CLAIM_NAME, jti.getValue());
		
		JSONObject events = new JSONObject();
		events.put(EVENT_TYPE, new JSONObject());
		setClaim(EVENTS_CLAIM_NAME, events);
		
		if (sid != null) {
			setClaim(SID_CLAIM_NAME, sid.getValue());
		}
	}


	/**
	 * Creates a new logout token claims set. Either the subject or the
	 * session ID must be set, or both.
	 *
	 * @param iss The issuer. Must not be {@code null}.
	 * @param sub The subject. Must not be {@code null} unless the session
	 *            ID is set.
	 * @param aud The audience. Must not be {@code null}.
	 * @param iat The issue time. Must not be {@code null}.
	 * @param jti The JWT ID. Must not be {@code null}.
	 * @param sid The session ID. Must not be {@code null} unless the
	 *            subject is set.
	 */
	@Deprecated
	public LogoutTokenClaimsSet(final Issuer iss,
				    final Subject sub,
				    final List<Audience> aud,
				    final Date iat,
				    final JWTID jti,
				    final SessionID sid) {

		this(iss, sub, aud, iat, null, jti, sid);
	}
	
	
	/**
	 * Creates a new logout token claims set from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object. Must be verified to represent a
	 *                   valid logout token claims set and not be
	 *                   {@code null}.
	 *
	 * @throws ParseException If the JSON object doesn't represent a valid
	 *                        logout token claims set.
	 */
	private LogoutTokenClaimsSet(final JSONObject jsonObject)
		throws ParseException {
		
		super(jsonObject);
		
		if (getStringClaim(ISS_CLAIM_NAME) == null)
			throw new ParseException("Missing or invalid iss claim");
		
		if (getStringClaim(SUB_CLAIM_NAME) == null && getStringClaim(SID_CLAIM_NAME) == null)
			throw new ParseException("Missing or invalid sub and / or sid claim(s)");
		
		if (getStringClaim(AUD_CLAIM_NAME) == null && getStringListClaim(AUD_CLAIM_NAME) == null ||
			getStringListClaim(AUD_CLAIM_NAME) != null && getStringListClaim(AUD_CLAIM_NAME).isEmpty())
			throw new ParseException("Missing or invalid aud claim");
		
		if (getDateClaim(IAT_CLAIM_NAME) == null)
			throw new ParseException("Missing or invalid iat claim");

		if (getDateClaim(EXP_CLAIM_NAME) == null)
			throw new ParseException("Missing or invalid exp claim");
		
		if (getStringClaim(JTI_CLAIM_NAME) == null)
			throw new ParseException("Missing or invalid jti claim");
		
		if (getClaim(EVENTS_CLAIM_NAME) == null)
			throw new ParseException("Missing or invalid events claim");
		
		JSONObject events = getClaim(EVENTS_CLAIM_NAME, JSONObject.class);
		
		if (JSONObjectUtils.getJSONObject(events, EVENT_TYPE, null) == null) {
			throw new ParseException("Missing event type " + EVENT_TYPE);
		}
		
		if (jsonObject.containsKey("nonce")) {
			throw new ParseException("Nonce is prohibited");
		}
	}
	
	
	/**
	 * Creates a new logout token claims set from the specified JSON Web
	 * Token (JWT) claims set.
	 *
	 * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
	 *
	 * @throws ParseException If the JWT claims set doesn't represent a
	 *                        valid logout token claims set.
	 */
	public LogoutTokenClaimsSet(final JWTClaimsSet jwtClaimsSet)
		throws ParseException {
		
		this(JSONObjectUtils.toJSONObject(jwtClaimsSet));
	}
	
	
	/**
	 * Gets the JWT ID. Corresponds to the {@code jti} claim.
	 *
	 * @return The JWT ID.
	 */
	public JWTID getJWTID() {
		
		return new JWTID(getStringClaim(JTI_CLAIM_NAME));
	}
	
	
	@Override
	public JSONObject toJSONObject() {
		
		if (getClaim("nonce") != null) {
			throw new IllegalStateException("Nonce is prohibited");
		}
		
		return super.toJSONObject();
	}
	
	
	@Override
	public JWTClaimsSet toJWTClaimsSet()
		throws ParseException {
		
		if (getClaim("nonce") != null) {
			throw new ParseException("Nonce is prohibited");
		}
		
		return super.toJWTClaimsSet();
	}
	
	
	/**
	 * Parses a logout token claims set from the specified JSON object
	 * string.
	 *
	 * @param json The JSON object string to parse. Must not be
	 *             {@code null}.
	 *
	 * @return The logout token claims set.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static LogoutTokenClaimsSet parse(final String json)
		throws ParseException {
		
		JSONObject jsonObject = JSONObjectUtils.parse(json);
		
		try {
			return new LogoutTokenClaimsSet(jsonObject);
			
		} catch (IllegalArgumentException e) {
			
			throw new ParseException(e.getMessage(), e);
		}
	}
}
