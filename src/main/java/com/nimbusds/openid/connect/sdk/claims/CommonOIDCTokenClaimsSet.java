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


import net.minidev.json.JSONObject;

import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

/**
 * Common OpenID tokens (ID, logout) claims set.
 */
abstract class CommonOIDCTokenClaimsSet extends CommonClaimsSet {


	/**
	 * The expiration time claim name.
	 */
	public static final String EXP_CLAIM_NAME = "exp";
	
	
	/**
	 * The session identifier claim name.
	 */
	public static final String SID_CLAIM_NAME = "sid";
	
	
	/**
	 * The names of the standard top-level claims.
	 */
	private static final Set<String> STD_CLAIM_NAMES;
	
	
	static {
		Set<String> claimNames = new HashSet<>(CommonClaimsSet.getStandardClaimNames());
		claimNames.add(EXP_CLAIM_NAME);
		claimNames.add(SID_CLAIM_NAME);
		STD_CLAIM_NAMES = Collections.unmodifiableSet(claimNames);
	}
	
	
	/**
	 * Gets the names of the standard top-level claims.
	 *
	 * @return The names of the standard top-level claims (read-only set).
	 */
	public static Set<String> getStandardClaimNames() {
		
		return STD_CLAIM_NAMES;
	}
	
	
	/**
	 * Creates a new empty common OpenID tokens claims set.
	 */
	protected CommonOIDCTokenClaimsSet() {
		
		super();
	}
	
	
	/**
	 * Creates a new common OpenID tokens claims set from the specified
	 * JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 */
	protected CommonOIDCTokenClaimsSet(final JSONObject jsonObject) {
		
		super(jsonObject);
	}


	/**
	 * Gets the token expiration time. Corresponds to the {@code exp}
	 * claim.
	 *
	 * @return The expiration time.
	 */
	public Date getExpirationTime() {

		return getDateClaim(EXP_CLAIM_NAME);
	}
	
	
	/**
	 * Gets the session ID. Corresponds to the {@code sid} claim.
	 *
	 * @return The session ID, {@code null} if not specified.
	 */
	public SessionID getSessionID() {
		
		String val = getStringClaim(SID_CLAIM_NAME);
		
		return val != null ? new SessionID(val) : null;
	}
	
	
	/**
	 * Sets the session ID. Corresponds to the {@code sid} claim.
	 *
	 * @param sid The session ID, {@code null} if not specified.
	 */
	public void setSessionID(final SessionID sid) {
		
		setClaim(SID_CLAIM_NAME, sid != null ? sid.getValue() : null);
	}
}
