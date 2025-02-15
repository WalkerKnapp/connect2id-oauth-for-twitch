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


import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.Nonce;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import java.util.*;


/**
 * ID token claims set, serialisable to a JSON object.
 *
 * <p>Example ID token claims set:
 *
 * <pre>
 * {
 *   "iss"       : "https://server.example.com",
 *   "sub"       : "24400320",
 *   "aud"       : "s6BhdRkqt3",
 *   "nonce"     : "n-0S6_WzA2Mj",
 *   "exp"       : 1311281970,
 *   "iat"       : 1311280970,
 *   "auth_time" : 1311280969,
 *   "acr"       : "urn:mace:incommon:iap:silver",
 *   "at_hash"   : "MTIzNDU2Nzg5MDEyMzQ1Ng"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 *     <li>OpenID Connect Front-Channel Logout 1.0
 *     <li>OpenID Connect Native SSO for Mobile Apps 1.0
 *     <li>Financial Services – Financial API - Part 2: Read and Write API
 *         Security Profile
 * </ul>
 */
public class IDTokenClaimsSet extends CommonOIDCTokenClaimsSet {


	/**
	 * The subject authentication time claim name.
	 */
	public static final String AUTH_TIME_CLAIM_NAME = "auth_time";


	/**
	 * The nonce claim name.
	 */
	public static final String NONCE_CLAIM_NAME = "nonce";


	/**
	 * The access token hash claim name.
	 */
	public static final String AT_HASH_CLAIM_NAME = "at_hash";


	/**
	 * The authorisation code hash claim name.
	 */
	public static final String C_HASH_CLAIM_NAME = "c_hash";
	
	
	/**
	 * The state hash claim name.
	 */
	public static final String S_HASH_CLAIM_NAME = "s_hash";


	/**
	 * The device secret hash claim name.
	 */
	public static final String DS_HASH_CLAIM_NAME = "ds_hash";


	/**
	 * The ACR claim name.
	 */
	public static final String ACR_CLAIM_NAME = "acr";


	/**
	 * The AMRs claim name.
	 */
	public static final String AMR_CLAIM_NAME = "amr";


	/**
	 * The authorised party claim name.
	 */
	public static final String AZP_CLAIM_NAME = "azp";


	/**
	 * The subject JWK claim name.
	 */
	public static final String SUB_JWK_CLAIM_NAME = "sub_jwk";


	/**
	 * The names of the standard top-level ID token claims.
	 */
	private static final Set<String> STD_CLAIM_NAMES;


	static {
		Set<String> claimNames = new HashSet<>(CommonOIDCTokenClaimsSet.getStandardClaimNames());
		claimNames.add(AUTH_TIME_CLAIM_NAME);
		claimNames.add(NONCE_CLAIM_NAME);
		claimNames.add(AT_HASH_CLAIM_NAME);
		claimNames.add(C_HASH_CLAIM_NAME);
		claimNames.add(S_HASH_CLAIM_NAME);
		claimNames.add(DS_HASH_CLAIM_NAME);
		claimNames.add(ACR_CLAIM_NAME);
		claimNames.add(AMR_CLAIM_NAME);
		claimNames.add(AZP_CLAIM_NAME);
		claimNames.add(SUB_JWK_CLAIM_NAME);
		STD_CLAIM_NAMES = Collections.unmodifiableSet(claimNames);
	}


	/**
	 * Gets the names of the standard top-level ID token claims.
	 *
	 * @return The names of the standard top-level ID token claims
	 *         (read-only set).
	 */
	public static Set<String> getStandardClaimNames() {

		return STD_CLAIM_NAMES;
	}


	/**
	 * Creates a new minimal ID token claims set. Note that the ID token
	 * may require additional claims to be present depending on the
	 * original OpenID Connect authorisation request.
	 *
	 * @param iss The issuer. Must not be {@code null}.
	 * @param sub The subject. Must not be {@code null}.
	 * @param aud The audience. Must not be {@code null}.
	 * @param exp The expiration time. Must not be {@code null}.
	 * @param iat The issue time. Must not be {@code null}.
	 */
	public IDTokenClaimsSet(final Issuer iss,
				final Subject sub,
				final List<Audience> aud,
				final Date exp,
				final Date iat) {

		setClaim(ISS_CLAIM_NAME, iss.getValue());
		setClaim(SUB_CLAIM_NAME, sub.getValue());

		if (aud.isEmpty()) {
			throw new IllegalArgumentException("The aud must not be empty");
		}

		JSONArray audList = new JSONArray();

		for (Audience a: aud)
			audList.add(a.getValue());

		setClaim(AUD_CLAIM_NAME, audList);

		if (exp.before(iat) || exp.equals(iat)) {
			throw new IllegalArgumentException("The exp must be after iat");
		}

		setDateClaim(EXP_CLAIM_NAME, Objects.requireNonNull(exp));
		setDateClaim(IAT_CLAIM_NAME, Objects.requireNonNull(iat));
	}


	/**
	 * Creates a new ID token claims set from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must be verified to represent a
	 *                   valid ID token claims set and not be {@code null}.
	 *
	 * @throws ParseException If the JSON object doesn't represent a valid
	 *                        ID token claims set.
	 */
	private IDTokenClaimsSet(final JSONObject jsonObject)
		throws ParseException {

		super(jsonObject);

		if (getStringClaim(ISS_CLAIM_NAME) == null)
			throw new ParseException("Missing or invalid iss claim");

		if (getStringClaim(SUB_CLAIM_NAME) == null)
			throw new ParseException("Missing or invalid sub claim");

		if (getStringClaim(AUD_CLAIM_NAME) == null && getStringListClaim(AUD_CLAIM_NAME) == null ||
		    getStringListClaim(AUD_CLAIM_NAME) != null && getStringListClaim(AUD_CLAIM_NAME).isEmpty())
			throw new ParseException("Missing or invalid aud claim");

		if (getDateClaim(EXP_CLAIM_NAME) == null)
			throw new ParseException("Missing or invalid exp claim");

		if (getDateClaim(IAT_CLAIM_NAME) == null)
			throw new ParseException("Missing or invalid iat claim");
	}


	/**
	 * Creates a new ID token claims set from the specified JSON Web Token
	 * (JWT) claims set.
	 *
	 * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
	 *
	 * @throws ParseException If the JWT claims set doesn't represent a
	 *                        valid ID token claims set.
	 */
	public IDTokenClaimsSet(final JWTClaimsSet jwtClaimsSet)
		throws ParseException {

		this(JSONObjectUtils.toJSONObject(jwtClaimsSet));
	}


	/**
	 * Checks if this ID token claims set contains all required claims for
	 * the specified OpenID Connect response type.
	 *
	 * @param responseType     The OpenID Connect response type. Must not
	 *                         be {@code null}.
	 * @param iatAuthzEndpoint Specifies the endpoint where the ID token
	 *                         was issued (required for hybrid flow).
	 *                         {@code true} if the ID token was issued at
	 *                         the authorisation endpoint, {@code false} if
	 *                         the ID token was issued at the token
	 *                         endpoint.
	 *
	 * @return {@code true} if the required claims are contained, else
	 *         {@code false}.
	 */
	public boolean hasRequiredClaims(final ResponseType responseType, final boolean iatAuthzEndpoint) {

		// Code flow
		// See http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
		if (ResponseType.CODE.equals(responseType)) {
			// nonce, c_hash and at_hash not required
			return true; // ok
		}

		// Implicit flow
		// See http://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken
		if (ResponseType.IDTOKEN.equals(responseType)) {

			return getNonce() != null;

		}

		if (ResponseType.IDTOKEN_TOKEN.equals(responseType)) {

			if (getNonce() == null) {
				// nonce required
				return false;
			}

			return getAccessTokenHash() != null;
		}

		// Hybrid flow
		// See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
		if (ResponseType.CODE_IDTOKEN.equals(responseType)) {

			if (getNonce() == null) {
				// nonce required
				return false;
			}

			if (! iatAuthzEndpoint) {
				// c_hash and at_hash not required when id_token issued at token endpoint
				// See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken2
				return true;
			}

			return getCodeHash() != null;

		}

		if (ResponseType.CODE_TOKEN.equals(responseType)) {

			if (getNonce() == null) {
				// nonce required
				return false;
			}

			if (! iatAuthzEndpoint) {
				// c_hash and at_hash not required when id_token issued at token endpoint
				// See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken2
				return true;
			}

			return true; // ok
		}

		if (ResponseType.CODE_IDTOKEN_TOKEN.equals(responseType)) {

			if (getNonce() == null) {
				// nonce required
				return false;
			}

			if (! iatAuthzEndpoint) {
				// c_hash and at_hash not required when id_token issued at token endpoint
				// See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken2
				return true;
			}

			if (getAccessTokenHash() == null) {
				// at_hash required when issued at authz endpoint
				return false;
			}

			return getCodeHash() != null;

		}

		throw new IllegalArgumentException("Unsupported response_type: " + responseType);
	}


	/**
	 * Use {@link #hasRequiredClaims(ResponseType, boolean)} instead.
	 *
	 * @param responseType The OpenID Connect response type. Must not be
	 *                     {@code null}.
	 *
	 * @return {@code true} if the required claims are contained, else
	 *         {@code false}.
	 */
	@Deprecated
	public boolean hasRequiredClaims(final ResponseType responseType) {

		return hasRequiredClaims(responseType, true);
	}


	/**
	 * Gets the subject authentication time. Corresponds to the
	 * {@code auth_time} claim.
	 *
	 * @return The authentication time, {@code null} if not specified or
	 *         parsing failed.
	 */
	public Date getAuthenticationTime() {

		return getDateClaim(AUTH_TIME_CLAIM_NAME);
	}


	/**
	 * Sets the subject authentication time. Corresponds to the
	 * {@code auth_time} claim.
	 *
	 * @param authTime The authentication time, {@code null} if not
	 *                 specified.
	 */
	public void setAuthenticationTime(final Date authTime) {

		setDateClaim(AUTH_TIME_CLAIM_NAME, authTime);
	}


	/**
	 * Gets the ID token nonce. Corresponds to the {@code nonce} claim.
	 *
	 * @return The nonce, {@code null} if not specified or parsing failed.
	 */
	public Nonce getNonce() {

		String value = getStringClaim(NONCE_CLAIM_NAME);
		return value != null ? new Nonce(value) : null;
	}


	/**
	 * Sets the ID token nonce. Corresponds to the {@code nonce} claim.
	 *
	 * @param nonce The nonce, {@code null} if not specified.
	 */
	public void setNonce(final Nonce nonce) {

		setClaim(NONCE_CLAIM_NAME, nonce != null ? nonce.getValue() : null);
	}


	/**
	 * Gets the access token hash. Corresponds to the {@code at_hash}
	 * claim.
	 *
	 * @return The access token hash, {@code null} if not specified or
	 *         parsing failed.
	 */
	public AccessTokenHash getAccessTokenHash() {

		String value = getStringClaim(AT_HASH_CLAIM_NAME);
		return value != null ? new AccessTokenHash(value) : null;
	}


	/**
	 * Sets the access token hash. Corresponds to the {@code at_hash}
	 * claim.
	 *
	 * @param atHash The access token hash, {@code null} if not specified.
	 */
	public void setAccessTokenHash(final AccessTokenHash atHash) {

		setClaim(AT_HASH_CLAIM_NAME, atHash != null ? atHash.getValue() : null);
	}


	/**
	 * Gets the authorisation code hash. Corresponds to the {@code c_hash}
	 * claim.
	 *
	 * @return The authorisation code hash, {@code null} if not specified
	 *         or parsing failed.
	 */
	public CodeHash getCodeHash() {

		String value = getStringClaim(C_HASH_CLAIM_NAME);
		return value != null ? new CodeHash(value) : null;
	}


	/**
	 * Sets the authorisation code hash. Corresponds to the {@code c_hash}
	 * claim.
	 *
	 * @param cHash The authorisation code hash, {@code null} if not
	 *              specified.
	 */
	public void setCodeHash(final CodeHash cHash) {

		setClaim(C_HASH_CLAIM_NAME, cHash != null ? cHash.getValue() : null);
	}
	
	
	/**
	 * Gets the state hash. Corresponds to the {@code s_hash} claim.
	 *
	 * @return The state hash, {@code null} if not specified or parsing
	 *         failed.
	 */
	public StateHash getStateHash() {
		
		String value = getStringClaim(S_HASH_CLAIM_NAME);
		return value != null ? new StateHash(value) : null;
	}
	
	
	/**
	 * Sets the state hash. Corresponds to the {@code s_hash} claim.
	 *
	 * @param sHash The state hash, {@code null} if not specified.
	 */
	public void setStateHash(final StateHash sHash) {
		
		setClaim(S_HASH_CLAIM_NAME, sHash != null ? sHash.getValue() : null);
	}


	/**
	 * Gets the device secret hash. Corresponds to the {@code ds_hash}
	 * claim.
	 *
	 * @return The device secret hash, {@code null} if not specified or
	 *         parsing failed.
	 */
	public DeviceSecretHash getDeviceSecretHash() {

		String value = getStringClaim(DS_HASH_CLAIM_NAME);
		return value != null ? new DeviceSecretHash(value) : null;
	}


	/**
	 * Sets the device secret hash. Corresponds to the {@code ds_hash}
	 * claim.
	 *
	 * @param dsHash The device secret hash, {@code null} if not specified.
	 */
	public void setDeviceSecretHash(final DeviceSecretHash dsHash) {

		setClaim(DS_HASH_CLAIM_NAME, dsHash != null ? dsHash.getValue() : null);
	}


	/**
	 * Gets the Authentication Context Class Reference (ACR). Corresponds
	 * to the {@code acr} claim.
	 *
	 * @return The Authentication Context Class Reference (ACR),
	 *         {@code null} if not specified or parsing failed.
	 */
	public ACR getACR() {

		String value = getStringClaim(ACR_CLAIM_NAME);
		return value != null ? new ACR(value) : null;
	}


	/**
	 * Sets the Authentication Context Class Reference (ACR). Corresponds
	 * to the {@code acr} claim.
	 *
	 * @param acr The Authentication Context Class Reference (ACR),
	 *            {@code null} if not specified.
	 */
	public void setACR(final ACR acr) {

		setClaim(ACR_CLAIM_NAME, acr != null ? acr.getValue() : null);
	}


	/**
	 * Gets the Authentication Methods References (AMRs). Corresponds to
	 * the {@code amr} claim.
	 *
	 * @return The Authentication Methods Reference (AMR) list,
	 *         {@code null} if not specified or parsing failed.
	 */
	public List<AMR> getAMR() {

		List<String> rawList = getStringListClaim(AMR_CLAIM_NAME);

		if (rawList == null || rawList.isEmpty())
			return null;

		List<AMR> amrList = new ArrayList<>(rawList.size());

		for (String s: rawList)
			amrList.add(new AMR(s));

		return amrList;
	}


	/**
	 * Sets the Authentication Methods References (AMRs). Corresponds to
	 * the {@code amr} claim.
	 *
	 * @param amr The Authentication Methods Reference (AMR) list,
	 *            {@code null} if not specified.
	 */
	public void setAMR(final List<AMR> amr) {

		if (amr != null) {

			List<String> amrList = new ArrayList<>(amr.size());

			for (AMR a: amr)
				amrList.add(a.getValue());

			setClaim(AMR_CLAIM_NAME, amrList);

		} else {
			setClaim(AMR_CLAIM_NAME, null);
		}
	}


	/**
	 * Gets the authorised party for the ID token. Corresponds to the
	 * {@code azp} claim.
	 *
	 * @return The authorised party, {@code null} if not specified or
	 *         parsing failed.
	 */
	public AuthorizedParty getAuthorizedParty() {

		String value = getStringClaim(AZP_CLAIM_NAME);
		return value != null ? new AuthorizedParty(value) : null;
	}


	/**
	 * Sets the authorised party for the ID token. Corresponds to the
	 * {@code azp} claim.
	 *
	 * @param azp The authorised party, {@code null} if not specified.
	 */
	public void setAuthorizedParty(final AuthorizedParty azp) {

		setClaim(AZP_CLAIM_NAME, azp != null ? azp.getValue() : null);
	}


	/**
	 * Gets the subject's JSON Web Key (JWK) for a self-issued OpenID
	 * Connect provider. Corresponds to the {@code sub_jwk} claim.
	 *
	 * @return The subject's JWK, {@code null} if not specified or parsing
	 *         failed.
	 */
	public JWK getSubjectJWK() {

		JSONObject jsonObject = getClaim(SUB_JWK_CLAIM_NAME, JSONObject.class);

		if (jsonObject == null)
			return null;

		try {
			return JWK.parse(jsonObject);

		} catch (java.text.ParseException e) {

			return null;
		}
	}


	/**
	 * Sets the subject's JSON Web Key (JWK) for a self-issued OpenID
	 * Connect provider. Corresponds to the {@code sub_jwk} claim.
	 *
	 * @param subJWK The subject's JWK (must be public), {@code null} if
	 *               not specified.
	 */
	public void setSubjectJWK(final JWK subJWK) {

		if (subJWK != null) {

			if (subJWK.isPrivate())
				throw new IllegalArgumentException("The subject's JSON Web Key (JWK) must be public");

			setClaim(SUB_JWK_CLAIM_NAME, new JSONObject(subJWK.toJSONObject()));

		} else {
			setClaim(SUB_JWK_CLAIM_NAME, null);
		}
	}


	/**
	 * Parses an ID token claims set from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The ID token claims set.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static IDTokenClaimsSet parse(final JSONObject jsonObject)
		throws ParseException {

		try {
			return new IDTokenClaimsSet(jsonObject);

		} catch (IllegalArgumentException e) {
			
			throw new ParseException(e.getMessage(), e);
		}
	}


	/**
	 * Parses an ID token claims set from the specified JSON object string.
	 *
	 * @param json The JSON object string to parse. Must not be
	 *             {@code null}.
	 *
	 * @return The ID token claims set.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static IDTokenClaimsSet parse(final String json)
		throws ParseException {

		return parse(JSONObjectUtils.parse(json));
	}
}
