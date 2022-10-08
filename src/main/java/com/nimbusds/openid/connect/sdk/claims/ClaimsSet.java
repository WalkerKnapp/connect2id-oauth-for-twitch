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


import java.net.URI;
import java.net.URL;
import java.util.*;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Claims set with basic getters and setters, serialisable to a JSON object.
 */
public class ClaimsSet implements JSONAware {
	
	
	/**
	 * The issuer claim name.
	 */
	public static final String ISS_CLAIM_NAME = "iss";
	
	
	/**
	 * The audience claim name.
	 */
	public static final String AUD_CLAIM_NAME = "aud";
	
	
	/**
	 * The names of the standard top-level claims.
	 */
	private static final Set<String> STD_CLAIM_NAMES = Collections.unmodifiableSet(
		new HashSet<>(Arrays.asList(
			ISS_CLAIM_NAME,
			AUD_CLAIM_NAME
		)));
	
	
	/**
	 * Gets the names of the standard top-level claims.
	 *
	 * @return The names of the standard top-level claims (read-only set).
	 */
	public static Set<String> getStandardClaimNames() {
		
		return STD_CLAIM_NAMES;
	}


	/**
	 * The JSON object representation of the claims set.
	 */
	protected final JSONObject claims;


	/**
	 * Creates a new empty claims set.
	 */
	public ClaimsSet() {

		claims = new JSONObject();
	}


	/**
	 * Creates a new claims set from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 */
	public ClaimsSet(final JSONObject jsonObject) {

		if (jsonObject == null)
			throw new IllegalArgumentException("The JSON object must not be null");

		claims = jsonObject;
	}


	/**
	 * Puts all claims from the specified other claims set.
	 *
	 * @param other The other claims set. Must not be {@code null}.
	 */
	public void putAll(final ClaimsSet other) {

		putAll(other.claims);
	}


	/**
	 * Puts all claims from the specified map.
	 *
	 * @param claims The claims to put. Must not be {@code null}.
	 */
	public void putAll(final Map<String,Object> claims) {

		this.claims.putAll(claims);
	}


	/**
	 * Gets a claim.
	 *
	 * @param name The claim name. Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified.
	 */
	public Object getClaim(final String name) {

		return claims.get(name);
	}


	/**
	 * Gets a claim that casts to the specified class.
	 *
	 * @param name  The claim name. Must not be {@code null}.
	 * @param clazz The Java class that the claim value should cast to.
	 *              Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified or casting
	 *         failed.
	 */
	public <T> T getClaim(final String name, final Class<T> clazz) {

		try {
			return JSONObjectUtils.getGeneric(claims, name, clazz);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Returns a map of all instances, including language-tagged, of a
	 * claim with the specified base name.
	 *
	 * <p>Example JSON serialised claims set:
	 *
	 * <pre>
	 * {
	 *   "month"    : "January",
	 *   "month#de" : "Januar"
	 *   "month#es" : "enero",
	 *   "month#it" : "gennaio"
	 * }
	 * </pre>
	 *
	 * <p>The "month" claim instances as java.util.Map:
	 *
	 * <pre>
	 * null = "January" (no language tag)
	 * "de" = "Januar"
	 * "es" = "enero"
	 * "it" = "gennaio"
	 * </pre>
	 *
	 * @param name  The claim name. Must not be {@code null}.
	 * @param clazz The Java class that the claim values should cast to.
	 *              Must not be {@code null}.
	 *
	 * @return The matching language-tagged claim values, empty map if
	 *         none. A {@code null} key indicates the value has no language
	 *         tag (corresponds to the base name).
	 */
	public <T> Map<LangTag,T> getLangTaggedClaim(final String name, final Class<T> clazz) {

		Map<LangTag,Object> matches = LangTagUtils.find(name, claims);
		Map<LangTag,T> out = new HashMap<>();

		for (Map.Entry<LangTag,Object> entry: matches.entrySet()) {

			LangTag langTag = entry.getKey();
			String compositeKey = name + (langTag != null ? "#" + langTag : "");

			try {
				out.put(langTag, JSONObjectUtils.getGeneric(claims, compositeKey, clazz));
			} catch (ParseException e) {
				// skip
			}
		}

		return out;
	}


	/**
	 * Sets a claim.
	 *
	 * @param name  The claim name, with an optional language tag. Must not
	 *              be {@code null}.
	 * @param value The claim value. Should serialise to a JSON entity. If
	 *              {@code null} any existing claim with the same name will
	 *              be removed.
	 */
	public void setClaim(final String name, final Object value) {

		if (value != null)
			claims.put(name, value);
		else
			claims.remove(name);
	}


	/**
	 * Sets a claim with an optional language tag.
	 *
	 * @param name    The claim name. Must not be {@code null}.
	 * @param value   The claim value. Should serialise to a JSON entity.
	 *                If {@code null} any existing claim with the same name
	 *                and language tag (if any) will be removed.
	 * @param langTag The language tag of the claim value, {@code null} if
	 *                not tagged.
	 */
	public void setClaim(final String name, final Object value, final LangTag langTag) {

		String keyName = langTag != null ? name + "#" + langTag : name;
		setClaim(keyName, value);
	}


	/**
	 * Gets a string-based claim.
	 *
	 * @param name The claim name. Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified or casting
	 *         failed.
	 */
	public String getStringClaim(final String name) {

		try {
			return JSONObjectUtils.getString(claims, name, null);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Gets a string-based claim with an optional language tag.
	 *
	 * @param name    The claim name. Must not be {@code null}.
	 * @param langTag The language tag of the claim value, {@code null} to
	 *                get the non-tagged value.
	 *
	 * @return The claim value, {@code null} if not specified or casting
	 *         failed.
	 */
	public String getStringClaim(final String name, final LangTag langTag) {

		return langTag == null ? getStringClaim(name) : getStringClaim(name + '#' + langTag);
	}


	/**
	 * Gets a boolean-based claim.
	 *
	 * @param name The claim name. Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified or casting
	 *         failed.
	 */
	public Boolean getBooleanClaim(final String name) {

		try {
			return JSONObjectUtils.getBoolean(claims, name);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Gets a number-based claim.
	 *
	 * @param name The claim name. Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified or casting
	 *         failed.
	 */
	public Number getNumberClaim(final String name) {

		try {
			return JSONObjectUtils.getNumber(claims, name);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Gets an URL string based claim.
	 *
	 * @param name The claim name. Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified or parsing
	 *         failed.
	 */
	public URL getURLClaim(final String name) {

		try {
			return JSONObjectUtils.getURL(claims, name);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Sets an URL string based claim.
	 *
	 * @param name  The claim name. Must not be {@code null}.
	 * @param value The claim value. If {@code null} any existing claim
	 *              with the same name will be removed.
	 */
	public void setURLClaim(final String name, final URL value) {

		if (value != null)
			setClaim(name, value.toString());
		else
			claims.remove(name);
	}


	/**
	 * Gets an URI string based claim.
	 *
	 * @param name The claim name. Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified or parsing
	 *         failed.
	 */
	public URI getURIClaim(final String name) {

		try {
			return JSONObjectUtils.getURI(claims, name, null);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Sets an URI string based claim.
	 *
	 * @param name  The claim name. Must not be {@code null}.
	 * @param value The claim value. If {@code null} any existing claim
	 *              with the same name will be removed.
	 */
	public void setURIClaim(final String name, final URI value) {

		if (value != null)
			setClaim(name, value.toString());
		else
			claims.remove(name);
	}


	/**
	 * Gets a date / time based claim, represented as the number of seconds
	 * from 1970-01-01T0:0:0Z as measured in UTC until the date / time.
	 *
	 * @param name The claim name. Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified or parsing
	 *         failed.
	 */
	public Date getDateClaim(final String name) {

		try {
			return DateUtils.fromSecondsSinceEpoch(JSONObjectUtils.getNumber(claims, name).longValue());
		} catch (Exception e) {
			return null;
		}
	}


	/**
	 * Sets a date / time based claim, represented as the number of seconds
	 * from 1970-01-01T0:0:0Z as measured in UTC until the date / time.
	 *
	 * @param name  The claim name. Must not be {@code null}.
	 * @param value The claim value. If {@code null} any existing claim
	 *              with the same name will be removed.
	 */
	public void setDateClaim(final String name, final Date value) {

		if (value != null)
			setClaim(name, DateUtils.toSecondsSinceEpoch(value));
		else
			claims.remove(name);
	}


	/**
	 * Gets a string list based claim.
	 *
	 * @param name The claim name. Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified or parsing
	 *         failed.
	 */
	public List<String> getStringListClaim(final String name) {

		try {
			return JSONObjectUtils.getStringList(claims, name);
		} catch (ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Gets a JSON object based claim.
	 *
	 * @param name The claim name. Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified or parsing
	 *         failed.
	 */
	public JSONObject getJSONObjectClaim(final String name) {
		
		try {
			return JSONObjectUtils.getJSONObject(claims, name);
		} catch (ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Gets a JSON array based claim.
	 *
	 * @param name The claim name. Must not be {@code null}.
	 *
	 * @return The claim value, {@code null} if not specified or parsing
	 *         failed.
	 */
	public JSONArray getJSONArrayClaim(final String name) {
		
		try {
			return JSONObjectUtils.getJSONArray(claims, name);
		} catch (ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Gets the issuer. Corresponds to the {@code iss} claim.
	 *
	 * @return The issuer, {@code null} if not specified.
	 */
	public Issuer getIssuer() {
		
		String iss = getStringClaim(ISS_CLAIM_NAME);
		
		return iss != null ? new Issuer(iss) : null;
	}
	
	
	/**
	 * Sets the issuer. Corresponds to the {@code iss} claim.
	 *
	 * @param iss The issuer, {@code null} if not specified.
	 */
	public void setIssuer(final Issuer iss) {
		
		if (iss != null)
			setClaim(ISS_CLAIM_NAME, iss.getValue());
		else
			setClaim(ISS_CLAIM_NAME, null);
	}
	
	
	/**
	 * Gets the audience. Corresponds to the {@code aud} claim.
	 *
	 * @return The audience, {@code null} if not specified.
	 */
	public List<Audience> getAudience() {
		
		if (getClaim(AUD_CLAIM_NAME) instanceof String) {
			// Special case - aud is a string
			return new Audience(getStringClaim(AUD_CLAIM_NAME)).toSingleAudienceList();
		}
		
		// General case - JSON string array
		List<String> rawList = getStringListClaim(AUD_CLAIM_NAME);
		
		if (rawList == null) {
			return null;
		}
		
		List<Audience> audList = new ArrayList<>(rawList.size());
		
		for (String s: rawList)
			audList.add(new Audience(s));
		
		return audList;
	}
	
	
	/**
	 * Sets the audience. Corresponds to the {@code aud} claim.
	 *
	 * @param aud The audience, {@code null} if not specified.
	 */
	public void setAudience(final Audience aud) {
		
		if (aud != null)
			setAudience(aud.toSingleAudienceList());
		else
			setClaim(AUD_CLAIM_NAME, null);
	}
	
	
	/**
	 * Sets the audience list. Corresponds to the {@code aud} claim.
	 *
	 * @param audList The audience list, {@code null} if not specified.
	 */
	public void setAudience(final List<Audience> audList) {
		
		if (audList != null)
			setClaim(AUD_CLAIM_NAME, Audience.toStringList(audList));
		else
			setClaim(AUD_CLAIM_NAME, null);
	}


	/**
	 * Gets the JSON object representation of this claims set.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "country"       : "USA",
	 *   "country#en"    : "USA",
	 *   "country#de_DE" : "Vereinigte Staaten",
	 *   "country#fr_FR" : "Etats Unis"
	 * }
	 * </pre>
	 *
	 * @return The JSON object representation.
	 */
	public JSONObject toJSONObject() {
		
		JSONObject out = new JSONObject();
		out.putAll(claims);
		return out;
	}
	
	
	@Override
	public String toJSONString() {
		return toJSONObject().toJSONString();
	}


	/**
	 * Gets the JSON Web Token (JWT) claims set for this claim set.
	 *
	 * @return The JWT claims set.
	 *
	 * @throws ParseException If the conversion to a JWT claims set fails.
	 */
	public JWTClaimsSet toJWTClaimsSet()
		throws ParseException {

		try {
			// Parse from JSON string to handle nested JSONArray & JSONObject properly
			// Work around https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/347/revise-nested-jsonarray-and-jsonobject
			return JWTClaimsSet.parse(claims.toJSONString());

		} catch (java.text.ParseException e) {

			throw new ParseException(e.getMessage(), e);
		}
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof ClaimsSet)) return false;
		ClaimsSet claimsSet = (ClaimsSet) o;
		return claims.equals(claimsSet.claims);
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(claims);
	}
}
