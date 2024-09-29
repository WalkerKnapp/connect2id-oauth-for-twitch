/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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


import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import java.util.Map;
import java.util.Objects;


/**
 * Trust mark entry.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, sections 3.1 and 5.3.
 * </ul>
 */
@Immutable
public final class TrustMarkEntry implements Map.Entry<Identifier, SignedJWT> {
	
	
	/**
	 * The trust mark identifier.
	 */
	private final Identifier id;
	
	
	/**
	 * The trust mark.
	 */
	private final SignedJWT trustMark;
	
	
	/**
	 * Creates a new trust mark entry.
	 *
	 * @param id        The identifier. Must not be {@code null}.
	 * @param trustMark The trust mark. Must not be {@code null}.
	 */
	public TrustMarkEntry(final Identifier id, final SignedJWT trustMark) {
		Objects.requireNonNull(id);
		this.id = id;
		Objects.requireNonNull(trustMark);
		if (JWSObject.State.UNSIGNED.equals(trustMark.getState())) {
			throw new IllegalArgumentException("The trust mark must be in a signed state");
		}
		this.trustMark = trustMark;
	}
	
	
	/**
	 * Returns the identifier.
	 *
	 * @return The identifier.
	 */
	public Identifier getID() {
		return id;
	}
	
	
	/**
	 * Returns the trust mark.
	 *
	 * @return The trust mark.
	 */
	public SignedJWT getTrustMark() {
		return trustMark;
	}
	
	
	@Override
	public Identifier getKey() {
		return getID();
	}
	
	
	@Override
	public SignedJWT getValue() {
		return getTrustMark();
	}
	
	
	@Override
	public SignedJWT setValue(SignedJWT signedJWT) {
		throw new UnsupportedOperationException();
	}
	
	
	/**
	 * Returns a JSON object representation of this entry.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		JSONObject o = new JSONObject();
		o.put("id", getID().getValue());
		o.put("trust_mark", getTrustMark().serialize());
		return o;
	}
	
	
	/**
	 * Parses a trust mark entry from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The trust mark entry.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static TrustMarkEntry parse(final JSONObject jsonObject)
		throws ParseException {
		
		String idString = JSONObjectUtils.getNonBlankString(jsonObject, "id");
		String jwtString = JSONObjectUtils.getNonBlankString(jsonObject, "trust_mark");
		try {
			return new TrustMarkEntry(new Identifier(idString), SignedJWT.parse(jwtString));
		} catch (java.text.ParseException e) {
			throw new ParseException(e.getMessage(), e);
		}
	}
}
