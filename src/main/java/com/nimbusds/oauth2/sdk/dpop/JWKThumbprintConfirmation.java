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

package com.nimbusds.oauth2.sdk.dpop;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.cnf.AbstractConfirmation;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import java.util.AbstractMap;
import java.util.Map;
import java.util.Objects;


/**
 * JSON Web Key (JWK) SHA-256 thumbprint confirmation.
 */
@Immutable
public final class JWKThumbprintConfirmation extends AbstractConfirmation {
	
	
	/**
	 * The JWK SHA-256 thumbprint.
	 */
	private final Base64URL jkt;
	
	
	/**
	 * Creates a new JWK SHA-256 thumbprint.
	 *
	 * @param jkt The JWK SHA-256 thumbprint. Must not be {@code null}.
	 */
	public JWKThumbprintConfirmation(final Base64URL jkt) {
		this.jkt = Objects.requireNonNull(jkt);
	}
	
	
	/**
	 * Returns the JWK SHA-256 thumbprint.
	 *
	 * @return The JWK SHA-256 thumbprint.
	 */
	public Base64URL getValue() {
		
		return jkt;
	}
	
	
	@Override
	public Map.Entry<String,JSONObject> toJWTClaim() {
		
		JSONObject cnf = new JSONObject();
		cnf.put("jkt", jkt.toString());
		
		return new AbstractMap.SimpleImmutableEntry<>(
			"cnf",
			cnf
		);
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof JWKThumbprintConfirmation)) return false;
		JWKThumbprintConfirmation that = (JWKThumbprintConfirmation) o;
		return jkt.equals(that.jkt);
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(jkt);
	}
	
	
	/**
	 * Parses a JWK SHA-256 thumbprint confirmation from the specified JWT
	 * claims set.
	 *
	 * @param jwtClaimsSet The JWT claims set.
	 *
	 * @return The JWK SHA-256 thumbprint confirmation, {@code null} if not
	 *         found.
	 */
	public static JWKThumbprintConfirmation parse(final JWTClaimsSet jwtClaimsSet) {
		
		JSONObject cnf = parseConfirmationJSONObject(jwtClaimsSet);
		
		if (cnf == null) {
			return null;
		}
		
		return parseFromConfirmationJSONObject(cnf);
	}
	
	
	/**
	 * Parses a JWK SHA-256 thumbprint confirmation from the specified JSON
	 * object representation of a JWT claims set.
	 *
	 * @param jsonObject The JSON object.
	 *
	 * @return The JWK SHA-256 thumbprint confirmation, {@code null} if not
	 *         found.
	 */
	public static JWKThumbprintConfirmation parse(final JSONObject jsonObject) {
		
		if (! jsonObject.containsKey("cnf")) {
			return null;
		}
		
		try {
			return parseFromConfirmationJSONObject(JSONObjectUtils.getJSONObject(jsonObject, "cnf"));
		} catch (ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Parses a JWK SHA-256 thumbprint confirmation from the specified
	 * confirmation ("cnf") JSON object.
	 *
	 * @param cnf The confirmation JSON object, {@code null} if none.
	 *
	 * @return The JWK SHA-256 thumbprint confirmation, {@code null} if not
	 *         found.
	 */
	public static JWKThumbprintConfirmation parseFromConfirmationJSONObject(final JSONObject cnf) {
		
		if (cnf == null) {
			return null;
		}
		
		try {
			String jktString = JSONObjectUtils.getString(cnf, "jkt");
			return new JWKThumbprintConfirmation(new Base64URL(jktString));
		} catch (ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Creates a confirmation of the specified JWK.
	 *
	 * @param jwk The JWK.
	 *
	 * @return The JWK SHA-256 thumbprint confirmation.
	 *
	 * @throws JOSEException If the thumbprint computation failed.
	 */
	public static JWKThumbprintConfirmation of(final JWK jwk)
		throws JOSEException {
		
		return new JWKThumbprintConfirmation(jwk.computeThumbprint());
	}
}
