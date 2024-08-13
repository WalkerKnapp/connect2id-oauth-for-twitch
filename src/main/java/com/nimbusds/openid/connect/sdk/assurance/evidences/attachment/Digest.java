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

package com.nimbusds.openid.connect.sdk.assurance.evidences.attachment;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * Cryptographic digest.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
@Immutable
public final class Digest {
	
	
	/**
	 * The hash algorithm.
	 */
	private final HashAlgorithm alg;
	
	
	/**
	 * The hash value.
	 */
	private final Base64 value;
	
	
	/**
	 * Creates a new cryptographic digest.
	 *
	 * @param alg   The hash algorithm. Must not be {@code null}.
	 * @param value The hash value. Must not be {@code null}.
	 */
	public Digest(final HashAlgorithm alg, final Base64 value) {
		Objects.requireNonNull(alg);
		this.alg = alg;
		Objects.requireNonNull(value);
		this.value = value;
	}
	
	
	/**
	 * Returns the hash algorithm.
	 *
	 * @return The hash algorithm.
	 */
	public HashAlgorithm getHashAlgorithm() {
		return alg;
	}
	
	
	/**
	 * Returns the hash value.
	 *
	 * @return the hash value.
	 */
	public Base64 getValue() {
		return value;
	}
	
	
	/**
	 * Returns {@code true} if this digest matches the computed for the
	 * specified content.
	 *
	 * @param content The content. Must not be {@code null}.
	 *
	 * @return If {@code true} if the digest matches the content, else
	 *         {@code false}.
	 *
	 * @throws NoSuchAlgorithmException If the hash algorithm isn't
	 *                                  supported.
	 */
	public boolean matches(final Base64 content)
		throws NoSuchAlgorithmException {
		
		Digest computed = Digest.compute(getHashAlgorithm(), content);
		return this.equals(computed);
	}
	
	
	/**
	 * Returns a JSON object representation of this cryptographic digest.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("alg", getHashAlgorithm().getValue());
		jsonObject.put("value", getValue().toString());
		return jsonObject;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof Digest)) return false;
		Digest digest = (Digest) o;
		return alg.equals(digest.alg) && getValue().equals(digest.getValue());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(alg, getValue());
	}
	
	
	/**
	 * Computes the digest for the specified content.
	 *
	 * @param alg     The hash algorithm. Must not be {@code null}.
	 * @param content The content. Must not be {@code null}.
	 *
	 * @return The digest.
	 *
	 * @throws NoSuchAlgorithmException If the hash algorithm isn't
	 *                                  supported.
	 */
	public static Digest compute(final HashAlgorithm alg, final Base64 content)
		throws NoSuchAlgorithmException {
		
		return compute(alg, content.decode());
	}
	
	
	/**
	 * Computes the digest for the specified content.
	 *
	 * @param alg     The hash algorithm. Must not be {@code null}.
	 * @param content The content. Must not be {@code null}.
	 *
	 * @return The digest.
	 *
	 * @throws NoSuchAlgorithmException If the hash algorithm isn't
	 *                                  supported.
	 */
	public static Digest compute(final HashAlgorithm alg, final byte[] content)
		throws NoSuchAlgorithmException {
		
		MessageDigest md = MessageDigest.getInstance(alg.getValue().toUpperCase());
		byte[] hash = md.digest(content);
		return new Digest(alg, Base64.encode(hash));
	}
	
	
	/**
	 * Parses a digest from the specified JSON object.
	 *
	 * @param jsonObject The JSON object.
	 *
	 * @return The cryptographic digest.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static Digest parse(final JSONObject jsonObject)
		throws ParseException {
		
		HashAlgorithm alg = new HashAlgorithm(JSONObjectUtils.getString(jsonObject, "alg"));
		Base64 value = new Base64(JSONObjectUtils.getString(jsonObject, "value"));
		return new Digest(alg, value);
	}
}
