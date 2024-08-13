/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.oauth2.sdk.ciba;


import java.util.regex.Pattern;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * CIBA request ID ({@code auth_req_id}).
 *
 * <p>Related specifications:
 *
 * <ul>
 *      <li>OpenID Connect CIBA Flow - Core 1.0
 * </ul>
 */
@Immutable
public class AuthRequestID extends Identifier {
	
	
	/**
	 * The minimal required entropy (128 bits or 16 bytes).
	 */
	public static final int MIN_BYTE_LENGTH = 128 / 8;
	
	
	/**
	 * The recommended entropy (160 bits or 20 bytes).
	 */
	public static final int RECOMMENDED_BYTE_LENGTH = 160 / 8;
	
	
	/**
	 * Pattern that matches allowed characters only.
	 */
	public static final Pattern ALLOWED_CHARS_PATTERN = Pattern.compile("^[a-zA-Z0-9\\.\\-_]+$");
	
	
	private static final long serialVersionUID = -484823633025535607L;
	
	
	/**
	 * Creates a new CIBA request ID with a randomly generated 160-bit
	 * (20-byte) value (the {@link #RECOMMENDED_BYTE_LENGTH recommended
	 * length}), Base64URL-encoded.
	 */
	public AuthRequestID() {
		super(RECOMMENDED_BYTE_LENGTH);
	}
	
	
	/**
	 * Creates a new CIBA request ID with a randomly generated value of the
	 * specified byte length, Base64URL-encoded.
	 *
	 * @param byteLength The byte length of the value to generate. Must be
	 *                   at least {@link #MIN_BYTE_LENGTH 128 bits (16
	 *                   bytes) long}.
	 */
	public AuthRequestID(final int byteLength) {
		super(byteLength);
		if (byteLength < MIN_BYTE_LENGTH) {
			throw new IllegalArgumentException("The CIBA request ID must be at least " + MIN_BYTE_LENGTH + " bits long");
		}
	}
	
	
	/**
	 * Creates a new CIBA request ID with the specified value.
	 *
	 * @param value The CIBA request ID value. Must contain only
	 *              {@link #ALLOWED_CHARS_PATTERN legal characters} only
	 *              and not be {@code null} or empty string.
	 */
	public AuthRequestID(final String value) {
		super(value);
		
		if (! ALLOWED_CHARS_PATTERN.matcher(value).matches()) {
			throw new IllegalArgumentException("Illegal character(s) in the auth_req_id value");
		}
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof AuthRequestID && this.toString().equals(object.toString());
	}
	
	
	/**
	 * Parses new CIBA request ID from the specified value.
	 *
	 * @param value The CIBA request ID value.
	 *
	 * @return The CIBA request ID.
	 *
	 * @throws ParseException On a illegal value.
	 */
	public static AuthRequestID parse(final String value)
		throws ParseException {
		
		try {
			return new AuthRequestID(value);
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage());
		}
	}
}
