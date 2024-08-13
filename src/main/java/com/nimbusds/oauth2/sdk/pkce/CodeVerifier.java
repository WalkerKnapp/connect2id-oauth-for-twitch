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

package com.nimbusds.oauth2.sdk.pkce;


import com.nimbusds.oauth2.sdk.auth.Secret;


/**
 * Authorisation code verifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Proof Key for Code Exchange by OAuth Public Clients (RFC 7636)
 * </ul>
 */
public class CodeVerifier extends Secret {
	
	
	private static final long serialVersionUID = 1L;
	
	
	/**
	 * The minimum character length of a code verifier.
	 */
	public static final int MIN_LENGTH = 43;
	
	
	/**
	 * The maximum character length of a code verifier.
	 */
	public static final int MAX_LENGTH = 128;
	
	
	/**
	 * Creates a new code verifier with the specified value.
	 *
	 * @param value The code verifier value. Must not contain characters
	 *              other than [A-Z] / [a-z] / [0-9] / "-" / "." / "_" /
	 *              "~". The verifier length must be at least 43
	 *              characters but not more than 128 characters. Must not
	 *              be {@code null} or empty string.
	 */
	public CodeVerifier(final String value) {
		super(value);

		if (value.length() < MIN_LENGTH) {
			throw new IllegalArgumentException("The code verifier must be at least " + MIN_LENGTH + " characters");
		}

		if (value.length() > MAX_LENGTH) {
			throw new IllegalArgumentException("The code verifier must not be longer than " + MAX_LENGTH + " characters");
		}

		if (! isLegal(value)) {
			throw new IllegalArgumentException("Illegal char(s) in code verifier, see RFC 7636, section 4.1");
		}
	}


	/**
	 * Generates a new code verifier represented by a secure random 256-bit
	 * number that is Base64URL-encoded (as a 43 character string, which is
	 * the {@link #MIN_LENGTH minimum character length} of a code
	 * verifier).
	 */
	public CodeVerifier() {
		super(32);
	}


	@Override
	public boolean equals(final Object object) {
		return object instanceof CodeVerifier && super.equals(object);
	}
	
	
	/**
	 * Returns {@code true} if the specified string is legal for a code
	 * verifier.
	 *
	 * @param s The string, {@code null} if not specified.
	 *
	 * @return {@code true} if legal or {@code null}, {@code false} if
	 *         illegal.
	 */
	static boolean isLegal(final String s) {

		if (s == null) {
			return true;
		}

		for (char c : s.toCharArray()) {
			if (!isLegal(c)) {
				return false;
			}
		}

		return true;
	}
	
	/**
	 * Returns {@code true} if the specified character is legal for a code
	 * verifier.
	 *
	 * @param c The character.
	 *
	 * @return {@code true} if legal, {@code false} if illegal.
	 */
	static boolean isLegal(final char c) {

		// https://tools.ietf.org/html/rfc7636#page-8
		//
		// ABNF for "code_verifier" is as follows.
		//
		// code-verifier = 43*128unreserved
		// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
		// ALPHA = %x41-5A / %x61-7A
		// DIGIT = %x30-39

		if (c > 0x7f) {
			// Not ASCII
			return false;
		}

		return c >= 0x41 && c <= 0x5a || c >= 0x61 && c <= 0x7a || c >= 0x30 && c <= 0x39 || c == '-' || c == '.' || c == '_' || c == '~';
	}
}
