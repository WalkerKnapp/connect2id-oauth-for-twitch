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


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Authorisation code challenge.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Proof Key for Code Exchange by OAuth Public Clients (RFC 7636)
 * </ul>
 */
public class CodeChallenge extends Identifier {
	
	
	private static final long serialVersionUID = 1353706942392517197L;
	
	
	/**
	 * Creates a new code challenge with the specified value.
	 *
	 * @param value The code challenge value. Must not be {@code null} or
	 *              empty string.
	 */
	private CodeChallenge(final String value) {
		super(value);
	}


	/**
	 * Computes the code challenge using the specified method and verifier.
	 *
	 * @param method       The code challenge method. Must be supported and
	 *                     not {@code null}.
	 * @param codeVerifier The code verifier. Must not be {@code null}.
	 *
	 * @return The computed code challenge.
	 */
	public static CodeChallenge compute(final CodeChallengeMethod method, final CodeVerifier codeVerifier) {

		if (CodeChallengeMethod.PLAIN.equals(method)) {
			return new CodeChallenge(codeVerifier.getValue());
		}

		if (CodeChallengeMethod.S256.equals(method)) {

			MessageDigest md;

			try {
				md = MessageDigest.getInstance("SHA-256");
			} catch (NoSuchAlgorithmException e) {
				throw new IllegalStateException(e.getMessage());
			}

			byte[] hash = md.digest(codeVerifier.getValueBytes());

			return new CodeChallenge(Base64URL.encode(hash).toString());
		}

		throw new IllegalArgumentException("Unsupported code challenge method: " + method);
	}
	
	
	/**
	 * Parses a code challenge from the specified string.
	 *
	 * @param value The code challenge value.
	 *
	 * @return The code challenge.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static CodeChallenge parse(final String value)
		throws ParseException {
		
		try {
			return new CodeChallenge(value);
		} catch (IllegalArgumentException e) {
			throw new ParseException("Invalid code challenge: " + e.getMessage(), e);
		}
	}
}
