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

package com.nimbusds.openid.connect.sdk.validators;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.openid.connect.sdk.claims.CodeHash;
import net.jcip.annotations.ThreadSafe;


/**
 * Authorisation code validator, using the {@code c_hash} ID token claim.
 * Required in the hybrid flow where the authorisation code is returned
 * together with an ID token at the authorisation endpoint.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 * </ul>
 */
@ThreadSafe
public class AuthorizationCodeValidator {
	

	/**
	 * Validates the specified authorisation code.
	 *
	 * @param code         The authorisation code. Must not be
	 *                     {@code null}.
	 * @param jwsAlgorithm The JWS algorithm of the ID token. Must not
	 *                     be {@code null}.=
	 * @param codeHash     The authorisation code hash, as set in the
	 *                     {@code c_hash} ID token claim. Must not be
	 *                     {@code null}.
	 *
	 * @throws InvalidHashException If the authorisation code doesn't match
	 *                              the hash.
	 */
	public static void validate(final AuthorizationCode code,
				    final JWSAlgorithm jwsAlgorithm,
				    final CodeHash codeHash)
		throws InvalidHashException {

		CodeHash expectedHash = CodeHash.compute(code, jwsAlgorithm);

		if (expectedHash == null) {
			throw InvalidHashException.INVALID_CODE_HASH_EXCEPTION;
		}

		if (! expectedHash.equals(codeHash)) {
			throw InvalidHashException.INVALID_CODE_HASH_EXCEPTION;
		}
	}
}
