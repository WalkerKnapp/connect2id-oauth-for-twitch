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

package com.nimbusds.oauth2.sdk;


/**
 * Assertion grant. Used in access token requests with an assertion, such as a
 * SAML 2.0 assertion or JSON Web Token (JWT).
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Assertion Framework for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7521)
 * </ul>
 */
public abstract class AssertionGrant extends AuthorizationGrant {
	
	
	private static final String MISSING_ASSERTION_PARAM_MESSAGE = "Missing or empty assertion parameter";


	/**
	 * Caches missing {@code assertion} parameter exception.
	 */
	protected static final ParseException MISSING_ASSERTION_PARAM_EXCEPTION
		= new ParseException(MISSING_ASSERTION_PARAM_MESSAGE,
			OAuth2Error.INVALID_REQUEST.appendDescription(": " + MISSING_ASSERTION_PARAM_MESSAGE));


	/**
	 * Creates a new assertion-based authorisation grant.
	 *
	 * @param type The authorisation grant type. Must not be {@code null}.
	 */
	protected AssertionGrant(final GrantType type) {

		super(type);
	}


	/**
	 * Gets the assertion.
	 *
	 * @return The assertion as a string.
	 */
	public abstract String getAssertion();
}
