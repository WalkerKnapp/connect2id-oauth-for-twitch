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


import java.util.*;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;


/**
 * SAML 2.0 bearer grant. Used in access token requests with a SAML 2.0 bearer
 * assertion.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Assertion Framework for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7521)
 *     <li>SAML 2.0 Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7522)
 * </ul>
 */
@Immutable
public class SAML2BearerGrant extends AssertionGrant {


	/**
	 * The grant type.
	 */
	public static final GrantType GRANT_TYPE = GrantType.SAML2_BEARER;


	/**
	 * The SAML 2.0 assertion.
	 */
	private final Base64URL assertion;


	/**
	 * Creates a new SAML 2.0 bearer assertion grant.
	 *
	 * @param assertion The SAML 2.0 bearer assertion. Must not be
	 *                  {@code null}.
	 */
	public SAML2BearerGrant(final Base64URL assertion) {

		super(GRANT_TYPE);
		this.assertion = Objects.requireNonNull(assertion);
	}


	/**
	 * Gets the SAML 2.0 bearer assertion.
	 *
	 * @return The SAML 2.0 bearer assertion.
	 */
	public Base64URL getSAML2Assertion() {

		return assertion;
	}


	@Override
	public String getAssertion() {

		return assertion.toString();
	}


	@Override
	public Map<String,List<String>> toParameters() {

		Map<String,List<String>> params = new LinkedHashMap<>();
		params.put("grant_type", Collections.singletonList(GRANT_TYPE.getValue()));
		params.put("assertion", Collections.singletonList(assertion.toString()));
		return params;
	}


	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		SAML2BearerGrant that = (SAML2BearerGrant) o;

		return assertion.equals(that.assertion);

	}


	@Override
	public int hashCode() {
		return assertion.hashCode();
	}


	/**
	 * Parses a SAML 2.0 bearer grant from the specified request body
	 * parameters.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Asaml2-
	 * bearer&amp;assertion=PEFzc2VydGlvbiBJc3N1ZUluc3RhbnQ9IjIwMTEtMDU
	 * [...omitted for brevity...]aG5TdGF0ZW1lbnQ-PC9Bc3NlcnRpb24-
	 * </pre>
	 *
	 * @param params The parameters.
	 *
	 * @return The SAML 2.0 bearer grant.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static SAML2BearerGrant parse(final Map<String,List<String>> params)
		throws ParseException {
		
		GrantType.ensure(GRANT_TYPE, params);

		// Parse JWT assertion
		String assertionString = MultivaluedMapUtils.getFirstValue(params, "assertion");

		if (assertionString == null || assertionString.trim().isEmpty())
			throw MISSING_ASSERTION_PARAM_EXCEPTION;

		return new SAML2BearerGrant(new Base64URL(assertionString));
	}
}
