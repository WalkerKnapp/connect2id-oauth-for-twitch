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


import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import net.jcip.annotations.Immutable;

import java.util.*;


/**
 * Resource owner password credentials grant. Used in access token requests
 * with the resource owner's username and password.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749)
 * </ul>
 */
@Immutable
public class ResourceOwnerPasswordCredentialsGrant extends AuthorizationGrant {


	/**
	 * The grant type.
	 */
	public static final GrantType GRANT_TYPE = GrantType.PASSWORD;


	/**
	 * The username.
	 */
	private final String username;


	/**
	 * The password.
	 */
	private final Secret password;


	/**
	 * Creates a new resource owner password credentials grant.
	 *
	 * @param username The resource owner's username. Must not be
	 *                 {@code null}.
	 * @param password The resource owner's password. Must not be
	 *                 {@code null}.
	 */
	public ResourceOwnerPasswordCredentialsGrant(final String username,
						     final Secret password) {

		super(GRANT_TYPE);
		this.username = Objects.requireNonNull(username);
		this.password = Objects.requireNonNull(password);
	}


	/**
	 * Gets the resource owner's username.
	 *
	 * @return The username.
	 */
	public String getUsername() {

		return username;
	}


	/**
	 * Gets the resource owner's password.
	 *
	 * @return The password.
	 */
	public Secret getPassword() {

		return password;
	}


	@Override
	public Map<String,List<String>> toParameters() {

		Map<String,List<String>> params = new LinkedHashMap<>();
		params.put("grant_type", Collections.singletonList(GRANT_TYPE.getValue()));
		params.put("username", Collections.singletonList(username));
		params.put("password", Collections.singletonList(password.getValue()));
		return params;
	}


	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		ResourceOwnerPasswordCredentialsGrant that = (ResourceOwnerPasswordCredentialsGrant) o;
		if (!username.equals(that.username)) return false;
		return password.equals(that.password);
	}


	@Override
	public int hashCode() {
		int result = username.hashCode();
		result = 31 * result + password.hashCode();
		return result;
	}


	/**
	 * Parses a resource owner password credentials grant from the
	 * specified request body parameters.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * grant_type=password
	 * username=johndoe
	 * password=A3ddj3w
	 * </pre>
	 *
	 * @param params The parameters.
	 *
	 * @return The resource owner password credentials grant.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ResourceOwnerPasswordCredentialsGrant parse(final Map<String,List<String>> params)
		throws ParseException {
		
		GrantType.ensure(GRANT_TYPE, params);

		// Parse the username
		String username = MultivaluedMapUtils.getFirstValue(params, "username");

		if (username == null || username.trim().isEmpty()) {
			String msg = "Missing or empty username parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
		}

		// Parse the password
		String passwordString = MultivaluedMapUtils.getFirstValue(params, "password");

		if (passwordString == null || passwordString.trim().isEmpty()) {
			String msg = "Missing or empty password parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
		}

		Secret password = new Secret(passwordString);

		return new ResourceOwnerPasswordCredentialsGrant(username, password);
	}
}
