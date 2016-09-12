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


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Authorisation response mode.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices 1.0.
 *     <li>OAuth 2.0 Form Post Response Mode 1.0.
 * </ul>
 */
@Immutable
public final class ResponseMode extends Identifier {


	/**
	 * The authorisation response parameters are encoded in the query
	 * string added to the {@code redirect_uri} when redirecting back to
	 * the client.
	 */
	public static final ResponseMode QUERY = new ResponseMode("query");


	/**
	 * The authorisation response parameters are encoded in the fragment
	 * added to the {@code redirect_uri} when redirecting back to the
	 * client.
	 */
	public static final ResponseMode FRAGMENT = new ResponseMode("fragment");


	/**
	 * The authorisation response parameters are encoded as HTML form
	 * values that are auto-submitted in the User Agent, and thus are
	 * transmitted via the HTTP POST method to the client, with the result
	 * parameters being encoded in the body using the
	 * {@code application/x-www-form-urlencoded} format. The action
	 * attribute of the form MUST be the client's redirection URI. The
	 * method of the form attribute MUST be POST.
	 */
	public static final ResponseMode FORM_POST = new ResponseMode("form_post");


	/**
	 * Creates a new authorisation response mode with the specified value.
	 *
	 * @param value The response mode value. Must not be {@code null}.
	 */
	public ResponseMode(final String value) {

		super(value);
	}


	@Override
	public boolean equals(final Object object) {

		return object instanceof ResponseMode &&
			this.toString().equals(object.toString());
	}
}
