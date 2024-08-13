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

package com.nimbusds.openid.connect.sdk;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ResponseType;


/**
 * OpenID Connect {@link #ID_TOKEN id_token} response type value constant.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices
 *     <li>OAuth 2.0 (RFC 6749)
 * </ul>
 */
@Immutable
public class OIDCResponseTypeValue {

	
	/**
	 * ID Token response type.
	 */
	public static final ResponseType.Value ID_TOKEN = new ResponseType.Value("id_token");


	/**
	 * None response type, should not be combined with other response type
	 * values.
	 */
	public static final ResponseType.Value NONE = new ResponseType.Value("none");


	/**
	 * Prevents public instantiation.
	 */
	private OIDCResponseTypeValue() { }
}
