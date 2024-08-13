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

package com.nimbusds.oauth2.sdk.ciba;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * CIBA specific errors.
 *
 * <p>Related specifications:
 *
 * <ul>
 *      <li>OpenID Connect CIBA Flow - Core 1.0
 * </ul>
 */
public final class CIBAError {
	
	
	/**
	 * The {@code login_hint_token} provided in the CIBA request is not
	 * valid because it has expired.
	 */
	public static final ErrorObject EXPIRED_LOGIN_HINT_TOKEN = new ErrorObject(
		"expired_login_hint_token",
		"Expired login_hint_token",
		HTTPResponse.SC_BAD_REQUEST);
	
	
	/**
	 * The OpenID provider / OAuth 2.0 authorisation server is not able to
	 * identify the end-user by means of the {@code login_hint_token},
	 * {@code id_token_hint} or {@code login_hint} in the provided in the
	 * request.
	 */
	public static final ErrorObject UNKNOWN_USER_ID = new ErrorObject(
		"unknown_user_id",
		"Unknown user ID",
		HTTPResponse.SC_BAD_REQUEST);
	
	
	/**
	 * A secret {@code user_code} is required but was missing from the
	 * request.
	 */
	public static final ErrorObject MISSING_USER_CODE = new ErrorObject(
		"missing_user_code",
		"Required user_code is missing",
		HTTPResponse.SC_BAD_REQUEST);
	
	
	/**
	 * The secret {@code user_code} was invalid.
	 */
	public static final ErrorObject INVALID_USER_CODE = new ErrorObject(
		"invalid_user_code",
		"Invalid user_code",
		HTTPResponse.SC_BAD_REQUEST);
	
	
	/**
	 * The binding message ({@code binding_message}) is invalid or
	 * unacceptable in the given request context.
	 */
	public static final ErrorObject INVALID_BINDING_MESSAGE = new ErrorObject(
		"invalid_binding_message",
		"Invalid or unacceptable binding_message",
		HTTPResponse.SC_BAD_REQUEST);
	
	
	/**
	 * The {@code auth_req_id} has expired.
	 */
	public static final ErrorObject EXPIRED_TOKEN = new ErrorObject(
		"expired_token",
		"The auth_req_id has expired",
		0);
	
	
	/**
	 * The transaction failed due to an unexpected condition.
	 */
	public static final ErrorObject TRANSACTION_FAILED = new ErrorObject(
		"transaction_failed",
		"The transaction failed due to an unexpected condition",
		0);
	
	
	/**
	 * Prevents public instantiation.
	 */
	private CIBAError() { }
}
