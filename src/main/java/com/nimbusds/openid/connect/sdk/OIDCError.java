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


import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * OpenID Connect specific errors.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 * </ul>
 */
public final class OIDCError {

	
	// Authentication endpoint
	
	
	/**
	 * The {@link OIDCError#INTERACTION_REQUIRED} error code string.
	 */
	public static final String INTERACTION_REQUIRED_CODE = "interaction_required";
	
	
	/**
	 * The authorisation server requires end-user interaction of some form 
	 * to proceed. This error may be returned when the {@link Prompt} 
	 * parameter in the {@link AuthenticationRequest} is set to
	 * {@link Prompt.Type#NONE none} to request that the authorisation 
	 * server should not display any user interfaces to the end-user, but 
	 * the {@link AuthenticationRequest} cannot be completed without
	 * displaying a user interface for end-user interaction.
	 */
	public static final ErrorObject INTERACTION_REQUIRED =
		new ErrorObject(INTERACTION_REQUIRED_CODE, "User interaction required", HTTPResponse.SC_FOUND);
	
	
	/**
	 * The {@link OIDCError#LOGIN_REQUIRED} error code string.
	 */
	public static final String LOGIN_REQUIRED_CODE = "login_required";
	
	
	/**
	 * The authorisation server requires end-user authentication. This 
	 * error may be returned when the prompt parameter in the 
	 * {@link AuthenticationRequest} is set to {@link Prompt.Type#NONE}
	 * to request that the authorisation server should not display any user 
	 * interfaces to the end-user, but the {@link AuthenticationRequest}
	 * cannot be completed without displaying a user interface for user 
	 * authentication.
	 */
	public static final ErrorObject LOGIN_REQUIRED =
		new ErrorObject(LOGIN_REQUIRED_CODE, "Login required", HTTPResponse.SC_FOUND);
	
	
	/**
	 * The {@link OIDCError#ACCOUNT_SELECTION_REQUIRED} error code string.
	 */
	public static final String ACCOUNT_SELECTION_REQUIRED_CODE = "account_selection_required";

	
	/**
	 * The end-user is required to select a session at the authorisation 
	 * server. The end-user may be authenticated at the authorisation 
	 * server with different associated accounts, but the end-user did not 
	 * select a session. This error may be returned when the prompt 
	 * parameter in the {@link AuthenticationRequest} is set to
	 * {@link Prompt.Type#NONE} to request that the authorisation server 
	 * should not display any user interfaces to the end-user, but the 
	 * {@link AuthenticationRequest} cannot be completed without
	 * displaying a user interface to prompt for a session to use.
	 */
	public static final ErrorObject ACCOUNT_SELECTION_REQUIRED =
		new ErrorObject(ACCOUNT_SELECTION_REQUIRED_CODE, "Session selection required", HTTPResponse.SC_FOUND);
	
	
	/**
	 * The {@link OIDCError#CONSENT_REQUIRED} error code string.
	 */
	public static final String CONSENT_REQUIRED_CODE = "consent_required";
	
	
	/**
	 * The authorisation server requires end-user consent. This error may 
	 * be returned when the prompt parameter in the 
	 * {@link AuthenticationRequest} is set to {@link Prompt.Type#NONE}
	 * to request that the authorisation server should not display any 
	 * user interfaces to the end-user, but the 
	 * {@link AuthenticationRequest} cannot be completed without
	 * displaying a user interface for end-user consent.
	 */
	public static final ErrorObject	CONSENT_REQUIRED =
		new ErrorObject(CONSENT_REQUIRED_CODE, "Consent required", HTTPResponse.SC_FOUND);
	
	
	/**
	 * The {@link OIDCError#UNMET_AUTHENTICATION_REQUIREMENTS} error code
	 * string.
	 */
	public static final String UNMET_AUTHENTICATION_REQUIREMENTS_CODE = "unmet_authentication_requirements";
	
	
	/**
	 * The OpenID provider is unable to authenticate the end-user at the
	 * required Authentication Context Class Reference value when
	 * requested with an essential {@code acr} claim. This error code may
	 * also be used in other appropriate cases.
	 */
	public static final ErrorObject UNMET_AUTHENTICATION_REQUIREMENTS =
		new ErrorObject(UNMET_AUTHENTICATION_REQUIREMENTS_CODE, "Unmet authentication requirements", HTTPResponse.SC_FOUND);
	
	
	/**
	 * The {@link OIDCError#REGISTRATION_NOT_SUPPORTED} error code string.
	 */
	public static final String REGISTRATION_NOT_SUPPORTED_CODE = "registration_not_supported";
	
	
	/**
	 * The {@code registration} parameter in the
	 * {@link AuthenticationRequest} is not supported. Applies only to
	 * self-issued OpenID providers.
	 */
	public static final ErrorObject REGISTRATION_NOT_SUPPORTED =
		new ErrorObject(REGISTRATION_NOT_SUPPORTED_CODE, "Registration parameter not supported", HTTPResponse.SC_FOUND);
	
	
	/**
	 * Prevents public instantiation.
	 */
	private OIDCError() { }
}
