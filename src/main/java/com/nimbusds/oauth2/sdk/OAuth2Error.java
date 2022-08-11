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


import com.nimbusds.oauth2.sdk.http.HTTPResponse;


/**
 * Standard OAuth 2.0 authorisation and token endpoint errors.
 *
 * <p>The set HTTP status code is ignored for authorisation errors passed by
 * HTTP redirection. Errors that are only used by at the authorisation endpoint
 * are supplied with a matching HTTP status code in case they are used in a
 * different context.
 */
public final class OAuth2Error {


	// Common OAuth 2.0 authorisation errors

	/**
	 * The {@link OAuth2Error#INVALID_REQUEST} error code string.
	 */
	public static final String INVALID_REQUEST_CODE = "invalid_request";

	/**
	 * The request is missing a required parameter, includes an invalid 
	 * parameter, or is otherwise malformed.
	 */
	public static final ErrorObject INVALID_REQUEST = 
		new ErrorObject(INVALID_REQUEST_CODE, "Invalid request", HTTPResponse.SC_BAD_REQUEST);

	/**
	 * The {@link OAuth2Error#UNAUTHORIZED_CLIENT} error code string.
	 */
	public static final String UNAUTHORIZED_CLIENT_CODE = "unauthorized_client";

	/**
	 * The client is not authorised to request an authorisation code using 
	 * this method.
	 */
	public static final ErrorObject UNAUTHORIZED_CLIENT =
		new ErrorObject(UNAUTHORIZED_CLIENT_CODE, "Unauthorized client", HTTPResponse.SC_BAD_REQUEST);

	/**
	 * The {@link OAuth2Error#ACCESS_DENIED} error code string.
	 */
	public static final String ACCESS_DENIED_CODE = "access_denied";

	/**
	 * The resource owner or authorisation server denied the request.
	 */
	public static final ErrorObject ACCESS_DENIED =
		new ErrorObject(ACCESS_DENIED_CODE, "Access denied by resource owner or authorization server", HTTPResponse.SC_FORBIDDEN);

	/**
	 * The {@link OAuth2Error#UNSUPPORTED_RESPONSE_TYPE} error code string.
	 */
	public static final String UNSUPPORTED_RESPONSE_TYPE_CODE = "unsupported_response_type";

	/**
	 * The authorisation server does not support obtaining an authorisation 
	 * code using this method.
	 */
	public static final ErrorObject UNSUPPORTED_RESPONSE_TYPE =
		new ErrorObject(UNSUPPORTED_RESPONSE_TYPE_CODE, "Unsupported response type", HTTPResponse.SC_BAD_REQUEST);

	/**
	 * The {@link OAuth2Error#INVALID_SCOPE} error code string.
	 */
	public static final String INVALID_SCOPE_CODE = "invalid_scope";

	/**
	 * The requested scope is invalid, unknown, or malformed.
	 */
	public static final ErrorObject INVALID_SCOPE =
		new ErrorObject(INVALID_SCOPE_CODE, "Invalid, unknown or malformed scope", HTTPResponse.SC_BAD_REQUEST);

	/**
	 * The {@link OAuth2Error#SERVER_ERROR} error code string.
	 */
	public static final String SERVER_ERROR_CODE = "server_error";

	/**
	 * The authorisation server encountered an unexpected condition which 
	 * prevented it from fulfilling the request.
	 */
	public static final ErrorObject SERVER_ERROR =
		new ErrorObject(SERVER_ERROR_CODE, "Unexpected server error", HTTPResponse.SC_SERVER_ERROR);

	/**
	 * The {@link OAuth2Error#TEMPORARILY_UNAVAILABLE} error code string.
	 */
	public static final String TEMPORARILY_UNAVAILABLE_CODE = "temporarily_unavailable";

	/**
	 * The authorisation server is currently unable to handle the request 
	 * due to a temporary overloading or maintenance of the server.
	 */
	public static final ErrorObject TEMPORARILY_UNAVAILABLE =
		new ErrorObject(TEMPORARILY_UNAVAILABLE_CODE, "The authorization server is temporarily unavailable", HTTPResponse.SC_SERVICE_UNAVAILABLE);
	
	
	// Token, Base OAuth 2.0 authorisation errors, section 5.2
	/**
	 * The {@link OAuth2Error#INVALID_CLIENT} error code string.
	 */
	public static final String INVALID_CLIENT_CODE = "invalid_client";

	/**
	 * Client authentication failed (e.g. unknown client, no client 
	 * authentication included, or unsupported authentication method).
	 */
	public static final ErrorObject INVALID_CLIENT =
		new ErrorObject(INVALID_CLIENT_CODE, "Client authentication failed", HTTPResponse.SC_UNAUTHORIZED);

	/**
	 * The {@link OAuth2Error#INVALID_GRANT} error code string.
	 */
	public static final String INVALID_GRANT_CODE = "invalid_grant";

	/**
	 * The provided authorisation grant (e.g. authorisation code, resource 
	 * owner credentials) or refresh token is invalid, expired, revoked, 
	 * does not match the redirection URI used in the authorization request,
	 * or was issued to another client.
	 */
	public static final ErrorObject INVALID_GRANT =
		new ErrorObject(INVALID_GRANT_CODE, "Invalid grant", HTTPResponse.SC_BAD_REQUEST);

	/**
	 * The {@link OAuth2Error#UNSUPPORTED_GRANT_TYPE} error code string.
	 */
	public static final String UNSUPPORTED_GRANT_TYPE_CODE = "unsupported_grant_type";

	/**
	 * The authorisation grant type is not supported by the authorisation 
	 * server.
	 */
	public static final ErrorObject UNSUPPORTED_GRANT_TYPE =
		new ErrorObject(UNSUPPORTED_GRANT_TYPE_CODE, "Unsupported grant type", HTTPResponse.SC_BAD_REQUEST);

	/**
	 * The {@link OAuth2Error#INVALID_REQUEST_URI} error code string.
	 */
	public static final String INVALID_REQUEST_URI_CODE = "invalid_request_uri";

	/**
	 * The {@code request_uri} in the {@link AuthorizationRequest}
	 * returns an error or invalid data.
	 */
	public static final ErrorObject INVALID_REQUEST_URI =
		new ErrorObject(INVALID_REQUEST_URI_CODE, "Invalid request URI", HTTPResponse.SC_FOUND);

	/**
	 * The {@link OAuth2Error#INVALID_REQUEST_OBJECT} error code string.
	 */
	public static final String INVALID_REQUEST_OBJECT_CODE = "invalid_request_object";

	/**
	 * The {@code request} parameter in the {@link AuthorizationRequest}
	 * contains an invalid request object.
	 */
	public static final ErrorObject	INVALID_REQUEST_OBJECT =
		new ErrorObject(INVALID_REQUEST_OBJECT_CODE, "Invalid request JWT", HTTPResponse.SC_FOUND);

	/**
	 * The {@link OAuth2Error#REQUEST_URI_NOT_SUPPORTED} error code string.
	 */
	public static final String REQUEST_URI_NOT_SUPPORTED_CODE = "request_uri_not_supported";

	/**
	 * The {@code request_uri} parameter in the
	 * {@link AuthorizationRequest} is not supported.
	 */
	public static final ErrorObject REQUEST_URI_NOT_SUPPORTED =
		new ErrorObject(REQUEST_URI_NOT_SUPPORTED_CODE, "Request URI parameter not supported", HTTPResponse.SC_FOUND);

	/**
	 * The {@link OAuth2Error#REQUEST_NOT_SUPPORTED} error code string.
	 */
	public static final String REQUEST_NOT_SUPPORTED_CODE = "request_not_supported";

	/**
	 * The {@code request} parameter in the {@link AuthorizationRequest} is
	 * not supported.
	 */
	public static final ErrorObject REQUEST_NOT_SUPPORTED =
		new ErrorObject(REQUEST_NOT_SUPPORTED_CODE, "Request parameter not supported", HTTPResponse.SC_FOUND);

	/**
	 * The {@link OAuth2Error#INVALID_RESOURCE} error code string.
	 * @see #INVALID_TARGET_CODE
	 */
	@Deprecated
	public static final String INVALID_RESOURCE_CODE = "invalid_resource";

	/**
	 * The specified resource server URI is not valid or accepted by the
	 * authorisation server. @see #INVALID_TARGET
	 */
	@Deprecated
	public static final ErrorObject INVALID_RESOURCE =
		new ErrorObject(INVALID_RESOURCE_CODE, "Invalid or unaccepted resource", HTTPResponse.SC_BAD_REQUEST);

	/**
	 * The {@link OAuth2Error#INVALID_RESOURCE} error code string.
	 */
	public static final String INVALID_TARGET_CODE = "invalid_target";

	
	/**
	 * The specified resource server URI is not valid or accepted by the
	 * authorisation server.
	 */
	public static final ErrorObject INVALID_TARGET =
		new ErrorObject(INVALID_TARGET_CODE, "Invalid or unaccepted resource", HTTPResponse.SC_BAD_REQUEST);

	/**
	 * The {@link OAuth2Error#OVERBROAD_SCOPE} error code string.
	 */
	public static final String OVERBROAD_SCOPE_CODE = "overbroad_scope";

	/**
	 * The scope of the request is considered overbroad by the
	 * authorisation server.
	 */
	public static final ErrorObject OVERBROAD_SCOPE =
		new ErrorObject(OVERBROAD_SCOPE_CODE, "Overbroad scope", HTTPResponse.SC_BAD_REQUEST);
	
	
	/**
	 * The {@link OAuth2Error#INVALID_DPOP_PROOF} error code string.
	 */
	public static final String INVALID_DPOP_PROOF_CODE = "invalid_dpop_proof";
	
	
	/**
	 * The DPoP proof received by the authorisation server is invalid.
	 */
	public static final ErrorObject INVALID_DPOP_PROOF =
		new ErrorObject(INVALID_DPOP_PROOF_CODE, "Invalid DPoP proof", HTTPResponse.SC_BAD_REQUEST);
	
	
	// OpenID Connect Federation 1.0

	/**
	 * The {@link OAuth2Error#MISSING_TRUST_ANCHOR} error code string.
	 */
	public static final String MISSING_TRUST_ANCHOR_CODE = "missing_trust_anchor";

	/**
	 * No trusted anchor could be found to process an OpenID Connect
	 * Federation 1.0 authorisation request using automatic client
	 * registration.
	 */
	public static final ErrorObject MISSING_TRUST_ANCHOR =
		new ErrorObject(MISSING_TRUST_ANCHOR_CODE, "No trusted anchor could be found", HTTPResponse.SC_BAD_REQUEST);

	/**
	 * The {@link OAuth2Error#VALIDATION_FAILED} error code string.
	 */
	public static final String VALIDATION_FAILED_CODE = "validation_failed";

	/**
	 * The trust chain validation for an OpenID Connect Federation 1.0
	 * authorisation request using automatic client registration failed.
	 */
	public static final ErrorObject VALIDATION_FAILED =
		new ErrorObject(VALIDATION_FAILED_CODE, "Trust chain validation failed", HTTPResponse.SC_BAD_REQUEST);
	
	
	/**
	 * Prevents public instantiation.
	 */
	private OAuth2Error() { }
}