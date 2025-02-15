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


import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import net.jcip.annotations.Immutable;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;


/**
 * OpenID Connect authentication success response. Used to return an
 * authorisation code, access token and / or ID Token at the Authorisation
 * endpoint.
 *
 * <p>Example HTTP response with code and ID Token (code flow):
 *
 * <pre>
 * HTTP/1.1 302 Found
 * Location: https://client.example.org/cb#
 * code=Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk
 * &amp;id_token=eyJhbGciOiJSUzI1NiJ9.ew0KICAgICJpc3MiOiAiaHR0cDovL3Nlc
 * nZlci5leGFtcGxlLmNvbSIsDQogICAgInVzZXJfaWQiOiAiMjQ4Mjg5NzYxMDAxI
 * iwNCiAgICAiYXVkIjogInM2QmhkUmtxdDMiLA0KICAgICJub25jZSI6ICJuLTBTN
 * l9XekEyTWoiLA0KICAgICJleHAiOiAxMzExMjgxOTcwLA0KICAgICJpYXQiOiAxM
 * zExMjgwOTcwLA0KICAgICJjX2hhc2giOiAiTERrdEtkb1FhazNQazBjblh4Q2x0Q
 * mdfckNfM1RLVWI5T0xrNWZLTzl1QSINCn0.D6JxCgpOwlyuK7DPRu5hFOIJRSRDT
 * B7TQNRbOw9Vg9WroDi_XNzaqXCFSDH_YqcE-CBhoxD-Iq4eQL4E2jIjil47u7i68
 * Nheev7d8AJk4wfRimgpDhQX5K8YyGDWrTs7bhsMTPAPVa9bLIBndDZ2mEdmPcmR9
 * mXcwJI3IGF9JOaStYXJXMYWUMCmQARZEKG9JxIYPZNhFsqKe4TYQEmrq2s_HHQwk
 * XCGAmLBdptHY-Zx277qtidojQQFXzbD2Ak1ONT5sFjy3yxPnE87pNVtOEST5GJac
 * O1O88gmvmjNayu1-f5mr5Uc70QC6DjlKem3cUN5kudAQ4sLvFkUr8gkIQ
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 *     <li>OpenID Connect Session Management 1.0
 *     <li>OAuth 2.0 (RFC 6749)
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices 1.0
 *     <li>OAuth 2.0 Form Post Response Mode 1.0
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM)
 *     <li>OAuth 2.0 Authorization Server Issuer Identification (RFC 9207)
 * </ul>
 */
@Immutable
public class AuthenticationSuccessResponse
	extends AuthorizationSuccessResponse
	implements AuthenticationResponse {


	/**
	 * The ID token, if requested.
	 */
	private final JWT idToken;


	/**
	 * The session state, required if session management is supported.
	 */
	private final State sessionState;


	/**
	 * Creates a new OpenID Connect authentication success response.
	 *
	 * @param redirectURI  The requested redirection URI. Must not be
	 *                     {@code null}.
	 * @param code         The authorisation code, {@code null} if not
	 *                     requested.
	 * @param idToken      The ID token (ready for output), {@code null} if
	 *                     not requested.
	 * @param accessToken  The UserInfo access token, {@code null} if not
	 *                     requested.
	 * @param state        The state, {@code null} if not requested.
	 * @param sessionState The session state, {@code null} if session
	 *                     management is not supported.
	 * @param rm           The response mode, {@code null} if not
	 *                     specified.
	 */
	public AuthenticationSuccessResponse(final URI redirectURI,
					     final AuthorizationCode code,
					     final JWT idToken,
					     final AccessToken accessToken,
					     final State state,
					     final State sessionState,
					     final ResponseMode rm) {

		this(redirectURI, code, idToken, accessToken, state, sessionState, null, rm);
	}


	/**
	 * Creates a new OpenID Connect authentication success response.
	 *
	 * @param redirectURI  The requested redirection URI. Must not be
	 *                     {@code null}.
	 * @param code         The authorisation code, {@code null} if not
	 *                     requested.
	 * @param idToken      The ID token (ready for output), {@code null} if
	 *                     not requested.
	 * @param accessToken  The UserInfo access token, {@code null} if not
	 *                     requested.
	 * @param state        The state, {@code null} if not requested.
	 * @param sessionState The session state, {@code null} if session
	 *                     management is not supported.
	 * @param issuer       The issuer, {@code null} if not specified.
	 * @param rm           The response mode, {@code null} if not
	 *                     specified.
	 */
	public AuthenticationSuccessResponse(final URI redirectURI,
					     final AuthorizationCode code,
					     final JWT idToken,
					     final AccessToken accessToken,
					     final State state,
					     final State sessionState,
					     final Issuer issuer,
					     final ResponseMode rm) {

		super(redirectURI, code, accessToken, state, issuer, rm);

		this.idToken = idToken;

		this.sessionState = sessionState;
	}


	/**
	 * Creates a new JSON Web Token (JWT) secured OpenID Connect
	 * authentication success response.
	 *
	 * @param redirectURI The requested redirection URI. Must not be
	 *                    {@code null}.
	 * @param jwtResponse The JWT-secured response. Must not be
	 *                    {@code null}.
	 * @param rm          The response mode, {@code null} if not specified.
	 */
	public AuthenticationSuccessResponse(final URI redirectURI,
					     final JWT jwtResponse,
					     final ResponseMode rm) {

		super(redirectURI, jwtResponse, rm);
		idToken = null;
		sessionState = null;
	}
	
	
	@Override
	public ResponseType impliedResponseType() {
	
		ResponseType rt = new ResponseType();
		
		if (getAuthorizationCode() != null) {
			rt.add(ResponseType.Value.CODE);
		}

		if (getIDToken() != null) {
			rt.add(OIDCResponseTypeValue.ID_TOKEN);
		}
		
		if (getAccessToken() != null) {
			rt.add(ResponseType.Value.TOKEN);
		}
		
		return rt;
	}


	@Override
	public ResponseMode impliedResponseMode() {
		
		if (getResponseMode() != null) {
			return getResponseMode();
		} else {
			if (getJWTResponse() != null) {
				// JARM
				return ResponseMode.JWT;
			} else if (getAccessToken() != null || getIDToken() != null) {
				return ResponseMode.FRAGMENT;
			} else {
				return ResponseMode.QUERY;
			}
		}
	}
	
	
	/**
	 * Gets the requested ID token.
	 *
	 * @return The ID token (ready for output), {@code null} if not 
	 *         requested.
	 */
	public JWT getIDToken() {
	
		return idToken;
	}


	/**
	 * Gets the session state for session management.
	 *
	 * @return The session store, {@code null} if session management is not
	 *         supported.
	 */
	public State getSessionState() {

		return sessionState;
	}
	
	
	@Override
	public Map<String,List<String>> toParameters() {
	
		Map<String,List<String>> params = super.toParameters();
		
		if (getJWTResponse() != null) {
			// JARM, no other top-level parameters
			return params;
		}

		if (idToken != null) {

			try {
				params.put("id_token", Collections.singletonList(idToken.serialize()));
				
			} catch (IllegalStateException e) {
				throw new SerializeException("Couldn't serialize ID token: " + e.getMessage(), e);
			}
		}

		if (sessionState != null) {

			params.put("session_state", Collections.singletonList(sessionState.getValue()));
		}

		return params;
	}
	
	
	@Override
	public AuthenticationSuccessResponse toSuccessResponse() {
		return this;
	}
	
	
	@Override
	public AuthenticationErrorResponse toErrorResponse() {
		throw new ClassCastException("Cannot cast to AuthenticationErrorResponse");
	}
	
	
	/**
	 * Parses an OpenID Connect authentication success response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param params      The response parameters to parse. Must not be 
	 *                    {@code null}.
	 *
	 * @return The OpenID Connect authentication success response.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        OpenID Connect authentication success
	 *                        response.
	 */
	public static AuthenticationSuccessResponse parse(final URI redirectURI,
							  final Map<String,List<String>> params)
		throws ParseException {

		AuthorizationSuccessResponse asr = AuthorizationSuccessResponse.parse(redirectURI, params);
		
		// JARM, ignore other top level params
		if (asr.getJWTResponse() != null) {
			return new AuthenticationSuccessResponse(redirectURI, asr.getJWTResponse(), asr.getResponseMode());
		}

		// Parse id_token parameter
		String idTokenString = MultivaluedMapUtils.getFirstValue(params, "id_token");
		JWT idToken = null;
		if (idTokenString != null) {
			
			try {
				idToken = JWTParser.parse(idTokenString);
				
			} catch (java.text.ParseException e) {
			
				throw new ParseException("Invalid ID Token JWT: " + e.getMessage(), e);
			}
		}

		// Parse the optional session_state parameter

		State sessionState = null;

		if (StringUtils.isNotBlank(MultivaluedMapUtils.getFirstValue(params, "session_state"))) {

			sessionState = new State(MultivaluedMapUtils.getFirstValue(params, "session_state"));
		}

		return new AuthenticationSuccessResponse(redirectURI,
			asr.getAuthorizationCode(),
			idToken,
			asr.getAccessToken(),
			asr.getState(),
			sessionState,
			asr.getIssuer(),
			null);
	}
	
	
	/**
	 * Parses an OpenID Connect authentication success response.
	 *
	 * <p>Use a relative URI if the host, port and path details are not
	 * known:
	 *
	 * <pre>
	 * URI relUrl = new URI("https:///?code=Qcb0Orv1...&amp;state=af0ifjsldkj");
	 * </pre>
	 *
	 * <p>Example URI:
	 *
	 * <pre>
	 * https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
	 * </pre>
	 *
	 * @param uri The URI to parse. Can be absolute or relative, with a
	 *            fragment or query string containing the authentication
	 *            response parameters. Must not be {@code null}.
	 *
	 * @return The OpenID Connect authentication success response.
	 *
	 * @throws ParseException If the redirection URI couldn't be parsed to
	 *                        an OpenID Connect authentication success
	 *                        response.
	 */
	public static AuthenticationSuccessResponse parse(final URI uri)
		throws ParseException {

		return parse(URIUtils.getBaseURI(uri), parseResponseParameters(uri));
	}


	/**
	 * Parses an OpenID Connect authentication success response from the
	 * specified initial HTTP 302 redirect response generated at the
	 * authorisation endpoint.
	 *
	 * <p>Example HTTP response:
	 *
	 * <pre>
	 * HTTP/1.1 302 Found
	 * Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
	 * </pre>
	 *
	 * @see #parse(HTTPRequest)
	 *
	 * @param httpResponse The HTTP response to parse. Must not be 
	 *                     {@code null}.
	 *
	 * @return The OpenID Connect authentication success response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an 
	 *                        OpenID Connect authentication success
	 *                        response.
	 */
	public static AuthenticationSuccessResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		URI location = httpResponse.getLocation();
		
		if (location == null)
			throw new ParseException("Missing redirection URI / HTTP Location header");

		return parse(location);
	}


	/**
	 * Parses an OpenID Connect authentication success response from the
	 * specified HTTP request at the client redirection (callback) URI.
	 * Applies to {@code query}, {@code fragment} and {@code form_post}
	 * response modes.
	 *
	 * <p>Example HTTP request (authentication success):
	 *
	 * <pre>
	 * GET /cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz HTTP/1.1
	 * Host: client.example.com
	 * </pre>
	 *
	 * @see #parse(HTTPResponse)
	 *
	 * @param httpRequest The HTTP request to parse. Must not be
	 *                    {@code null}.
	 *
	 * @return The authentication success response.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an
	 *                        OpenID Connect authentication success
	 *                        response.
	 */
	public static AuthenticationSuccessResponse parse(final HTTPRequest httpRequest)
		throws ParseException {

		return parse(URIUtils.getBaseURI(httpRequest.getURI()), parseResponseParameters(httpRequest));
	}
}
