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


import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Authorisation success response. Used to return an authorisation code or 
 * access token at the Authorisation endpoint.
 *
 * <p>Example HTTP response with code (code flow):
 *
 * <pre>
 * HTTP/1.1 302 Found
 * Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
 * </pre>
 *
 * <p>Example HTTP response with access token (implicit flow):
 *
 * <pre>
 * HTTP/1.1 302 Found
 * Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
 *           &amp;state=xyz&amp;token_type=Bearer&amp;expires_in=3600
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749)
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices 1.0
 *     <li>OAuth 2.0 Form Post Response Mode 1.0
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM)
 *     <li>OAuth 2.0 Authorization Server Issuer Identification (RFC 9207)
 * </ul>
 */
@Immutable
public class AuthorizationSuccessResponse 
	extends AuthorizationResponse 
	implements SuccessResponse {
	
	
	/**
	 * The authorisation code, if requested.
	 */
	private final AuthorizationCode code;
	
	
	/**
	 * The access token, if requested.
	 */
	private final AccessToken accessToken;
	
	
	/**
	 * Creates a new authorisation success response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param code        The authorisation code, {@code null} if not 
	 *                    requested.
	 * @param accessToken The access token, {@code null} if not requested.
	 * @param state       The state, {@code null} if not specified.
	 * @param rm          The response mode, {@code null} if not specified.
	 */
	public AuthorizationSuccessResponse(final URI redirectURI,
	                                    final AuthorizationCode code,
				            final AccessToken accessToken,
				            final State state,
					    final ResponseMode rm) {
	
		this(redirectURI, code, accessToken, state, null, rm);
	}
	
	
	/**
	 * Creates a new authorisation success response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param code        The authorisation code, {@code null} if not
	 *                    requested.
	 * @param accessToken The access token, {@code null} if not requested.
	 * @param state       The state, {@code null} if not specified.
	 * @param issuer      The issuer, {@code null} if not specified.
	 * @param rm          The response mode, {@code null} if not specified.
	 */
	public AuthorizationSuccessResponse(final URI redirectURI,
					    final AuthorizationCode code,
					    final AccessToken accessToken,
					    final State state,
					    final Issuer issuer,
					    final ResponseMode rm) {
	
		super(redirectURI, state, issuer, rm);
		this.code = code;
		this.accessToken = accessToken;
	}
	
	
	/**
	 * Creates a new JSON Web Token (JWT) secured authorisation success
	 * response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param jwtResponse The JWT-secured response. Must not be
	 *                    {@code null}.
	 * @param rm          The response mode, {@code null} if not specified.
	 */
	public AuthorizationSuccessResponse(final URI redirectURI,
					    final JWT jwtResponse,
					    final ResponseMode rm) {
	
		super(redirectURI, jwtResponse, rm);
		code = null;
		accessToken = null;
	}


	@Override
	public boolean indicatesSuccess() {

		return true;
	}
	
	
	/**
	 * Returns the implied response type.
	 *
	 * @return The implied response type.
	 */
	public ResponseType impliedResponseType() {
	
		ResponseType rt = new ResponseType();
		
		if (code != null)
			rt.add(ResponseType.Value.CODE);
		
		if (accessToken != null)
			rt.add(ResponseType.Value.TOKEN);
			
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
			} else if (accessToken != null) {
				return ResponseMode.FRAGMENT;
			} else {
				return ResponseMode.QUERY;
			}
		}
	}
	
	
	/**
	 * Gets the authorisation code.
	 *
	 * @return The authorisation code, {@code null} if not requested.
	 */
	public AuthorizationCode getAuthorizationCode() {
	
		return code;
	}
	
	
	/**
	 * Gets the access token.
	 *
	 * @return The access token, {@code null} if not requested.
	 */
	public AccessToken getAccessToken() {
	
		return accessToken;
	}


	@Override
	public Map<String,List<String>> toParameters() {

		Map<String,List<String>> params = new HashMap<>();
		
		if (getJWTResponse() != null) {
			// JARM, no other top-level parameters
			params.put("response", Collections.singletonList(getJWTResponse().serialize()));
			return params;
		}

		if (code != null)
			params.put("code", Collections.singletonList(code.getValue()));

		if (accessToken != null) {
			
			for (Map.Entry<String,Object> entry: accessToken.toJSONObject().entrySet()) {

				params.put(entry.getKey(), Collections.singletonList(entry.getValue().toString()));
			}
		}
			
		if (getState() != null)
			params.put("state", Collections.singletonList(getState().getValue()));
		
		if (getIssuer() != null)
			params.put("iss", Collections.singletonList(getIssuer().getValue()));

		return params;
	}


	/**
	 * Parses an authorisation success response.
	 *
	 * @param redirectURI The base redirection URI. Must not be
	 *                    {@code null}.
	 * @param params      The response parameters to parse. Must not be 
	 *                    {@code null}.
	 *
	 * @return The authorisation success response.
	 *
	 * @throws ParseException If the parameters couldn't be parsed to an
	 *                        authorisation success response.
	 */
	public static AuthorizationSuccessResponse parse(final URI redirectURI,
		                                         final Map<String,List<String>> params)
		throws ParseException {
		
		// JARM, ignore other top level params
		String responseString = MultivaluedMapUtils.getFirstValue(params, "response");
		if (responseString != null) {
			JWT jwtResponse;
			try {
				jwtResponse = JWTParser.parse(responseString);
			} catch (java.text.ParseException e) {
				throw new ParseException("Invalid JWT response: " + e.getMessage(), e);
			}
			
			return new AuthorizationSuccessResponse(redirectURI, jwtResponse, ResponseMode.JWT);
		}
		
		// Parse code parameter
		AuthorizationCode code = null;
		
		if (params.get("code") != null) {
			code = new AuthorizationCode(MultivaluedMapUtils.getFirstValue(params, "code"));
		}
		
		// Parse access_token parameters
		AccessToken accessToken = null;
		
		if (params.get("access_token") != null) {

			JSONObject jsonObject = new JSONObject();
			jsonObject.putAll(MultivaluedMapUtils.toSingleValuedMap(params));
			accessToken = AccessToken.parse(jsonObject);
		}
		
		// Parse optional state parameter
		State state = State.parse(MultivaluedMapUtils.getFirstValue(params, "state"));
		
		// Parse optional issuer, OAuth 2.0 Authorization Server Issuer Identification (RFC 9207)
		Issuer issuer = Issuer.parse(MultivaluedMapUtils.getFirstValue(params, "iss"));
		
		return new AuthorizationSuccessResponse(redirectURI, code, accessToken, state, issuer,null);
	}
	
	
	/**
	 * Parses an authorisation success response.
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
	 *            fragment or query string containing the authorisation
	 *            response parameters. Must not be {@code null}.
	 *
	 * @return The authorisation success response.
	 *
	 * @throws ParseException If the redirection URI couldn't be parsed to
	 *                        an authorisation success response.
	 */
	public static AuthorizationSuccessResponse parse(final URI uri)
		throws ParseException {

		return parse(URIUtils.getBaseURI(uri), parseResponseParameters(uri));
	}


	/**
	 * Parses an authorisation success response from the specified initial
	 * HTTP 302 redirect response generated at the authorisation endpoint.
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
	 * @return The authorisation success response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to an 
	 *                        authorisation success response.
	 */
	public static AuthorizationSuccessResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		URI location = httpResponse.getLocation();
		
		if (location == null) {
			throw new ParseException("Missing redirection URL / HTTP Location header");
		}

		return parse(location);
	}


	/**
	 * Parses an authorisation success response from the specified HTTP
	 * request at the client redirection (callback) URI. Applies to
	 * {@code query}, {@code fragment} and {@code form_post} response
	 * modes.
	 *
	 * <p>Example HTTP request (authorisation success):
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
	 * @return The authorisation success response.
	 *
	 * @throws ParseException If the HTTP request couldn't be parsed to an
	 *                        authorisation success response.
	 */
	public static AuthorizationSuccessResponse parse(final HTTPRequest httpRequest)
		throws ParseException {

		return parse(URIUtils.getBaseURI(httpRequest.getURI()), parseResponseParameters(httpRequest));
	}
}
