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

package com.nimbusds.oauth2.sdk.token;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import net.jcip.annotations.Immutable;

import java.net.URI;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * OAuth 2.0 DPoP token error. Used to indicate that access to a resource
 * protected by a DPoP access token is denied, due to the request, token or
 * DPoP proof being invalid, or due to the access token having insufficient
 * scope.
 *
 * <p>Standard DPoP access token errors:
 *
 * <ul>
 *     <li>{@link #MISSING_TOKEN}
 *     <li>{@link #INVALID_REQUEST}
 *     <li>{@link #INVALID_TOKEN}
 *     <li>{@link #INSUFFICIENT_SCOPE}
 *     <li>{@link #USE_DPOP_NONCE}
 * </ul>
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 401 Unauthorized
 * WWW-Authenticate: DPoP realm="example.com",
 *                   error="invalid_token",
 *                   error_description="The access token expired"
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer
 *         (DPoP) (RFC 9449)
 *     <li>Hypertext Transfer Protocol (HTTP/1.1): Authentication (RFC 7235)
 * </ul>
 */
@Immutable
public class DPoPTokenError extends TokenSchemeError {
	
	
	private static final long serialVersionUID = 7399517620661603486L;
	
	
	/**
	 * Regex pattern for matching the JWS algorithms parameter of a
	 * WWW-Authenticate header.
	 */
	static final Pattern ALGS_PATTERN = Pattern.compile("algs=\"([^\"]+)");
	
	/**
	 * The request does not contain an access token. No error code or
	 * description is specified for this error, just the HTTP status code
	 * is set to 401 (Unauthorized).
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * HTTP/1.1 401 Unauthorized
	 * WWW-Authenticate: DPoP
	 * </pre>
	 */
	public static final DPoPTokenError MISSING_TOKEN =
		new DPoPTokenError(null, null, HTTPResponse.SC_UNAUTHORIZED);
	
	
	/**
	 * The request is missing a required parameter, includes an unsupported
	 * parameter or parameter value, repeats the same parameter, uses more
	 * than one method for including an access token, or is otherwise
	 * malformed. The HTTP status code is set to 400 (Bad Request).
	 */
	public static final DPoPTokenError INVALID_REQUEST =
		new DPoPTokenError("invalid_request", "Invalid request",
			             HTTPResponse.SC_BAD_REQUEST);
	
	
	/**
	 * The access token provided is expired, revoked, malformed, or invalid
	 * for other reasons.  The HTTP status code is set to 401
	 * (Unauthorized).
	 */
	public static final DPoPTokenError INVALID_TOKEN =
		new DPoPTokenError("invalid_token", "Invalid access token",
			             HTTPResponse.SC_UNAUTHORIZED);
	
	
	/**
	 * The request requires higher privileges than provided by the access
	 * token. The HTTP status code is set to 403 (Forbidden).
	 */
	public static final DPoPTokenError INSUFFICIENT_SCOPE =
		new DPoPTokenError("insufficient_scope", "Insufficient scope",
			             HTTPResponse.SC_FORBIDDEN);
	
	
	/**
	 * The request has a DPoP proof that is invalid. The HTTP status code
	 * is set to 401 (Unauthorized).
	 */
	public static final DPoPTokenError INVALID_DPOP_PROOF =
		new DPoPTokenError("invalid_dpop_proof", "Invalid DPoP proof",
			HTTPResponse.SC_UNAUTHORIZED);
	
	
	/**
	 * The request is missing a required DPoP nonce. The HTTP status code
	 * is set to 401 (Unauthorized).
	 */
	public static final DPoPTokenError USE_DPOP_NONCE =
		new DPoPTokenError("use_dpop_nonce", "Use of DPoP nonce required",
			HTTPResponse.SC_UNAUTHORIZED);
	
	
	/**
	 * The acceptable JWS algorithms, {@code null} if not specified.
	 */
	private final Set<JWSAlgorithm> jwsAlgs;
	
	
	/**
	 * Creates a new OAuth 2.0 DPoP token error with the specified code
	 * and description.
	 *
	 * @param code        The error code, {@code null} if not specified.
	 * @param description The error description, {@code null} if not
	 *                    specified.
	 */
	public DPoPTokenError(final String code, final String description) {
	
		this(code, description, 0, null, null, null);
	}


	/**
	 * Creates a new OAuth 2.0 DPoP token error with the specified code,
	 * description and HTTP status code.
	 *
	 * @param code           The error code, {@code null} if not specified.
	 * @param description    The error description, {@code null} if not
	 *                       specified.
	 * @param httpStatusCode The HTTP status code, zero if not specified.
	 */
	public DPoPTokenError(final String code, final String description, final int httpStatusCode) {
	
		this(code, description, httpStatusCode, null, null, null);
	}


	/**
	 * Creates a new OAuth 2.0 DPoP token error with the specified code,
	 * description, HTTP status code, page URI, realm and scope.
	 *
	 * @param code           The error code, {@code null} if not specified.
	 * @param description    The error description, {@code null} if not
	 *                       specified.
	 * @param httpStatusCode The HTTP status code, zero if not specified.
	 * @param uri            The error page URI, {@code null} if not
	 *                       specified.
	 * @param realm          The realm, {@code null} if not specified.
	 * @param scope          The required scope, {@code null} if not
	 *                       specified.
	 */
	public DPoPTokenError(final String code,
			      final String description,
			      final int httpStatusCode,
			      final URI uri,
			      final String realm,
			      final Scope scope) {
	
		this(code, description, httpStatusCode, uri, realm, scope, null);
	}


	/**
	 * Creates a new OAuth 2.0 DPoP token error with the specified code,
	 * description, HTTP status code, page URI, realm and scope.
	 *
	 * @param code           The error code, {@code null} if not specified.
	 * @param description    The error description, {@code null} if not
	 *                       specified.
	 * @param httpStatusCode The HTTP status code, zero if not specified.
	 * @param uri            The error page URI, {@code null} if not
	 *                       specified.
	 * @param realm          The realm, {@code null} if not specified.
	 * @param scope          The required scope, {@code null} if not
	 *                       specified.
	 * @param jwsAlgs        The acceptable JWS algorithms, {@code null} if
	 *                       not specified.
	 */
	public DPoPTokenError(final String code,
			      final String description,
			      final int httpStatusCode,
			      final URI uri,
			      final String realm,
			      final Scope scope,
			      final Set<JWSAlgorithm> jwsAlgs) {
	
		super(AccessTokenType.DPOP, code, description, httpStatusCode, uri, realm, scope);
		
		this.jwsAlgs = jwsAlgs;
	}


	@Override
	public DPoPTokenError setDescription(final String description) {

		return new DPoPTokenError(
			getCode(),
			description,
			getHTTPStatusCode(),
			getURI(),
			getRealm(),
			getScope(),
			getJWSAlgorithms()
		);
	}


	@Override
	public DPoPTokenError appendDescription(final String text) {

		String newDescription;
		if (getDescription() != null)
			newDescription = getDescription() + text;
		else
			newDescription = text;

		return new DPoPTokenError(
			getCode(),
			newDescription,
			getHTTPStatusCode(),
			getURI(),
			getRealm(),
			getScope(),
			getJWSAlgorithms()
		);
	}


	@Override
	public DPoPTokenError setHTTPStatusCode(final int httpStatusCode) {

		return new DPoPTokenError(
			getCode(),
			getDescription(),
			httpStatusCode,
			getURI(),
			getRealm(),
			getScope(),
			getJWSAlgorithms()
		);
	}


	@Override
	public DPoPTokenError setURI(final URI uri) {

		return new DPoPTokenError(
			getCode(),
			getDescription(),
			getHTTPStatusCode(),
			uri,
			getRealm(),
			getScope(),
			getJWSAlgorithms()
		);
	}


	@Override
	public DPoPTokenError setRealm(final String realm) {

		return new DPoPTokenError(
			getCode(),
			getDescription(),
			getHTTPStatusCode(),
			getURI(),
			realm,
			getScope(),
			getJWSAlgorithms()
		);
	}


	@Override
	public DPoPTokenError setScope(final Scope scope) {

		return new DPoPTokenError(
			getCode(),
			getDescription(),
			getHTTPStatusCode(),
			getURI(),
			getRealm(),
			scope,
			getJWSAlgorithms()
		);
	}
	
	
	/**
	 * Returns the acceptable JWS algorithms.
	 *
	 * @return The acceptable JWS algorithms, {@code null} if not
	 *         specified.
	 */
	public Set<JWSAlgorithm> getJWSAlgorithms() {
		
		return jwsAlgs;
	}
	
	
	/**
	 * Sets the acceptable JWS algorithms.
	 *
	 * @param jwsAlgs The acceptable JWS algorithms, {@code null} if not
	 *                specified.
	 *
	 * @return A copy of this error with the specified acceptable JWS
	 *         algorithms.
	 */
	public DPoPTokenError setJWSAlgorithms(final Set<JWSAlgorithm> jwsAlgs) {
		
		return new DPoPTokenError(
			getCode(),
			getDescription(),
			getHTTPStatusCode(),
			getURI(),
			getRealm(),
			getScope(),
			jwsAlgs
		);
	}
	
	
	/**
	 * Returns the {@code WWW-Authenticate} HTTP response header code for 
	 * this DPoP access token error response.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * DPoP realm="example.com", error="invalid_token", error_description="Invalid access token"
	 * </pre>
	 *
	 * @return The {@code Www-Authenticate} header value.
	 */
	@Override
	public String toWWWAuthenticateHeader() {

		String header = super.toWWWAuthenticateHeader();
		
		if (CollectionUtils.isEmpty(getJWSAlgorithms())) {
			return header;
		}
		
		StringBuilder sb = new StringBuilder(header);
		
		if (header.contains("=")) {
			sb.append(',');
		}
		
		sb.append(" algs=\"");
		
		String delim = "";
		for (JWSAlgorithm alg: getJWSAlgorithms()) {
			sb.append(delim);
			delim = " ";
			sb.append(alg.getName());
		}
		sb.append("\"");
		
		return sb.toString();
	}


	/**
	 * Parses an OAuth 2.0 DPoP token error from the specified HTTP
	 * response {@code WWW-Authenticate} header.
	 *
	 * @param wwwAuth The {@code WWW-Authenticate} header value to parse. 
	 *                Must not be {@code null}.
	 *
	 * @return The DPoP token error.
	 *
	 * @throws ParseException If the {@code WWW-Authenticate} header value 
	 *                        couldn't be parsed to a DPoP token error.
	 */
	public static DPoPTokenError parse(final String wwwAuth)
		throws ParseException {

		TokenSchemeError genericError = TokenSchemeError.parse(wwwAuth, AccessTokenType.DPOP);
		
		Set<JWSAlgorithm> jwsAlgs = null;
		
		Matcher m = ALGS_PATTERN.matcher(wwwAuth);
		
		if (m.find()) {
			String algsString = m.group(1);
			jwsAlgs = new HashSet<>();
			for (String algName: algsString.split("\\s+")) {
				jwsAlgs.add(JWSAlgorithm.parse(algName));
			}
		}
		
		return new DPoPTokenError(
			genericError.getCode(),
			genericError.getDescription(),
			genericError.getHTTPStatusCode(),
			genericError.getURI(),
			genericError.getRealm(),
			genericError.getScope(),
			jwsAlgs
		);
	}
}
