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

package com.nimbusds.oauth2.sdk.token;


import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * The base abstract class for token scheme errors. Concrete extending classes
 * should be immutable.
 */
public abstract class TokenSchemeError extends ErrorObject {
	
	
	private static final long serialVersionUID = -1132784406578139418L;
	
	
	/**
	 * Regex pattern for matching the realm parameter of a WWW-Authenticate
	 * header. Limits the realm string length to 256 chars to prevent
	 * potential stack overflow exception for very long strings due to
	 * recursive nature of regex.
	 */
	static final Pattern REALM_PATTERN = Pattern.compile("realm=\"(([^\\\\\"]|\\\\.){0,256})\"");
	
	
	/**
	 * Regex pattern for matching the error parameter of a WWW-Authenticate
	 * header. Double quoting is optional.
	 */
	static final Pattern ERROR_PATTERN = Pattern.compile("error=(\"([\\w\\_-]+)\"|([\\w\\_-]+))");
	
	
	/**
	 * Regex pattern for matching the error description parameter of a
	 * WWW-Authenticate header.
	 */
	static final Pattern ERROR_DESCRIPTION_PATTERN = Pattern.compile("error_description=\"([^\"]+)\"");
	
	
	/**
	 * Regex pattern for matching the error URI parameter of a
	 * WWW-Authenticate header.
	 */
	static final Pattern ERROR_URI_PATTERN = Pattern.compile("error_uri=\"([^\"]+)\"");
	
	
	/**
	 * Regex pattern for matching the scope parameter of a WWW-Authenticate
	 * header.
	 */
	static final Pattern SCOPE_PATTERN = Pattern.compile("scope=\"([^\"]+)");
	
	
	/**
	 * The token scheme.
	 */
	private final AccessTokenType scheme;
	
	
	/**
	 * The realm, {@code null} if not specified.
	 */
	private final String realm;
	
	
	/**
	 * Required scope, {@code null} if not specified.
	 */
	private final Scope scope;
	
	
	/**
	 * Returns {@code true} if the specified scope consists of valid
	 * characters. Values for the "scope" attributes must not include
	 * characters outside the [0x20, 0x21] | [0x23 - 0x5B] | [0x5D - 0x7E]
	 * range. See RFC 6750, section 3.
	 *
	 * @see ErrorObject#isLegal(String)
	 *
	 * @param scope The scope.
	 *
	 * @return {@code true} if the scope contains valid characters, else
	 *         {@code false}.
	 */
	public static boolean isScopeWithValidChars(final Scope scope) {
		
		return ErrorObject.isLegal(scope.toString());
	}
	
	
	/**
	 * Creates a new token error with the specified code, description, HTTP
	 * status code, page URI, realm and scope.
	 *
	 * @param scheme         The token scheme. Must not be {@code null}.
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
	protected TokenSchemeError(final AccessTokenType scheme,
				   final String code,
				   final String description,
				   final int httpStatusCode,
				   final URI uri,
				   final String realm,
				   final Scope scope) {
		
		super(code, description, httpStatusCode, uri);
		
		this.scheme = Objects.requireNonNull(scheme);
		this.realm = realm;
		this.scope = scope;
		
		if (scope != null && ! isScopeWithValidChars(scope)) {
			throw new IllegalArgumentException("The scope contains illegal characters, see RFC 6750, section 3");
		}
	}
	
	
	/**
	 * Returns the token scheme.
	 *
	 * @return The token scheme.
	 */
	public AccessTokenType getScheme() {
		
		return scheme;
	}
	
	
	/**
	 * Returns the realm.
	 *
	 * @return The realm, {@code null} if not specified.
	 */
	public String getRealm() {
		
		return realm;
	}
	
	
	/**
	 * Returns the required scope.
	 *
	 * @return The required scope, {@code null} if not specified.
	 */
	public Scope getScope() {
		
		return scope;
	}
	
	
	@Override
	public abstract TokenSchemeError setDescription(final String description);
	
	
	@Override
	public abstract TokenSchemeError appendDescription(final String text);
	
	
	@Override
	public abstract TokenSchemeError setHTTPStatusCode(final int httpStatusCode);
	
	
	@Override
	public abstract TokenSchemeError setURI(final URI uri);
	
	
	/**
	 * Sets the realm.
	 *
	 * @param realm realm, {@code null} if not specified.
	 *
	 * @return A copy of this error with the specified realm.
	 */
	public abstract TokenSchemeError setRealm(final String realm);
	
	
	/**
	 * Sets the required scope.
	 *
	 * @param scope The required scope, {@code null} if not specified.
	 *
	 * @return A copy of this error with the specified required scope.
	 */
	public abstract TokenSchemeError setScope(final Scope scope);
	
	
	/**
	 * Returns the {@code WWW-Authenticate} HTTP response header code for
	 * this token scheme error.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * Bearer realm="example.com", error="invalid_token", error_description="Invalid access token"
	 * </pre>
	 *
	 * @return The {@code Www-Authenticate} header value.
	 */
	public String toWWWAuthenticateHeader() {
		
		StringBuilder sb = new StringBuilder(getScheme().getValue());
		
		int numParams = 0;
		
		// Serialise realm, may contain double quotes
		if (getRealm() != null) {
			sb.append(" realm=\"");
			sb.append(getRealm().replaceAll("\"","\\\\\""));
			sb.append('"');
			
			numParams++;
		}
		
		// Serialise error, error_description, error_uri
		if (getCode() != null) {
			
			if (numParams > 0)
				sb.append(',');
			
			sb.append(" error=\"");
			sb.append(getCode());
			sb.append('"');
			numParams++;
			
			if (getDescription() != null) {
				// Output description only if code is present
				sb.append(',');
				sb.append(" error_description=\"");
				sb.append(getDescription());
				sb.append('"');
				numParams++;
			}
			
			if (getURI() != null) {
				// Output description only if code is present
				sb.append(',');
				sb.append(" error_uri=\"");
				sb.append(getURI().toString()); // double quotes always escaped in URI representation
				sb.append('"');
				numParams++;
			}
		}
		
		// Serialise scope
		if (getScope() != null) {
			
			if (numParams > 0)
				sb.append(',');
			
			sb.append(" scope=\"");
			sb.append(getScope().toString());
			sb.append('"');
		}
		
		return sb.toString();
	}
	
	
	/**
	 * Parses an OAuth 2.0 generic token scheme error from the specified
	 * HTTP response {@code WWW-Authenticate} header.
	 *
	 * @param wwwAuth The {@code WWW-Authenticate} header value to parse.
	 *                Must not be {@code null}.
	 * @param scheme  The token scheme. Must not be {@code null}.
	 *
	 * @return The generic token scheme error.
	 *
	 * @throws ParseException If the {@code WWW-Authenticate} header value
	 *                        couldn't be parsed to a generic token scheme
	 *                        error.
	 */
	static TokenSchemeError parse(final String wwwAuth,
				      final AccessTokenType scheme)
		throws ParseException {
		
		// We must have a WWW-Authenticate header set to <Scheme> .*
		if (! wwwAuth.regionMatches(true, 0, scheme.getValue(), 0, scheme.getValue().length()))
			throw new ParseException("WWW-Authenticate scheme must be OAuth 2.0 DPoP");
		
		Matcher m;
		
		// Parse optional realm
		m = REALM_PATTERN.matcher(wwwAuth);
		
		String realm = null;
		
		if (m.find())
			realm = m.group(1);
		
		if (realm != null)
			realm = realm.replace("\\\"", "\""); // strip escaped double quotes
		
		
		// Parse optional error
		String errorCode = null;
		String errorDescription = null;
		URI errorURI = null;
		
		m = ERROR_PATTERN.matcher(wwwAuth);
		
		if (m.find()) {
			
			// Error code: try group with double quotes, else group with no quotes
			errorCode = m.group(2) != null ? m.group(2) : m.group(3);
			
			if (! ErrorObject.isLegal(errorCode))
				errorCode = null; // found invalid chars
			
			// Parse optional error description
			m = ERROR_DESCRIPTION_PATTERN.matcher(wwwAuth);
			
			if (m.find())
				errorDescription = m.group(1);
			
			
			// Parse optional error URI
			m = ERROR_URI_PATTERN.matcher(wwwAuth);
			
			if (m.find()) {
				try {
					errorURI = new URI(m.group(1));
				} catch (URISyntaxException e) {
					// ignore, URI is not required to construct error object
				}
			}
		}
		
		
		Scope scope = null;
		
		m = SCOPE_PATTERN.matcher(wwwAuth);
		
		if (m.find())
			scope = Scope.parse(m.group(1));
		
		
		return new TokenSchemeError(AccessTokenType.UNKNOWN, errorCode, errorDescription, 0, errorURI, realm, scope) {
			
			private static final long serialVersionUID = -1629382220440634919L;
			
			
			@Override
			public TokenSchemeError setDescription(String description) {
				return null;
			}
			
			
			@Override
			public TokenSchemeError appendDescription(String text) {
				return null;
			}
			
			
			@Override
			public TokenSchemeError setHTTPStatusCode(int httpStatusCode) {
				return null;
			}
			
			
			@Override
			public TokenSchemeError setURI(URI uri) {
				return null;
			}
			
			
			@Override
			public TokenSchemeError setRealm(String realm) {
				return null;
			}
			
			
			@Override
			public TokenSchemeError setScope(Scope scope) {
				return null;
			}
		};
	}
}
