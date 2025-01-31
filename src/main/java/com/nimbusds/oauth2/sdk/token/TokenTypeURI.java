package com.nimbusds.oauth2.sdk.token;


import com.nimbusds.oauth2.sdk.ParseException;
import net.jcip.annotations.Immutable;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;


/**
 * Token type URI. A URN used to identify the type of token in a token
 * exchange. The token type URIs can potentially be used in other contexts.
 *
 * <p>The standard OAuth URIs are registered at IANA, see
 * https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#uri
 *
 * <ul>
 *     <li>OAuth 2.0 Token Exchange (RFC 8693)
 * </ul>
 */
@Immutable
public final class TokenTypeURI implements Serializable {
	
	
	private static final long serialVersionUID = 1371197657238309877L;
	
	
	/**
	 * The token type URI for an OAuth 2.0 access token.
	 */
	public static final TokenTypeURI ACCESS_TOKEN = new TokenTypeURI(URI.create("urn:ietf:params:oauth:token-type:access_token"));
	
	
	/**
	 * The token type URI for an OAuth 2.0 refresh token.
	 */
	public static final TokenTypeURI REFRESH_TOKEN = new TokenTypeURI(URI.create("urn:ietf:params:oauth:token-type:refresh_token"));


	/**
	 * The token type URI for a BASE64URL-encoded SAML 1.1 assertion.
	 */
	public static final TokenTypeURI SAML1 = new TokenTypeURI(URI.create("urn:ietf:params:oauth:token-type:saml1"));


	/**
	 * The token type URI for a BASE64URL-encoded SAML 2.0 assertion.
	 */
	public static final TokenTypeURI SAML2 = new TokenTypeURI(URI.create("urn:ietf:params:oauth:token-type:saml2"));


	/**
	 * The token type URI for a JSON Web Token (JWT).
	 */
	public static final TokenTypeURI JWT = new TokenTypeURI(URI.create("urn:ietf:params:oauth:token-type:jwt"));


	/**
	 * The token type URI for an OpenID Connect ID Token.
	 */
	public static final TokenTypeURI ID_TOKEN = new TokenTypeURI(URI.create("urn:ietf:params:oauth:token-type:id_token"));


	/**
	 * The token type URI for a {@code device_secret} for OpenID Connect
	 * native SSO.
	 */
	public static final TokenTypeURI DEVICE_SECRET = new TokenTypeURI(URI.create("urn:openid:params:token-type:device-secret"));
	
	
	private static final Map<String, TokenTypeURI> KNOWN_TOKEN_TYPE_URIS;
	
	static {
		Map<String, TokenTypeURI> knownTokenTypeUris = new HashMap<>();
		knownTokenTypeUris.put(ACCESS_TOKEN.getURI().toString(), ACCESS_TOKEN);
		knownTokenTypeUris.put(REFRESH_TOKEN.getURI().toString(), REFRESH_TOKEN);
		knownTokenTypeUris.put(ID_TOKEN.getURI().toString(), ID_TOKEN);
		knownTokenTypeUris.put(SAML1.getURI().toString(), SAML1);
		knownTokenTypeUris.put(SAML2.getURI().toString(), SAML2);
		knownTokenTypeUris.put(JWT.getURI().toString(), JWT);
		knownTokenTypeUris.put(DEVICE_SECRET.getURI().toString(), DEVICE_SECRET);
		KNOWN_TOKEN_TYPE_URIS = Collections.unmodifiableMap(knownTokenTypeUris);
	}
	
	private final URI uri;
	
	
	/**
	 * Creates a new token type URI with the specified value.
	 *
	 * @param uri The URI value. Must not be {@code null}.
	 */
	private TokenTypeURI(final URI uri) {
		this.uri = Objects.requireNonNull(uri);
	}
	
	
	/**
	 * Returns the URI for this token type.
	 *
	 * @return The URI.
	 */
	public URI getURI() {
		return uri;
	}
	
	
	/**
	 * Parses a token type URI from the specified string.
	 *
	 * @param uriValue The URI string value. Must not be {@code null}.
	 *
	 * @return The token type URI.
	 *
	 * @throws ParseException If the token type URI value is illegal.
	 */
	public static TokenTypeURI parse(final String uriValue)
		throws ParseException {
		
		if (uriValue == null) {
			throw new IllegalArgumentException("The URI value must not be null");
		}
		
		TokenTypeURI knownURI = KNOWN_TOKEN_TYPE_URIS.get(uriValue);
		
		if (knownURI != null) {
			return knownURI;
		}
		
		try {
			return new TokenTypeURI(new URI(uriValue));
		} catch (URISyntaxException e) {
			throw new ParseException("Illegal token type URI: " + uriValue);
		}
	}
	
	
	@Override
	public String toString() {
		return getURI().toString();
	}
	
	
	@Override
	public boolean equals(final Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		
		TokenTypeURI that = (TokenTypeURI) o;
		
		return uri.equals(that.getURI());
	}
	
	
	@Override
	public int hashCode() {
		return uri.hashCode();
	}
}
