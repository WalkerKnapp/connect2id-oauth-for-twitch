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

package com.nimbusds.oauth2.sdk.auth;


import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.util.Base64;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;


/**
 * Client secret basic authentication at the Token endpoint. Implements
 * {@link ClientAuthenticationMethod#CLIENT_SECRET_BASIC}.
 *
 * <p>Example HTTP Authorization header (for client identifier "s6BhdRkqt3" and
 * secret "7Fjfp0ZBr1KtDRbnfVdmIw"):
 *
 * <pre>
 * Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3
 * </pre>
 *
 * <p>Related specifications:
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 2.3.1 and 3.2.1.
 *     <li>OpenID Connect Core 1.0, section 9.
 *     <li>HTTP Authentication: Basic and Digest Access Authentication 
 *         (RFC 2617).
 * </ul>
 */
@Immutable
public final class ClientSecretBasic extends PlainClientSecret {


	/**
	 * The default character set for the client ID and secret encoding.
	 */
	private static final Charset UTF8_CHARSET = Charset.forName("UTF-8");
	
	
	/**
	 * Creates a new client secret basic authentication.
	 *
	 * @param clientID The client identifier. Must not be {@code null}.
	 * @param secret   The client secret. Must not be {@code null}.
	 */
	public ClientSecretBasic(final ClientID clientID, final Secret secret) {
	
		super(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, clientID, secret);
	}
	
	
	/**
	 * Returns the HTTP Authorization header representation of this client
	 * secret basic authentication.
	 *
	 * <p>Note that OAuth 2.0 (RFC 6749, section 2.3.1) requires the client
	 * ID and secret to be {@code application/x-www-form-urlencoded} before
	 * passing them to the HTTP basic authentication algorithm. This
	 * behaviour differs from the original HTTP Basic Authentication
	 * specification (RFC 2617).
	 *
	 * <p>Example HTTP Authorization header (for client identifier
	 * "Aladdin" and password "open sesame"):
	 *
	 * <pre>
	 *
	 * Authorization: Basic QWxhZGRpbjpvcGVuK3Nlc2FtZQ==
	 * </pre>
	 *
	 * <p>See RFC 2617, section 2.
	 *
	 * @return The HTTP Authorization header.
	 */
	public String toHTTPAuthorizationHeader() {

		StringBuilder sb = new StringBuilder();

		try {
			sb.append(URLEncoder.encode(getClientID().getValue(), UTF8_CHARSET.name()));
			sb.append(':');
			sb.append(URLEncoder.encode(getClientSecret().getValue(), UTF8_CHARSET.name()));

		} catch (UnsupportedEncodingException e) {

			// UTF-8 should always be supported
		}

		return "Basic " + Base64.encode(sb.toString().getBytes(UTF8_CHARSET));
	}
	
	
	@Override
	public void applyTo(final HTTPRequest httpRequest) {
	
		httpRequest.setAuthorization(toHTTPAuthorizationHeader());
	}
	
	
	/**
	 * Parses a client secret basic authentication from the specified HTTP
	 * Authorization header.
	 *
	 * @param header The HTTP Authorization header to parse. Must not be 
	 *               {@code null}.
	 *
	 * @return The client secret basic authentication.
	 *
	 * @throws ParseException If the header couldn't be parsed to a client
	 *                        secret basic authentication.
	 */
	public static ClientSecretBasic parse(final String header)
		throws ParseException {
		
		String[] parts = header.split("\\s");
		
		if (parts.length != 2)
			throw new ParseException("Malformed client secret basic authentication: Unexpected number of HTTP Authorization header value parts: " + parts.length);
		
		if (! parts[0].equalsIgnoreCase("Basic"))
			throw new ParseException("HTTP authentication must be \"Basic\"");
		
		String credentialsString = new String(new Base64(parts[1]).decode(), UTF8_CHARSET);

		String[] credentials = credentialsString.split(":", 2);
		
		if (credentials.length != 2)
			throw new ParseException("Malformed client secret basic authentication: Missing credentials delimiter \":\"");

		try {
			String decodedClientID = URLDecoder.decode(credentials[0], UTF8_CHARSET.name());
			String decodedSecret = URLDecoder.decode(credentials[1], UTF8_CHARSET.name());

			return new ClientSecretBasic(new ClientID(decodedClientID), new Secret(decodedSecret));
			
		} catch (UnsupportedEncodingException e) {
		
			throw new ParseException(e.getMessage(), e);
		}
	}
	
	
	/**
	 * Parses a client secret basic authentication from the specified HTTP
	 * request.
	 *
	 * @param httpRequest The HTTP request to parse. Must not be 
	 *                    {@code null} and must contain a valid 
	 *                    Authorization header.
	 *
	 * @return The client secret basic authentication.
	 *
	 * @throws ParseException If the HTTP Authorization header couldn't be 
	 *                        parsed to a client secret basic 
	 *                        authentication.
	 */
	public static ClientSecretBasic parse(final HTTPRequest httpRequest)
		throws ParseException {
		
		String header = httpRequest.getAuthorization();
		
		if (header == null)
			throw new ParseException("Missing HTTP Authorization header");
			
		return parse(header);
	}
}
