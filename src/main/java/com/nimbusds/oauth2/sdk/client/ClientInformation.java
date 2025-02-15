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

package com.nimbusds.oauth2.sdk.client;


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import net.jcip.annotations.Immutable;
import net.minidev.json.JSONObject;

import java.net.URI;
import java.util.*;


/**
 * Client information. Encapsulates the registration and metadata details of 
 * an OAuth 2.0 client:
 * 
 * <ul>
 *     <li>The client identifier.
 *     <li>The client metadata.
 *     <li>The optional client secret for a confidential client.
 *     <li>The optional registration URI and access token if dynamic client
 *         registration is permitted.
 * </ul>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)
 *     <li>OAuth 2.0 Dynamic Client Registration Management Protocol (RFC 7592)
 * </ul>
 */
@Immutable
public class ClientInformation {


	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;


	static {
		Set<String> p = new HashSet<>(ClientMetadata.getRegisteredParameterNames());

		p.add("client_id");
		p.add("client_id_issued_at");
		p.add("client_secret");
		p.add("client_secret_expires_at");
		p.add("registration_access_token");
		p.add("registration_client_uri");

		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}


	/**
	 * The registered client ID.
	 */
	private final ClientID id;


	/**
	 * The date the client ID was issued at.
	 */
	private final Date issueDate;


	/**
	 * The client metadata.
	 */
	private final ClientMetadata metadata;


	/**
	 * The optional client secret.
	 */
	private final Secret secret;


	/**
	 * The client registration URI.
	 */
	private final URI registrationURI;


	/**
	 * The client registration access token.
	 */
	private final BearerAccessToken accessToken;
	
	
	/**
	 * Creates a new minimal client information instance without a client
	 * secret.
	 *
	 * @param id       The client identifier. Must not be {@code null}.
	 * @param metadata The client metadata. Must not be {@code null}.
	 */
	public ClientInformation(final ClientID id, final ClientMetadata metadata) {
		this(id, null, metadata, null);
	}


	/**
	 * Creates a new client information instance.
	 *
	 * @param id        The client identifier. Must not be {@code null}.
	 * @param issueDate The issue date of the client identifier,
	 *                  {@code null} if not specified.
	 * @param metadata  The client metadata. Must not be {@code null}.
	 * @param secret    The optional client secret, {@code null} if not
	 *                  specified.
	 */
	public ClientInformation(final ClientID id,
				 final Date issueDate,
				 final ClientMetadata metadata,
				 final Secret secret) {

		this(id, issueDate, metadata, secret, null, null);
	}


	/**
	 * Creates a new client information instance permitting dynamic client
	 * registration management.
	 * 
	 * @param id              The client identifier. Must not be 
	 *                        {@code null}.
	 * @param issueDate       The issue date of the client identifier,
	 *                        {@code null} if not specified.
	 * @param metadata        The client metadata. Must not be
	 *                        {@code null}.
	 * @param secret          The optional client secret, {@code null} if
	 *                        not specified.
	 * @param registrationURI The client registration URI, {@code null} if
	 *                        not specified.
	 * @param accessToken     The client registration access token,
	 *                        {@code null} if not specified.
	 */
	public ClientInformation(final ClientID id,
				 final Date issueDate,
				 final ClientMetadata metadata,
				 final Secret secret,
				 final URI registrationURI,
				 final BearerAccessToken accessToken) {

		this.id = Objects.requireNonNull(id);
		this.issueDate = issueDate;
		this.metadata = Objects.requireNonNull(metadata);
		this.secret = secret;
		this.registrationURI = registrationURI;
		this.accessToken = accessToken;
	}


	/**
	 * Gets the registered client metadata parameter names.
	 *
	 * @return The registered parameter names, as an unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {

		return REGISTERED_PARAMETER_NAMES;
	}


	/**
	 * Gets the client identifier. Corresponds to the {@code client_id}
	 * client registration parameter.
	 *
	 * @return The client ID.
	 */
	public ClientID getID() {

		return id;
	}


	/**
	 * Gets the issue date of the client identifier. Corresponds to the
	 * {@code client_id_issued_at} client registration parameter.
	 *
	 * @return The issue date, {@code null} if not specified.
	 */
	public Date getIDIssueDate() {

		return issueDate;
	}
	
	
	/**
	 * Gets the client metadata.
	 * 
	 * @return The client metadata.
	 */
	public ClientMetadata getMetadata() {
		
		return metadata;
	}


	/**
	 * Gets the client secret. Corresponds to the {@code client_secret} and
	 * {@code client_secret_expires_at} client registration parameters.
	 *
	 * @return The client secret, {@code null} if not specified.
	 */
	public Secret getSecret() {

		return secret;
	}


	/**
	 * Infers the client type.
	 *
	 * @return The client type.
	 */
	public ClientType inferClientType() {

		// The client must be unambiguously public, else it is marked as confidential

		return secret == null
			&& ClientAuthenticationMethod.NONE.equals(getMetadata().getTokenEndpointAuthMethod())
			&& getMetadata().getJWKSetURI() == null
			&& getMetadata().getJWKSet() == null
			? ClientType.PUBLIC : ClientType.CONFIDENTIAL;
	}


	/**
	 * Gets the URI of the client registration. Corresponds to the
	 * {@code registration_client_uri} client registration parameter.
	 *
	 * @return The registration URI, {@code null} if not specified.
	 */
	public URI getRegistrationURI() {

		return registrationURI;
	}


	/**
	 * Gets the registration access token. Corresponds to the
	 * {@code registration_access_token} client registration parameter.
	 *
	 * @return The registration access token, {@code null} if not
	 *         specified.
	 */
	public BearerAccessToken getRegistrationAccessToken() {

		return accessToken;
	}


	/**
	 * Returns the JSON object representation of this client information 
	 * instance.
	 *
	 * @return The JSON object.
	 */
	public JSONObject toJSONObject() {

		JSONObject o = metadata.toJSONObject();

		o.put("client_id", id.getValue());

		if (issueDate != null) {

			o.put("client_id_issued_at", issueDate.getTime() / 1000);
		}

		if (secret != null) {
			o.put("client_secret", secret.getValue());

			if (secret.getExpirationDate() != null) {
				o.put("client_secret_expires_at", secret.getExpirationDate().getTime() / 1000);
			} else {
				o.put("client_secret_expires_at", 0L);
			}
		}

		if (registrationURI != null) {

			o.put("registration_client_uri", registrationURI.toString());
		}

		if (accessToken != null) {

			o.put("registration_access_token", accessToken.getValue());
		}

		return o;
	}


	/**
	 * Parses a client information instance from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The client information.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        client information instance.
	 */
	public static ClientInformation parse(final JSONObject jsonObject)
		throws ParseException {
		
		return new ClientInformation(
			ClientCredentialsParser.parseID(jsonObject),
			ClientCredentialsParser.parseIDIssueDate(jsonObject),
			ClientMetadata.parse(jsonObject),
			ClientCredentialsParser.parseSecret(jsonObject),
			ClientCredentialsParser.parseRegistrationURI(jsonObject),
			ClientCredentialsParser.parseRegistrationAccessToken(jsonObject));
	}
}
