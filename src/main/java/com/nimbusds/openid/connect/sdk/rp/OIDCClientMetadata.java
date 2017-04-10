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

package com.nimbusds.openid.connect.sdk.rp;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import com.nimbusds.oauth2.sdk.client.RegistrationError;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.id.SectorID;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.apache.commons.collections.CollectionUtils;


/**
 * OpenID Connect client metadata.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.
 *     <li>OpenID Connect Session Management 1.0, section 5.1.1 (draft 28).
 *     <li>OpenID Connect Front-Channel Logout 1.0, section 2 (draft 02).
 *     <li>OpenID Connect Back-Channel Logout 1.0, section 2.2 (draft 04).
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591), section 2.
 * </ul>
 */
public class OIDCClientMetadata extends ClientMetadata {


	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;


	static {
		// Start with the base OAuth 2.0 client params
		Set<String> p = new HashSet<>(ClientMetadata.getRegisteredParameterNames());

		// OIDC params
		p.add("application_type");
		p.add("subject_type");
		p.add("sector_identifier_uri");
		p.add("request_uris");
		p.add("request_object_signing_alg");
		p.add("request_object_encryption_alg");
		p.add("request_object_encryption_enc");
		p.add("id_token_signed_response_alg");
		p.add("id_token_encrypted_response_alg");
		p.add("id_token_encrypted_response_enc");
		p.add("userinfo_signed_response_alg");
		p.add("userinfo_encrypted_response_alg");
		p.add("userinfo_encrypted_response_enc");
		p.add("default_max_age");
		p.add("require_auth_time");
		p.add("default_acr_values");
		p.add("initiate_login_uri");

		// OIDC session
		p.add("post_logout_redirect_uris");
		
		// OIDC logout
		p.add("frontchannel_logout_uri");
		p.add("frontchannel_logout_session_required");
		p.add("backchannel_logout_uri");
		p.add("backchannel_logout_session_required");

		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}


	/**
	 * The client application type.
	 */
	private ApplicationType applicationType;


	/**
	 * The subject identifier type for responses to this client.
	 */
	private SubjectType subjectType;


	/**
	 * Sector identifier URI.
	 */
	private URI sectorIDURI;
	
	
	/**
	 * Pre-registered OpenID Connect request URIs.
	 */
	private Set<URI> requestObjectURIs;


	/**
	 * The JSON Web Signature (JWS) algorithm required for the OpenID 
	 * Connect request objects sent by this client.
	 */
	private JWSAlgorithm requestObjectJWSAlg;


	/**
	 * The JSON Web Encryption (JWE) algorithm required for the OpenID
	 * Connect request objects sent by this client.
	 */
	private JWEAlgorithm requestObjectJWEAlg;


	/**
	 * The JSON Web Encryption (JWE) method required for the OpenID Connect
	 * request objects sent by this client.
	 */
	private EncryptionMethod requestObjectJWEEnc;


	/**
	 * The JSON Web Signature (JWS) algorithm required for the ID Tokens
	 * issued to this client.
	 */
	private JWSAlgorithm idTokenJWSAlg;


	/**
	 * The JSON Web Encryption (JWE) algorithm required for the ID Tokens
	 * issued to this client.
	 */
	private JWEAlgorithm idTokenJWEAlg;


	/**
	 * The JSON Web Encryption (JWE) method required for the ID Tokens
	 * issued to this client.
	 */
	private EncryptionMethod idTokenJWEEnc;


	/**
	 * The JSON Web Signature (JWS) algorithm required for the UserInfo
	 * responses to this client.
	 */
	private JWSAlgorithm userInfoJWSAlg;


	/**
	 * The JSON Web Encryption (JWE) algorithm required for the UserInfo
	 * responses to this client.
	 */
	private JWEAlgorithm userInfoJWEAlg;


	/**
	 * The JSON Web Encryption (JWE) method required for the UserInfo
	 * responses to this client.
	 */
	private EncryptionMethod userInfoJWEEnc;


	/**
	 * The default max authentication age, in seconds. If not specified 0.
	 */
	private int defaultMaxAge = -1;


	/**
	 * If {@code true} the {@code auth_time} claim in the ID Token is
	 * required by default.
	 */
	private boolean requiresAuthTime;


	/**
	 * The default Authentication Context Class Reference (ACR) values, by
	 * order of preference.
	 */
	private List<ACR> defaultACRs;


	/**
	 * Authorisation server initiated login HTTPS URI.
	 */
	private URI initiateLoginURI;


	/**
	 * Logout redirection URIs.
	 */
	private Set<URI> postLogoutRedirectURIs;
	
	
	/**
	 * Front-channel logout URI.
	 */
	private URI frontChannelLogoutURI;
	
	
	/**
	 * Indicates requirement for a session identifier on front-channel
	 * logout.
	 */
	private boolean frontChannelLogoutSessionRequired = false;
	
	
	/**
	 * Back-channel logout URI.
	 */
	private URI backChannelLogoutURI;
	
	
	/**
	 * Indicates requirement for a session identifier on back-channel
	 * logout.
	 */
	private boolean backChannelLogoutSessionRequired = false;


	/** 
	 * Creates a new OpenID Connect client metadata instance.
	 */
	public OIDCClientMetadata() {

		super();
	}
	
	
	/**
	 * Creates a new OpenID Connect client metadata instance from the
	 * specified base OAuth 2.0 client metadata.
	 * 
	 * @param metadata The base OAuth 2.0 client metadata. Must not be
	 *                 {@code null}.
	 */
	public OIDCClientMetadata(final ClientMetadata metadata) {
		
		super(metadata);
	}


	/**
	 * Gets the registered (standard) OpenID Connect client metadata
	 * parameter names.
	 *
	 * @return The registered OpenID Connect parameter names, as an
	 *         unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {

		return REGISTERED_PARAMETER_NAMES;
	}


	/**
	 * Gets the client application type. Corresponds to the
	 * {@code application_type} client metadata field.
	 *
	 * @return The client application type, {@code null} if not specified.
	 */
	public ApplicationType getApplicationType() {

		return applicationType;
	}


	/**
	 * Sets the client application type. Corresponds to the
	 * {@code application_type} client metadata field.
	 *
	 * @param applicationType The client application type, {@code null} if
	 *                        not specified.
	 */
	public void setApplicationType(final ApplicationType applicationType) {

		this.applicationType = applicationType;
	}


	/**
	 * Gets the subject identifier type for responses to this client. 
	 * Corresponds to the {@code subject_type} client metadata field.
	 *
	 * @return The subject identifier type, {@code null} if not specified.
	 */
	public SubjectType getSubjectType() {

		return subjectType;
	}


	/**
	 * Sets the subject identifier type for responses to this client. 
	 * Corresponds to the {@code subject_type} client metadata field.
	 *
	 * @param subjectType The subject identifier type, {@code null} if not 
	 *                    specified.
	 */
	public void setSubjectType(final SubjectType subjectType) {

		this.subjectType = subjectType;
	}


	/**
	 * Gets the sector identifier URI. Corresponds to the 
	 * {@code sector_identifier_uri} client metadata field.
	 *
	 * @return The sector identifier URI, {@code null} if not specified.
	 */
	public URI getSectorIDURI() {

		return sectorIDURI;
	}


	/**
	 * Sets the sector identifier URI. Corresponds to the 
	 * {@code sector_identifier_uri} client metadata field.
	 *
	 * @param sectorIDURI The sector identifier URI, {@code null} if not 
	 *                    specified.
	 */
	public void setSectorIDURI(final URI sectorIDURI) {

		if (sectorIDURI != null) {
			SectorID.ensureHTTPScheme(sectorIDURI);
			SectorID.ensureHostComponent(sectorIDURI);
		}

		this.sectorIDURI = sectorIDURI;
	}


	/**
	 * Resolves the sector identifier from the client metadata.
	 *
	 * @return The sector identifier, {@code null} if the subject type is
	 *         set to public.
	 *
	 * @throws IllegalStateException If resolution failed due to incomplete
	 *                               or inconsistent metadata.
	 */
	public SectorID resolveSectorID() {

		if (! SubjectType.PAIRWISE.equals(getSubjectType())) {
			// subject type is not pairwise or null
			return null;
		}

		// Check sector identifier URI first
		if (getSectorIDURI() != null) {
			return new SectorID(getSectorIDURI());
		}

		// Check redirect URIs second
		if (CollectionUtils.isEmpty(getRedirectionURIs())) {
			throw new IllegalStateException("Couldn't resolve sector ID: Missing redirect_uris");
		}

		if (getRedirectionURIs().size() > 1) {
			throw new IllegalStateException("Couldn't resolve sector ID: More than one redirect_uri, sector_identifier_uri not specified");
		}

		return new SectorID(getRedirectionURIs().iterator().next());
	}
	
	
	/**
	 * Gets the pre-registered OpenID Connect request object URIs.
	 * Corresponds to the {@code request_uris} client metadata field.
	 * 
	 * @return The request object URIs, {@code null} if not specified.
	 */
	public Set<URI> getRequestObjectURIs() {
		
		return requestObjectURIs;
	}
	
	
	/**
	 * Sets the pre-registered OpenID Connect request object URIs.
	 * Corresponds to the {@code request_uris} client metadata field.
	 *
	 * @param requestObjectURIs The request object URIs, {@code null} if
	 *                          not specified.
	 */
	public void setRequestObjectURIs(final Set<URI> requestObjectURIs) {

		this.requestObjectURIs = requestObjectURIs;
	}


	/**
	 * Gets the JSON Web Signature (JWS) algorithm required for the OpenID 
	 * Connect request objects sent by this client. Corresponds to the 
	 * {@code request_object_signing_alg} client metadata field.
	 *
	 * @return The JWS algorithm, {@code null} if not specified.
	 */
	public JWSAlgorithm getRequestObjectJWSAlg() {

		return requestObjectJWSAlg;
	}


	/**
	 * Sets the JSON Web Signature (JWS) algorithm required for the OpenID 
	 * Connect request objects sent by this client. Corresponds to the 
	 * {@code request_object_signing_alg} client metadata field.
	 *
	 * @param requestObjectJWSAlg The JWS algorithm, {@code null} if not 
	 *                            specified.
	 */
	public void setRequestObjectJWSAlg(final JWSAlgorithm requestObjectJWSAlg) {

		this.requestObjectJWSAlg = requestObjectJWSAlg;
	}


	/**
	 * Gets the JSON Web Encryption (JWE) algorithm required for the OpenID
	 * Connect request objects sent by this client. Corresponds to the
	 * {@code request_object_encryption_alg} client metadata field.
	 *
	 * @return The JWE algorithm, {@code null} if not specified.
	 */
	public JWEAlgorithm getRequestObjectJWEAlg() {

		return requestObjectJWEAlg;
	}


	/**
	 * Sets the JSON Web Encryption (JWE) algorithm required for the OpenID
	 * Connect request objects sent by this client. Corresponds to the
	 * {@code request_object_encryption_alg} client metadata field.
	 *
	 * @param requestObjectJWEAlg The JWE algorithm, {@code null} if not
	 *                            specified.
	 */
	public void setRequestObjectJWEAlg(final JWEAlgorithm requestObjectJWEAlg) {

		this.requestObjectJWEAlg = requestObjectJWEAlg;
	}


	/**
	 * Gets the JSON Web Encryption (JWE) method required for the OpenID
	 * Connect request objects sent by this client. Corresponds to the
	 * {@code request_object_encryption_enc} client metadata field.
	 *
	 * @return The JWE method, {@code null} if not specified.
	 */
	public EncryptionMethod getRequestObjectJWEEnc() {

		return requestObjectJWEEnc;
	}


	/**
	 * Sets the JSON Web Encryption (JWE) method required for the OpenID
	 * Connect request objects sent by this client. Corresponds to the
	 * {@code request_object_encryption_enc} client metadata field.
	 *
	 * @param requestObjectJWEEnc The JWE method, {@code null} if not
	 *                            specified.
	 */
	public void setRequestObjectJWEEnc(final EncryptionMethod requestObjectJWEEnc) {

		this.requestObjectJWEEnc = requestObjectJWEEnc;
	}


	/**
	 * Gets the JSON Web Signature (JWS) algorithm required for the ID 
	 * Tokens issued to this client. Corresponds to the 
	 * {@code id_token_signed_response_alg} client metadata field.
	 *
	 * @return The JWS algorithm, {@code null} if not specified.
	 */
	public JWSAlgorithm getIDTokenJWSAlg() {

		return idTokenJWSAlg;
	}


	/**
	 * Sets the JSON Web Signature (JWS) algorithm required for the ID 
	 * Tokens issued to this client. Corresponds to the 
	 * {@code id_token_signed_response_alg} client metadata field.
	 *
	 * @param idTokenJWSAlg The JWS algorithm, {@code null} if not 
	 *                      specified.
	 */
	public void setIDTokenJWSAlg(final JWSAlgorithm idTokenJWSAlg) {

		this.idTokenJWSAlg = idTokenJWSAlg;
	}


	/**
	 * Gets the JSON Web Encryption (JWE) algorithm required for the ID 
	 * Tokens issued to this client. Corresponds to the 
	 * {@code id_token_encrypted_response_alg} client metadata field.
	 *
	 * @return The JWE algorithm, {@code null} if not specified.
	 */
	public JWEAlgorithm getIDTokenJWEAlg() {

		return idTokenJWEAlg;
	}


	/**
	 * Sets the JSON Web Encryption (JWE) algorithm required for the ID 
	 * Tokens issued to this client. Corresponds to the 
	 * {@code id_token_encrypted_response_alg} client metadata field.
	 *
	 * @param idTokenJWEAlg The JWE algorithm, {@code null} if not 
	 *                      specified.
	 */
	public void setIDTokenJWEAlg(final JWEAlgorithm idTokenJWEAlg) {

		this.idTokenJWEAlg = idTokenJWEAlg;
	}


	/**
	 * Gets the JSON Web Encryption (JWE) method required for the ID Tokens
	 * issued to this client. Corresponds to the 
	 * {@code id_token_encrypted_response_enc} client metadata field.
	 *
	 * @return The JWE method, {@code null} if not specified.
	 */
	public EncryptionMethod getIDTokenJWEEnc() {

		return idTokenJWEEnc;
	}


	/**
	 * Sets the JSON Web Encryption (JWE) method required for the ID Tokens
	 * issued to this client. Corresponds to the 
	 * {@code id_token_encrypted_response_enc} client metadata field.
	 *
	 * @param idTokenJWEEnc The JWE method, {@code null} if not specified.
	 */
	public void setIDTokenJWEEnc(final EncryptionMethod idTokenJWEEnc) {

		this.idTokenJWEEnc = idTokenJWEEnc;
	}


	/**
	 * Gets the JSON Web Signature (JWS) algorithm required for the 
	 * UserInfo responses to this client. Corresponds to the 
	 * {@code userinfo_signed_response_alg} client metadata field.
	 *
	 * @return The JWS algorithm, {@code null} if not specified.
	 */
	public JWSAlgorithm getUserInfoJWSAlg() {

		return userInfoJWSAlg;
	}


	/**
	 * Sets the JSON Web Signature (JWS) algorithm required for the 
	 * UserInfo responses to this client. Corresponds to the
	 * {@code userinfo_signed_response_alg} client metadata field.
	 *
	 * @param userInfoJWSAlg The JWS algorithm, {@code null} if not 
	 *                       specified.
	 */
	public void setUserInfoJWSAlg(final JWSAlgorithm userInfoJWSAlg) {

		this.userInfoJWSAlg = userInfoJWSAlg;
	}


	/**
	 * Gets the JSON Web Encryption (JWE) algorithm required for the 
	 * UserInfo responses to this client. Corresponds to the 
	 * {@code userinfo_encrypted_response_alg} client metadata field.
	 *
	 * @return The JWE algorithm, {@code null} if not specified.
	 */
	public JWEAlgorithm getUserInfoJWEAlg() {

		return userInfoJWEAlg;
	}


	/**
	 * Sets the JSON Web Encryption (JWE) algorithm required for the 
	 * UserInfo responses to this client. Corresponds to the 
	 * {@code userinfo_encrypted_response_alg} client metadata field.
	 *
	 * @param userInfoJWEAlg The JWE algorithm, {@code null} if not
	 *                       specified.
	 */
	public void setUserInfoJWEAlg(final JWEAlgorithm userInfoJWEAlg) {

		this.userInfoJWEAlg = userInfoJWEAlg;
	}


	/**
	 * Gets the JSON Web Encryption (JWE) method required for the UserInfo
	 * responses to this client. Corresponds to the 
	 * {@code userinfo_encrypted_response_enc} client metadata field.
	 *
	 * @return The JWE method, {@code null} if not specified.
	 */
	public EncryptionMethod getUserInfoJWEEnc() {

		return userInfoJWEEnc;
	}


	/**
	 * Sets the JSON Web Encryption (JWE) method required for the UserInfo
	 * responses to this client. Corresponds to the 
	 * {@code userinfo_encrypted_response_enc} client metadata field.
	 *
	 * @param userInfoJWEEnc The JWE method, {@code null} if not specified.
	 */
	public void setUserInfoJWEEnc(final EncryptionMethod userInfoJWEEnc) {

		this.userInfoJWEEnc = userInfoJWEEnc;
	}


	/**
	 * Gets the default maximum authentication age. Corresponds to the 
	 * {@code default_max_age} client metadata field.
	 *
	 * @return The default max authentication age, in seconds. If not
	 *         specified -1.
	 */
	public int getDefaultMaxAge() {

		return defaultMaxAge;
	}


	/**
	 * Sets the default maximum authentication age. Corresponds to the 
	 * {@code default_max_age} client metadata field.
	 *
	 * @param defaultMaxAge The default max authentication age, in seconds.
	 *                      If not specified -1.
	 */
	public void setDefaultMaxAge(final int defaultMaxAge) {

		this.defaultMaxAge = defaultMaxAge;
	}


	/**
	 * Gets the default requirement for the {@code auth_time} claim in the
	 * ID Token. Corresponds to the {@code require_auth_time} client 
	 * metadata field.
	 *
	 * @return If {@code true} the {@code auth_Time} claim in the ID Token 
	 *         is required by default.
	 */
	public boolean requiresAuthTime() {

		return requiresAuthTime;
	}


	/**
	 * Sets the default requirement for the {@code auth_time} claim in the
	 * ID Token. Corresponds to the {@code require_auth_time} client 
	 * metadata field.
	 *
	 * @param requiresAuthTime If {@code true} the {@code auth_Time} claim 
	 *                         in the ID Token is required by default.
	 */
	public void requiresAuthTime(final boolean requiresAuthTime) {

		this.requiresAuthTime = requiresAuthTime;
	}


	/**
	 * Gets the default Authentication Context Class Reference (ACR) 
	 * values. Corresponds to the {@code default_acr_values} client 
	 * metadata field.
	 *
	 * @return The default ACR values, by order of preference, 
	 *         {@code null} if not specified.
	 */
	public List<ACR> getDefaultACRs() {

		return defaultACRs;
	}


	/**
	 * Sets the default Authentication Context Class Reference (ACR)
	 * values. Corresponds to the {@code default_acr_values} client 
	 * metadata field.
	 *
	 * @param defaultACRs The default ACRs, by order of preference, 
	 *                    {@code null} if not specified.
	 */
	public void setDefaultACRs(final List<ACR> defaultACRs) {

		this.defaultACRs = defaultACRs;
	}


	/**
	 * Gets the HTTPS URI that the authorisation server can call to
	 * initiate a login at the client. Corresponds to the 
	 * {@code initiate_login_uri} client metadata field.
	 *
	 * @return The login URI, {@code null} if not specified.
	 */
	public URI getInitiateLoginURI() {

		return initiateLoginURI;
	}


	/**
	 * Sets the HTTPS URI that the authorisation server can call to
	 * initiate a login at the client. Corresponds to the 
	 * {@code initiate_login_uri} client metadata field.
	 *
	 * @param loginURI The login URI, {@code null} if not specified.
	 */
	public void setInitiateLoginURI(final URI loginURI) {

		this.initiateLoginURI = loginURI;
	}


	/**
	 * Gets the post logout redirection URIs. Corresponds to the
	 * {@code post_logout_redirect_uris} client metadata field.
	 *
	 * @return The logout redirection URIs, {@code null} if not specified.
	 */
	public Set<URI> getPostLogoutRedirectionURIs() {

		return postLogoutRedirectURIs;
	}


	/**
	 * Sets the post logout redirection URIs. Corresponds to the
	 * {@code post_logout_redirect_uris} client metadata field.
	 *
	 * @param logoutURIs The logout redirection URIs, {@code null} if not
	 *                   specified.
	 */
	public void setPostLogoutRedirectionURIs(final Set<URI> logoutURIs) {

		postLogoutRedirectURIs = logoutURIs;
	}
	
	
	/**
	 * Gets the front-channel logout URI. Corresponds to the
	 * {@code frontchannel_logout_uri} client metadata field.
	 *
	 * @return The front-channel logout URI, {@code null} if not specified.
	 */
	public URI getFrontChannelLogoutURI() {
		
		return frontChannelLogoutURI;
	}
	
	
	/**
	 * Sets the front-channel logout URI. Corresponds to the
	 * {@code frontchannel_logout_uri} client metadata field.
	 *
	 * @param frontChannelLogoutURI The front-channel logout URI,
	 *                              {@code null} if not specified.
	 */
	public void setFrontChannelLogoutURI(final URI frontChannelLogoutURI) {
		
		this.frontChannelLogoutURI = frontChannelLogoutURI;
	}
	
	
	/**
	 * Gets the requirement for a session identifier on front-channel
	 * logout. Corresponds to
	 * the {@code frontchannel_logout_session_required} client metadata
	 * field.
	 *
	 * @return {@code true} if a session identifier is required, else
	 *         {@code false}.
	 */
	public boolean requiresFrontChannelLogoutSession() {
		
		return frontChannelLogoutSessionRequired;
	}
	
	
	/**
	 * Sets the requirement for a session identifier on front-channel
	 * logout. Corresponds to
	 * the {@code frontchannel_logout_session_required} client metadata
	 * field.
	 *
	 * @param requiresSession  {@code true} if a session identifier is
	 *                         required, else {@code false}.
	 */
	public void requiresFrontChannelLogoutSession(boolean requiresSession) {
		
		frontChannelLogoutSessionRequired = requiresSession;
	}
	
	
	/**
	 * Gets the back-channel logout URI. Corresponds to the
	 * {@code backchannel_logout_uri} client metadata field.
	 *
	 * @return The back-channel logout URI, {@code null} if not specified.
	 */
	public URI getBackChannelLogoutURI() {
		
		return backChannelLogoutURI;
	}
	
	
	/**
	 * Sets the back-channel logout URI. Corresponds to the
	 * {@code backchannel_logout_uri} client metadata field.
	 *
	 * @param backChannelLogoutURI The back-channel logout URI,
	 *                             {@code null} if not specified.
	 */
	public void setBackChannelLogoutURI(final URI backChannelLogoutURI) {
		
		this.backChannelLogoutURI = backChannelLogoutURI;
	}
	
	
	/**
	 * Gets the requirement for a session identifier on back-channel
	 * logout. Corresponds to
	 * the {@code backchannel_logout_session_required} client metadata
	 * field.
	 *
	 * @return {@code true} if a session identifier is required, else
	 *         {@code false}.
	 */
	public boolean requiresBackChannelLogoutSession() {
		
		return backChannelLogoutSessionRequired;
	}
	
	
	/**
	 * Sets the requirement for a session identifier on back-channel
	 * logout. Corresponds to
	 * the {@code backchannel_logout_session_required} client metadata
	 * field.
	 *
	 * @param requiresSession  {@code true} if a session identifier is
	 *                         required, else {@code false}.
	 */
	public void requiresBackChannelLogoutSession(final boolean requiresSession) {
		
		backChannelLogoutSessionRequired = requiresSession;
	}
	
	
	/**
	 * Applies the client metadata defaults where no values have been
	 * specified.
	 * 
	 * <ul>
	 *     <li>The response types default to {@code ["code"]}.
	 *     <li>The grant types default to {@code "authorization_code".}
	 *     <li>The client authentication method defaults to
	 *         "client_secret_basic".
	 *     <li>The application type defaults to
	 *         {@link ApplicationType#WEB}.
	 *     <li>The ID token JWS algorithm defaults to "RS256".
	 * </ul>
	 */
	@Override
	public void applyDefaults() {
		
		super.applyDefaults();

		if (applicationType == null) {
			applicationType = ApplicationType.WEB;
		}
		
		if (idTokenJWSAlg == null) {
			idTokenJWSAlg = JWSAlgorithm.RS256;
		}
	}


	@Override
	public JSONObject toJSONObject(boolean includeCustomFields) {

		JSONObject o = super.toJSONObject(includeCustomFields);

		o.putAll(getCustomFields());

		if (applicationType != null)
			o.put("application_type", applicationType.toString());

		if (subjectType != null)
			o.put("subject_type", subjectType.toString());


		if (sectorIDURI != null)
			o.put("sector_identifier_uri", sectorIDURI.toString());
		
		
		if (requestObjectURIs != null) {
			
			JSONArray uriList = new JSONArray();
			
			for (URI uri: requestObjectURIs)
				uriList.add(uri.toString());
			
			o.put("request_uris", uriList);
		}


		if (requestObjectJWSAlg != null)
			o.put("request_object_signing_alg", requestObjectJWSAlg.getName());

		if (requestObjectJWEAlg != null)
			o.put("request_object_encryption_alg", requestObjectJWEAlg.getName());

		if (requestObjectJWEEnc != null)
			o.put("request_object_encryption_enc", requestObjectJWEEnc.getName());


		if (idTokenJWSAlg != null)
			o.put("id_token_signed_response_alg", idTokenJWSAlg.getName());


		if (idTokenJWEAlg != null)
			o.put("id_token_encrypted_response_alg", idTokenJWEAlg.getName());


		if (idTokenJWEEnc != null)
			o.put("id_token_encrypted_response_enc", idTokenJWEEnc.getName());


		if (userInfoJWSAlg != null)
			o.put("userinfo_signed_response_alg", userInfoJWSAlg.getName());


		if (userInfoJWEAlg != null)
			o.put("userinfo_encrypted_response_alg", userInfoJWEAlg.getName());


		if (userInfoJWEEnc != null)
			o.put("userinfo_encrypted_response_enc", userInfoJWEEnc.getName());


		if (defaultMaxAge > 0)
			o.put("default_max_age", defaultMaxAge);


		if (requiresAuthTime())
			o.put("require_auth_time", requiresAuthTime);


		if (defaultACRs != null) {

			JSONArray acrList = new JSONArray();

			for (ACR acr: defaultACRs)
				acrList.add(acr);

			o.put("default_acr_values", acrList);
		}


		if (initiateLoginURI != null)
			o.put("initiate_login_uri", initiateLoginURI.toString());


		if (postLogoutRedirectURIs != null) {

			JSONArray uriList = new JSONArray();

			for (URI uri: postLogoutRedirectURIs)
				uriList.add(uri.toString());

			o.put("post_logout_redirect_uris", uriList);
		}
		
		if (frontChannelLogoutURI != null) {
			o.put("frontchannel_logout_uri", frontChannelLogoutURI.toString());
			o.put("frontchannel_logout_session_required", frontChannelLogoutSessionRequired);
		}
		
		if (backChannelLogoutURI != null) {
			o.put("backchannel_logout_uri", backChannelLogoutURI.toString());
			o.put("backchannel_logout_session_required", backChannelLogoutSessionRequired);
		}

		return o;
	}


	/**
	 * Parses an OpenID Connect client metadata instance from the specified
	 * JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The OpenID Connect client metadata.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OpenID Connect client metadata instance.
	 */
	public static OIDCClientMetadata parse(final JSONObject jsonObject)
		throws ParseException {

		ClientMetadata baseMetadata = ClientMetadata.parse(jsonObject);
		
		OIDCClientMetadata metadata = new OIDCClientMetadata(baseMetadata);

		// Parse the OIDC-specific fields from the custom OAuth 2.0 dyn
		// reg fields

		JSONObject oidcFields = baseMetadata.getCustomFields();

		try {
			if (jsonObject.get("application_type") != null) {
				metadata.setApplicationType(JSONObjectUtils.getEnum(jsonObject, "application_type", ApplicationType.class));
				oidcFields.remove("application_type");
			}

			if (jsonObject.get("subject_type") != null) {
				metadata.setSubjectType(JSONObjectUtils.getEnum(jsonObject, "subject_type", SubjectType.class));
				oidcFields.remove("subject_type");
			}

			if (jsonObject.get("sector_identifier_uri") != null) {
				metadata.setSectorIDURI(JSONObjectUtils.getURI(jsonObject, "sector_identifier_uri"));
				oidcFields.remove("sector_identifier_uri");
			}

			if (jsonObject.get("request_uris") != null) {

				Set<URI> requestURIs = new LinkedHashSet<>();

				for (String uriString : JSONObjectUtils.getStringArray(jsonObject, "request_uris")) {

					try {
						requestURIs.add(new URI(uriString));

					} catch (URISyntaxException e) {

						throw new ParseException("Invalid \"request_uris\" parameter");
					}
				}

				metadata.setRequestObjectURIs(requestURIs);
				oidcFields.remove("request_uris");
			}

			if (jsonObject.get("request_object_signing_alg") != null) {
				metadata.setRequestObjectJWSAlg(JWSAlgorithm.parse(
					JSONObjectUtils.getString(jsonObject, "request_object_signing_alg")));

				oidcFields.remove("request_object_signing_alg");
			}

			if (jsonObject.get("request_object_encryption_alg") != null) {
				metadata.setRequestObjectJWEAlg(JWEAlgorithm.parse(
					JSONObjectUtils.getString(jsonObject, "request_object_encryption_alg")));

				oidcFields.remove("request_object_encryption_alg");
			}

			if (jsonObject.get("request_object_encryption_enc") != null) {
				metadata.setRequestObjectJWEEnc(EncryptionMethod.parse(
					JSONObjectUtils.getString(jsonObject, "request_object_encryption_enc")));

				oidcFields.remove("request_object_encryption_enc");
			}

			if (jsonObject.get("id_token_signed_response_alg") != null) {
				metadata.setIDTokenJWSAlg(JWSAlgorithm.parse(
					JSONObjectUtils.getString(jsonObject, "id_token_signed_response_alg")));

				oidcFields.remove("id_token_signed_response_alg");
			}

			if (jsonObject.get("id_token_encrypted_response_alg") != null) {
				metadata.setIDTokenJWEAlg(JWEAlgorithm.parse(
					JSONObjectUtils.getString(jsonObject, "id_token_encrypted_response_alg")));

				oidcFields.remove("id_token_encrypted_response_alg");
			}

			if (jsonObject.get("id_token_encrypted_response_enc") != null) {
				metadata.setIDTokenJWEEnc(EncryptionMethod.parse(
					JSONObjectUtils.getString(jsonObject, "id_token_encrypted_response_enc")));

				oidcFields.remove("id_token_encrypted_response_enc");
			}

			if (jsonObject.get("userinfo_signed_response_alg") != null) {
				metadata.setUserInfoJWSAlg(JWSAlgorithm.parse(
					JSONObjectUtils.getString(jsonObject, "userinfo_signed_response_alg")));

				oidcFields.remove("userinfo_signed_response_alg");
			}

			if (jsonObject.get("userinfo_encrypted_response_alg") != null) {
				metadata.setUserInfoJWEAlg(JWEAlgorithm.parse(
					JSONObjectUtils.getString(jsonObject, "userinfo_encrypted_response_alg")));

				oidcFields.remove("userinfo_encrypted_response_alg");
			}

			if (jsonObject.get("userinfo_encrypted_response_enc") != null) {
				metadata.setUserInfoJWEEnc(EncryptionMethod.parse(
					JSONObjectUtils.getString(jsonObject, "userinfo_encrypted_response_enc")));

				oidcFields.remove("userinfo_encrypted_response_enc");
			}

			if (jsonObject.get("default_max_age") != null) {
				metadata.setDefaultMaxAge(JSONObjectUtils.getInt(jsonObject, "default_max_age"));
				oidcFields.remove("default_max_age");
			}

			if (jsonObject.get("require_auth_time") != null) {
				metadata.requiresAuthTime(JSONObjectUtils.getBoolean(jsonObject, "require_auth_time"));
				oidcFields.remove("require_auth_time");
			}

			if (jsonObject.get("default_acr_values") != null) {

				List<ACR> acrValues = new LinkedList<>();

				for (String acrString : JSONObjectUtils.getStringArray(jsonObject, "default_acr_values"))
					acrValues.add(new ACR(acrString));

				metadata.setDefaultACRs(acrValues);

				oidcFields.remove("default_acr_values");
			}

			if (jsonObject.get("initiate_login_uri") != null) {
				metadata.setInitiateLoginURI(JSONObjectUtils.getURI(jsonObject, "initiate_login_uri"));
				oidcFields.remove("initiate_login_uri");
			}

			if (jsonObject.get("post_logout_redirect_uris") != null) {

				Set<URI> logoutURIs = new LinkedHashSet<>();

				for (String uriString : JSONObjectUtils.getStringArray(jsonObject, "post_logout_redirect_uris")) {

					try {
						logoutURIs.add(new URI(uriString));

					} catch (URISyntaxException e) {

						throw new ParseException("Invalid \"post_logout_redirect_uris\" parameter");
					}
				}

				metadata.setPostLogoutRedirectionURIs(logoutURIs);
				oidcFields.remove("post_logout_redirect_uris");
			}
			
			if (jsonObject.get("frontchannel_logout_uri") != null) {
				
				metadata.setFrontChannelLogoutURI(JSONObjectUtils.getURI(jsonObject, "frontchannel_logout_uri"));
			
				if (jsonObject.get("frontchannel_logout_session_required") != null) {
					metadata.requiresFrontChannelLogoutSession(JSONObjectUtils.getBoolean(jsonObject, "frontchannel_logout_session_required"));
				}
			}
			
			
			if (jsonObject.get("backchannel_logout_uri") != null) {
				
				metadata.setBackChannelLogoutURI(JSONObjectUtils.getURI(jsonObject, "backchannel_logout_uri"));
				
				if (jsonObject.get("backchannel_logout_session_required") != null) {
					metadata.requiresBackChannelLogoutSession(JSONObjectUtils.getBoolean(jsonObject, "backchannel_logout_session_required"));
				}
			}
			
			
		} catch (ParseException e) {
			// Insert client_client_metadata error code so that it
			// can be reported back to the client if we have a
			// registration event
			throw new ParseException(e.getMessage(), RegistrationError.INVALID_CLIENT_METADATA.appendDescription(": " + e.getMessage()), e.getCause());
		}

		// The remaining fields are custom
		metadata.setCustomFields(oidcFields);

		return metadata;
	}
}
