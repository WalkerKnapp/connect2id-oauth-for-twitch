/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2022 Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.op;


import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerEndpointMetadata;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequestConfigurator;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.assurance.IdentityTrustFramework;
import com.nimbusds.openid.connect.sdk.assurance.evidences.*;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.AttachmentType;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.HashAlgorithm;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimType;
import com.nimbusds.openid.connect.sdk.federation.registration.ClientRegistrationType;
import net.minidev.json.JSONObject;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.*;


/**
 * OpenID Provider (OP) metadata.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Discovery 1.0
 *     <li>OpenID Connect Session Management 1.0
 *     <li>OpenID Connect Front-Channel Logout 1.0
 *     <li>OpenID Connect Back-Channel Logout 1.0
 *     <li>OpenID Connect Native SSO for Mobile Apps 1.0
 *     <li>OpenID Connect for Identity Assurance 1.0
 *     <li>OpenID Connect Federation 1.0
 *     <li>Initiating User Registration via OpenID Connect 1.0
 *     <li>OAuth 2.0 Authorization Server Metadata (RFC 8414)
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (RFC 8705)
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM)
 *     <li>OAuth 2.0 Authorization Server Issuer Identification (RFC 9207)
 *     <li>Financial-grade API - Part 2: Read and Write API Security Profile
 *     <li>OAuth 2.0 Pushed Authorization Requests (RFC 9126)
 *     <li>OAuth 2.0 Rich Authorization Requests (RFC 9396)
 *     <li>OAuth 2.0 Device Authorization Grant (RFC 8628)
 *     <li>OAuth 2.0 Incremental Authorization (draft-ietf-oauth-incremental-authz)
 * </ul>
 */
public class OIDCProviderMetadata extends AuthorizationServerMetadata implements ReadOnlyOIDCProviderMetadata {


	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;


	static {
		Set<String> p = new HashSet<>(AuthorizationServerMetadata.getRegisteredParameterNames());
		p.addAll(OIDCProviderEndpointMetadata.getRegisteredParameterNames());
		p.add("acr_values_supported");
		p.add("subject_types_supported");
		p.add("id_token_signing_alg_values_supported");
		p.add("id_token_encryption_alg_values_supported");
		p.add("id_token_encryption_enc_values_supported");
		p.add("userinfo_signing_alg_values_supported");
		p.add("userinfo_encryption_alg_values_supported");
		p.add("userinfo_encryption_enc_values_supported");
		p.add("display_values_supported");
		p.add("claim_types_supported");
		p.add("claims_supported");
		p.add("claims_locales_supported");
		p.add("claims_parameter_supported");
		p.add("backchannel_logout_supported");
		p.add("backchannel_logout_session_supported");
		p.add("frontchannel_logout_supported");
		p.add("native_sso_supported");
		p.add("frontchannel_logout_session_supported");
		p.add("verified_claims_supported");
		p.add("trust_frameworks_supported");
		p.add("evidence_supported");
		p.add("documents_supported");
		p.add("documents_methods_supported");
		p.add("documents_validation_methods_supported");
		p.add("documents_verification_methods_supported");
		p.add("id_documents_supported"); // deprecated
		p.add("id_documents_verification_methods_supported"); // deprecated
		p.add("electronic_records_supported");
		p.add("claims_in_verified_claims_supported");
		p.add("attachments_supported");
		p.add("digest_algorithms_supported");
		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}


	/**
	 * The UserInfo endpoint.
	 */
	private URI userInfoEndpoint;
	
	
	/**
	 * The cross-origin check session iframe.
	 */
	private URI checkSessionIframe;
	
	
	/**
	 * The logout endpoint.
	 */
	private URI endSessionEndpoint;


	/**
	 * The supported ACRs.
	 */
	private List<ACR> acrValues;


	/**
	 * The supported subject types.
	 */
	private final List<SubjectType> subjectTypes;


	/**
	 * The supported ID token JWS algorithms.
	 */
	private List<JWSAlgorithm> idTokenJWSAlgs;


	/**
	 * The supported ID token JWE algorithms.
	 */
	private List<JWEAlgorithm> idTokenJWEAlgs;


	/**
	 * The supported ID token encryption methods.
	 */
	private List<EncryptionMethod> idTokenJWEEncs;


	/**
	 * The supported UserInfo JWS algorithms.
	 */
	private List<JWSAlgorithm> userInfoJWSAlgs;


	/**
	 * The supported UserInfo JWE algorithms.
	 */
	private List<JWEAlgorithm> userInfoJWEAlgs;


	/**
	 * The supported UserInfo encryption methods.
	 */
	private List<EncryptionMethod> userInfoJWEEncs;


	/**
	 * The supported displays.
	 */
	private List<Display> displays;
	
	
	/**
	 * The supported claim types.
	 */
	private List<ClaimType> claimTypes;


	/**
	 * The supported claims names.
	 */
	private List<String> claims;
	
	
	/**
	 * The supported claims locales.
	 */
	private List<LangTag> claimsLocales;
	
	
	/**
	 * If {@code true} the {@code claims} parameter is supported, else not.
	 */
	private boolean claimsParamSupported = false;
	
	
	/**
	 * If {@code true} the {@code frontchannel_logout_supported} parameter
	 * is set, else not.
	 */
	private boolean frontChannelLogoutSupported = false;
	
	
	/**
	 * If {@code true} the {@code frontchannel_logout_session_supported}
	 * parameter is set, else not.
	 */
	private boolean frontChannelLogoutSessionSupported = false;
	
	
	/**
	 * If {@code true} the {@code backchannel_logout_supported} parameter
	 * is set, else not.
	 */
	private boolean backChannelLogoutSupported = false;
	
	
	/**
	 * If {@code true} the {@code backchannel_logout_session_supported}
	 * parameter is set, else not.
	 */
	private boolean backChannelLogoutSessionSupported = false;


	/**
	 * If {@code true} the {@code native_sso_supported} parameter is set,
	 * else not.
	 */
	private boolean nativeSSOSupported = false;
	
	
	/**
	 * If {@code true} verified claims are supported.
	 */
	private boolean verifiedClaimsSupported = false;
	
	
	/**
	 * The supported trust frameworks.
	 */
	private List<IdentityTrustFramework> trustFrameworks;
	
	
	/**
	 * The supported identity evidence types.
	 */
	private List<IdentityEvidenceType> evidenceTypes;
	
	
	/**
	 * The supported identity document types.
	 */
	private List<DocumentType> documentTypes;
	
	
	/**
	 * The supported coarse identity verification methods for evidences of
	 * type document.
	 */
	private List<IdentityVerificationMethod> documentMethods;
	
	
	/**
	 * The supported validation methods for evidences of type document.
	 */
	private List<ValidationMethodType> documentValidationMethods;
	
	
	/**
	 * The supported verification methods for evidences of type document.
	 */
	private List<VerificationMethodType> documentVerificationMethods;
	
	
	/**
	 * The supported identity document types.
	 */
	@Deprecated
	private List<IDDocumentType> idDocumentTypes;
	
	
	/**
	 * The supported verification methods for identity documents.
	 */
	@Deprecated
	private List<IdentityVerificationMethod> idVerificationMethods;
	
	
	/**
	 * The supported electronic record types.
	 */
	private List<ElectronicRecordType> electronicRecordTypes;
	
	
	/**
	 * The supported verified claims.
	 */
	private List<String> verifiedClaims;
	
	
	/**
	 * The supported attachment types.
	 */
	private List<AttachmentType> attachmentTypes;
	
	
	/**
	 * The supported digest algorithms for external attachments.
	 */
	private List<HashAlgorithm> attachmentDigestAlgs;


	/**
	 * Creates a new OpenID Connect provider metadata instance.
	 * 
	 * @param issuer       The issuer identifier. Must be a URI using the
	 *                     https scheme with no query or fragment 
	 *                     component. Must not be {@code null}.
	 * @param subjectTypes The supported subject types. At least one must
	 *                     be specified. Must not be {@code null}.
	 * @param jwkSetURI    The JWK set URI. Must not be {@code null}.
	 */
	public OIDCProviderMetadata(final Issuer issuer,
				    final List<SubjectType> subjectTypes,
				    final URI jwkSetURI) {
	
		super(issuer);
		
		ensureAtLeastOneSubjectType(subjectTypes);
		this.subjectTypes = subjectTypes;
		setJWKSetURI(Objects.requireNonNull(jwkSetURI));
		
		// Default OpenID Connect setting is supported
		setSupportsRequestURIParam(true);
	}


	/**
	 * Creates a new OpenID Connect Federation 1.0 provider metadata
	 * instance. The provider JWK set should be specified by
	 * {@code jwks_uri}, {@code signed_jwks_uri} or {@code jwks}.
	 *
	 * @param issuer                  The issuer identifier. Must be a URI
	 *                                using the https scheme with no query
	 *                                or fragment component. Must not be
	 *                                {@code null}.
	 * @param subjectTypes            The supported subject types. At least
	 *                                one must be specified. Must not be
	 *                                {@code null}.
	 * @param clientRegistrationTypes The supported client registration
	 *                                types. At least one must be
	 *                                specified. Must not be {@code null}.
	 * @param jwkSetURI               The JWK set URI, {@code null} if
	 *                                specified by another field.
	 * @param signedJWKSetURI         The signed JWK set URI, {@code null}
	 *                                if specified by another field.
	 * @param jwkSet                  the JWK set, {@code null} if
	 *                                specified by another field.
	 */
	public OIDCProviderMetadata(final Issuer issuer,
				    final List<SubjectType> subjectTypes,
				    final List<ClientRegistrationType> clientRegistrationTypes,
				    final URI jwkSetURI,
				    final URI signedJWKSetURI,
				    final JWKSet jwkSet) {
	
		super(issuer);
		
		ensureAtLeastOneSubjectType(subjectTypes);
		this.subjectTypes = subjectTypes;
		
		if (clientRegistrationTypes.size() < 1) {
			throw new IllegalArgumentException("At least one federation client registration type must be specified");
		}
		setClientRegistrationTypes(clientRegistrationTypes);
		
		if (jwkSetURI == null && signedJWKSetURI == null && jwkSet == null) {
			throw new IllegalArgumentException("At least one public JWK must be specified");
		}

		setJWKSetURI(jwkSetURI);
		setSignedJWKSetURI(signedJWKSetURI);
		setJWKSet(jwkSet);
		
		// Default OpenID Connect setting is supported
		setSupportsRequestURIParam(true);
	}
	
	
	private void ensureAtLeastOneSubjectType(final List<SubjectType> subjectTypes) {
		if (subjectTypes.size() < 1)
			throw new IllegalArgumentException("At least one supported subject type must be specified");
	}
	
	
	@Override
	public void setMtlsEndpointAliases(AuthorizationServerEndpointMetadata mtlsEndpointAliases) {
		if (mtlsEndpointAliases != null && !(mtlsEndpointAliases instanceof OIDCProviderEndpointMetadata)) {
			// convert the provided endpoints to OIDC
			super.setMtlsEndpointAliases(new OIDCProviderEndpointMetadata(mtlsEndpointAliases));
		} else {
			super.setMtlsEndpointAliases(mtlsEndpointAliases);
		}
	}
	
	
	@Override
	public OIDCProviderEndpointMetadata getReadOnlyMtlsEndpointAliases() {
		return getMtlsEndpointAliases();
	}
	
	
	@Override
	public OIDCProviderEndpointMetadata getMtlsEndpointAliases() {
		return (OIDCProviderEndpointMetadata) super.getMtlsEndpointAliases();
	}


	/**
	 * Gets the registered OpenID Connect provider metadata parameter
	 * names.
	 *
	 * @return The registered OpenID Connect provider metadata parameter
	 *         names, as an unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {
		return REGISTERED_PARAMETER_NAMES;
	}


	@Override
	public URI getUserInfoEndpointURI() {
		return userInfoEndpoint;
	}


	/**
	 * Sets the UserInfo endpoint URI. Corresponds the
	 * {@code userinfo_endpoint} metadata field.
	 *
	 * @param userInfoEndpoint The UserInfo endpoint URI, {@code null} if
	 *                         not specified.
	 */
	public void setUserInfoEndpointURI(final URI userInfoEndpoint) {
		this.userInfoEndpoint = userInfoEndpoint;
	}
	
	
	@Override
	public URI getCheckSessionIframeURI() {
		return checkSessionIframe;
	}


	/**
	 * Sets the cross-origin check session iframe URI. Corresponds to the
	 * {@code check_session_iframe} metadata field.
	 *
	 * @param checkSessionIframe The check session iframe URI, {@code null}
	 *                           if not specified.
	 */
	public void setCheckSessionIframeURI(final URI checkSessionIframe) {
		this.checkSessionIframe = checkSessionIframe;
	}
	
	
	@Override
	public URI getEndSessionEndpointURI() {
		return endSessionEndpoint;
	}


	/**
	 * Sets the logout endpoint URI. Corresponds to the
	 * {@code end_session_endpoint} metadata field.
	 *
	 * @param endSessionEndpoint The logoout endpoint URI, {@code null} if
	 *                           not specified.
	 */
	public void setEndSessionEndpointURI(final URI endSessionEndpoint) {
		this.endSessionEndpoint = endSessionEndpoint;
	}

	@Override
	public List<ACR> getACRs() {
		return acrValues;
	}


	/**
	 * Sets the supported Authentication Context Class References (ACRs).
	 * Corresponds to the {@code acr_values_supported} metadata field.
	 *
	 * @param acrValues The supported ACRs, {@code null} if not specified.
	 */
	public void setACRs(final List<ACR> acrValues) {
		this.acrValues = acrValues;
	}


	@Override
	public List<SubjectType> getSubjectTypes() {
		return subjectTypes;
	}


	@Override
	public List<JWSAlgorithm> getIDTokenJWSAlgs() {
		return idTokenJWSAlgs;
	}


	/**
	 * Sets the supported JWS algorithms for ID tokens. Corresponds to the
	 * {@code id_token_signing_alg_values_supported} metadata field.
	 *
	 * @param idTokenJWSAlgs The supported JWS algorithms, {@code null} if
	 *                       not specified.
	 */
	public void setIDTokenJWSAlgs(final List<JWSAlgorithm> idTokenJWSAlgs) {
		this.idTokenJWSAlgs = idTokenJWSAlgs;
	}


	@Override
	public List<JWEAlgorithm> getIDTokenJWEAlgs() {
		return idTokenJWEAlgs;
	}


	/**
	 * Sets the supported JWE algorithms for ID tokens. Corresponds to the
	 * {@code id_token_encryption_alg_values_supported} metadata field.
	 *
	 * @param idTokenJWEAlgs The supported JWE algorithms, {@code null} if
	 *                       not specified.
	 */
	public void setIDTokenJWEAlgs(final List<JWEAlgorithm> idTokenJWEAlgs) {
		this.idTokenJWEAlgs = idTokenJWEAlgs;
	}


	@Override
	public List<EncryptionMethod> getIDTokenJWEEncs() {
		return idTokenJWEEncs;
	}


	/**
	 * Sets the supported encryption methods for ID tokens. Corresponds to
	 * the {@code id_token_encryption_enc_values_supported} metadata field.
	 *
	 * @param idTokenJWEEncs The supported encryption methods, {@code null}
	 *                       if not specified.
	 */
	public void setIDTokenJWEEncs(final List<EncryptionMethod> idTokenJWEEncs) {
		this.idTokenJWEEncs = idTokenJWEEncs;
	}


	@Override
	public List<JWSAlgorithm> getUserInfoJWSAlgs() {
		return userInfoJWSAlgs;
	}


	/**
	 * Sets the supported JWS algorithms for UserInfo JWTs. Corresponds to
	 * the {@code userinfo_signing_alg_values_supported} metadata field.
	 *
	 * @param userInfoJWSAlgs The supported JWS algorithms, {@code null} if
	 *                        not specified.
	 */
	public void setUserInfoJWSAlgs(final List<JWSAlgorithm> userInfoJWSAlgs) {
		this.userInfoJWSAlgs = userInfoJWSAlgs;
	}


	@Override
	public List<JWEAlgorithm> getUserInfoJWEAlgs() {
		return userInfoJWEAlgs;
	}


	/**
	 * Sets the supported JWE algorithms for UserInfo JWTs. Corresponds to
	 * the {@code userinfo_encryption_alg_values_supported} metadata field.
	 *
	 * @param userInfoJWEAlgs The supported JWE algorithms, {@code null} if
	 *                        not specified.
	 */
	public void setUserInfoJWEAlgs(final List<JWEAlgorithm> userInfoJWEAlgs) {
		this.userInfoJWEAlgs = userInfoJWEAlgs;
	}


	@Override
	public List<EncryptionMethod> getUserInfoJWEEncs() {
		return userInfoJWEEncs;
	}


	/**
	 * Sets the supported encryption methods for UserInfo JWTs. Corresponds
	 * to the {@code userinfo_encryption_enc_values_supported} metadata
	 * field.
	 *
	 * @param userInfoJWEEncs The supported encryption methods,
	 *                        {@code null} if not specified.
	 */
	public void setUserInfoJWEEncs(final List<EncryptionMethod> userInfoJWEEncs) {
		this.userInfoJWEEncs = userInfoJWEEncs;
	}


	@Override
	public List<Display> getDisplays() {
		return displays;
	}


	/**
	 * Sets the supported displays. Corresponds to the
	 * {@code display_values_supported} metadata field.
	 *
	 * @param displays The supported displays, {@code null} if not
	 *                 specified.
	 */
	public void setDisplays(final List<Display> displays) {
		this.displays = displays;
	}
	
	
	@Override
	public List<ClaimType> getClaimTypes() {
		return claimTypes;
	}


	/**
	 * Sets the supported claim types. Corresponds to the
	 * {@code claim_types_supported} metadata field.
	 *
	 * @param claimTypes The supported claim types, {@code null} if not
	 *                   specified.
	 */
	public void setClaimTypes(final List<ClaimType> claimTypes) {
		this.claimTypes = claimTypes;
	}


	@Override
	public List<String> getClaims() {
		return claims;
	}


	/**
	 * Sets the supported claims names. Corresponds to the
	 * {@code claims_supported} metadata field.
	 *
	 * @param claims The supported claims names, {@code null} if not
	 *               specified.
	 */
	public void setClaims(final List<String> claims) {
		this.claims = claims;
	}
	
	
	@Override
	public List<LangTag> getClaimsLocales() {
		return claimsLocales;
	}


	/**
	 * Sets the supported claims locales. Corresponds to the
	 * {@code claims_locales_supported} metadata field.
	 *
	 * @param claimsLocales The supported claims locales, {@code null} if
	 *                      not specified.
	 */
	public void setClaimLocales(final List<LangTag> claimsLocales) {
		this.claimsLocales = claimsLocales;
	}
	
	
	@Override
	public boolean supportsClaimsParam() {
		return claimsParamSupported;
	}


	/**
	 * Sets the support for the {@code claims} authorisation request
	 * parameter. Corresponds to the {@code claims_parameter_supported}
	 * metadata field.
	 *
	 * @param claimsParamSupported {@code true} if the {@code claim}
	 *                             parameter is supported, else
	 *                             {@code false}.
	 */
	public void setSupportsClaimsParams(final boolean claimsParamSupported) {
		this.claimsParamSupported = claimsParamSupported;
	}
	
	
	@Override
	public boolean supportsFrontChannelLogout() {
		return frontChannelLogoutSupported;
	}
	
	
	/**
	 * Sets the support for front-channel logout. Corresponds to the
	 * {@code frontchannel_logout_supported} metadata field.
	 *
	 * @param frontChannelLogoutSupported {@code true} if front-channel
	 *                                    logout is supported, else
	 *                                    {@code false}.
	 */
	public void setSupportsFrontChannelLogout(final boolean frontChannelLogoutSupported) {
		this.frontChannelLogoutSupported = frontChannelLogoutSupported;
	}
	
	
	@Override
	public boolean supportsFrontChannelLogoutSession() {
		return frontChannelLogoutSessionSupported;
	}
	
	
	/**
	 * Sets the support for front-channel logout with a session ID.
	 * Corresponds to the {@code frontchannel_logout_session_supported}
	 * metadata field.
	 *
	 * @param frontChannelLogoutSessionSupported {@code true} if
	 *                                           front-channel logout with
	 *                                           a session ID is supported,
	 *                                           else {@code false}.
	 */
	public void setSupportsFrontChannelLogoutSession(final boolean frontChannelLogoutSessionSupported) {
		this.frontChannelLogoutSessionSupported = frontChannelLogoutSessionSupported;
	}
	
	
	@Override
	public boolean supportsBackChannelLogout() {
		return backChannelLogoutSupported;
	}
	
	
	/**
	 * Sets the support for back-channel logout. Corresponds to the
	 * {@code backchannel_logout_supported} metadata field.
	 *
	 * @param backChannelLogoutSupported {@code true} if back-channel
	 *                                   logout is supported, else
	 *                                   {@code false}.
	 */
	public void setSupportsBackChannelLogout(final boolean backChannelLogoutSupported) {
		this.backChannelLogoutSupported = backChannelLogoutSupported;
	}
	
	
	@Override
	public boolean supportsBackChannelLogoutSession() {
		return backChannelLogoutSessionSupported;
	}
	
	
	/**
	 * Sets the support for back-channel logout with a session ID.
	 * Corresponds to the {@code backchannel_logout_session_supported}
	 * metadata field.
	 *
	 * @param backChannelLogoutSessionSupported {@code true} if
	 *                                          back-channel logout with a
	 *                                          session ID is supported,
	 *                                          else {@code false}.
	 */
	public void setSupportsBackChannelLogoutSession(final boolean backChannelLogoutSessionSupported) {
		this.backChannelLogoutSessionSupported = backChannelLogoutSessionSupported;
	}


	@Override
	public boolean supportsNativeSSO() {
		return nativeSSOSupported;
	}


	/**
	 * Sets the support for OpenID Connect native SSO. Corresponds to the
	 * {@code native_sso_supported} metadata field.
	 *
	 * @param nativeSSOSupported {@code true} if native SSO is supported,
	 *                           else {@code false}.
	 */
	public void setSupportsNativeSSO(final boolean nativeSSOSupported) {
		this.nativeSSOSupported = nativeSSOSupported;
	}
	
	
	@Override
	public boolean supportsVerifiedClaims() {
		return verifiedClaimsSupported;
	}
	
	
	/**
	 * Sets support for verified claims. Corresponds to the
	 * {@code verified_claims_supported} metadata field.
	 *
	 * @param verifiedClaimsSupported {@code true} if verified claims are
	 *                                supported, else {@code false}.
	 */
	public void setSupportsVerifiedClaims(final boolean verifiedClaimsSupported) {
		this.verifiedClaimsSupported = verifiedClaimsSupported;
	}
	
	
	@Override
	public List<IdentityTrustFramework> getIdentityTrustFrameworks() {
		return trustFrameworks;
	}
	
	
	/**
	 * Sets the supported identity trust frameworks. Corresponds to the
	 * {@code trust_frameworks_supported} metadata field.
	 *
	 * @param trustFrameworks The supported identity trust frameworks,
	 *                        {@code null} if not specified.
	 */
	public void setIdentityTrustFrameworks(final List<IdentityTrustFramework> trustFrameworks) {
		this.trustFrameworks = trustFrameworks;
	}
	
	
	@Override
	public List<IdentityEvidenceType> getIdentityEvidenceTypes() {
		return evidenceTypes;
	}
	
	
	/**
	 * Sets the supported identity evidence types. Corresponds to the
	 * {@code evidence_supported} metadata field.
	 *
	 * @param evidenceTypes The supported identity evidence types,
	 *                      {@code null} if not specified.
	 */
	public void setIdentityEvidenceTypes(final List<IdentityEvidenceType> evidenceTypes) {
		this.evidenceTypes = evidenceTypes;
	}
	
	
	@Override
	public List<DocumentType> getDocumentTypes() {
		return documentTypes;
	}
	
	
	/**
	 * Sets the supported identity document types. Corresponds to the
	 * {@code documents_supported} metadata field.
	 *
	 * @param documentTypes The supported identity document types,
	 *                      {@code null} if not specified.
	 */
	public void setDocumentTypes(final List<DocumentType> documentTypes) {
		this.documentTypes = documentTypes;
	}
	
	
	@Override
	@Deprecated
	public List<IDDocumentType> getIdentityDocumentTypes() {
		return idDocumentTypes;
	}
	
	
	/**
	 * Sets the supported identity document types. Corresponds to the
	 * {@code id_documents_supported} metadata field.
	 *
	 * @param idDocuments The supported identity document types,
	 *                    {@code null} if not specified.
	 *
	 * @deprecated Use {@link #setDocumentTypes} instead.
	 */
	@Deprecated
	public void setIdentityDocumentTypes(final List<IDDocumentType> idDocuments) {
		this.idDocumentTypes = idDocuments;
	}
	
	
	@Override
	public List<IdentityVerificationMethod> getDocumentMethods() {
		return documentMethods;
	}
	
	
	/**
	 * Sets the supported coarse identity verification methods for
	 * evidences of type document. Corresponds to the
	 * {@code documents_methods_supported} metadata field.
	 *
	 * @param methods The supported identity verification methods for
	 *                document evidences, {@code null} if not specified.
	 */
	public void setDocumentMethods(final List<IdentityVerificationMethod> methods) {
		this.documentMethods = methods;
	}
	
	
	@Override
	public List<ValidationMethodType> getDocumentValidationMethods() {
		return documentValidationMethods;
	}
	
	
	/**
	 * Sets the supported validation methods for evidences of type
	 * document. Corresponds to the
	 * {@code documents_validation_methods_supported} metadata field.
	 *
	 * @param methods The validation methods for document evidences,
	 *                {@code null} if not specified.
	 */
	public void setDocumentValidationMethods(final List<ValidationMethodType> methods) {
		this.documentValidationMethods = methods;
	}
	
	
	@Override
	public List<VerificationMethodType> getDocumentVerificationMethods() {
		return documentVerificationMethods;
	}
	
	
	/**
	 * Sets the supported verification methods for evidences of type
	 * document. Corresponds to the
	 * {@code documents_verification_methods_supported} metadata field.
	 *
	 * @param methods The verification methods for document evidences,
	 *                {@code null} if not specified.
	 */
	public void setDocumentVerificationMethods(final List<VerificationMethodType> methods) {
		this.documentVerificationMethods = methods;
	}
	
	
	@Override
	public List<ElectronicRecordType> getElectronicRecordTypes() {
		return electronicRecordTypes;
	}
	
	
	/**
	 * Sets the supported electronic record types. Corresponds to the
	 * {@code electronic_records_supported} metadata field.
	 *
	 * @param electronicRecordTypes The supported electronic record types,
	 *                              {@code null} if not specified.
	 */
	public void setElectronicRecordTypes(final List<ElectronicRecordType> electronicRecordTypes) {
		this.electronicRecordTypes = electronicRecordTypes;
	}
	
	
	@Override
	@Deprecated
	public List<IdentityVerificationMethod> getIdentityVerificationMethods() {
		return idVerificationMethods;
	}
	
	
	/**
	 * Sets the supported identity verification methods. Corresponds to the
	 * {@code id_documents_verification_methods_supported} metadata field.
	 *
	 * @param idVerificationMethods The supported identity verification
	 *                              methods, {@code null} if not specified.
	 */
	@Deprecated
	public void setIdentityVerificationMethods(final List<IdentityVerificationMethod> idVerificationMethods) {
		this.idVerificationMethods = idVerificationMethods;
	}
	
	
	@Override
	public List<String> getVerifiedClaims() {
		return verifiedClaims;
	}
	
	
	/**
	 * Sets the names of the supported verified claims. Corresponds to the
	 * {@code claims_in_verified_claims_supported} metadata field.
	 *
	 * @param verifiedClaims The supported verified claims names,
	 *                       {@code null} if not specified.
	 */
	public void setVerifiedClaims(final List<String> verifiedClaims) {
		this.verifiedClaims = verifiedClaims;
	}
	
	
	@Override
	public List<AttachmentType> getAttachmentTypes() {
		return attachmentTypes;
	}
	
	
	/**
	 * Sets the supported evidence attachment types. Corresponds to the
	 * {@code attachments_supported} metadata field.
	 *
	 * @param attachmentTypes The supported evidence attachment types,
	 *                        empty if attachments are not supported,
	 *                        {@code null} if not specified.
	 */
	public void setAttachmentTypes(final List<AttachmentType> attachmentTypes) {
		this.attachmentTypes = attachmentTypes;
	}
	
	
	@Override
	public List<HashAlgorithm> getAttachmentDigestAlgs() {
		return attachmentDigestAlgs;
	}
	
	
	/**
	 * Sets the supported digest algorithms for the external evidence
	 * attachments. Corresponds to the {@code digest_algorithms_supported}
	 * metadata field.
	 *
	 * @param digestAlgs The supported digest algorithms, {@code null} if
	 *                   not specified.
	 */
	public void setAttachmentDigestAlgs(final List<HashAlgorithm> digestAlgs) {
		this.attachmentDigestAlgs = digestAlgs;
	}
	
	
	/**
	 * Applies the OpenID Provider metadata defaults where no values have
	 * been specified.
	 *
	 * <ul>
	 *     <li>The response modes default to {@code ["query", "fragment"]}.
	 *     <li>The grant types default to {@code ["authorization_code",
	 *         "implicit"]}.
	 *     <li>The token endpoint authentication methods default to
	 *         {@code ["client_secret_basic"]}.
	 *     <li>The claim types default to {@code ["normal]}.
	 * </ul>
	 */
	public void applyDefaults() {

		super.applyDefaults();

		if (claimTypes == null) {
			claimTypes = new ArrayList<>(1);
			claimTypes.add(ClaimType.NORMAL);
		}
	}


	@Override
	public JSONObject toJSONObject() {

		JSONObject o = super.toJSONObject();

		// Mandatory fields

		List<String> stringList = new ArrayList<>(subjectTypes.size());

		for (SubjectType st: subjectTypes)
			stringList.add(st.toString());

		o.put("subject_types_supported", stringList);

		// Optional fields

		if (userInfoEndpoint != null)
			o.put("userinfo_endpoint", userInfoEndpoint.toString());

		if (checkSessionIframe != null)
			o.put("check_session_iframe", checkSessionIframe.toString());

		if (endSessionEndpoint != null)
			o.put("end_session_endpoint", endSessionEndpoint.toString());

		if (acrValues != null) {
			o.put("acr_values_supported", Identifier.toStringList(acrValues));
		}

		if (idTokenJWSAlgs != null) {

			stringList = new ArrayList<>(idTokenJWSAlgs.size());

			for (JWSAlgorithm alg: idTokenJWSAlgs)
				stringList.add(alg.getName());

			o.put("id_token_signing_alg_values_supported", stringList);
		}

		if (idTokenJWEAlgs != null) {

			stringList = new ArrayList<>(idTokenJWEAlgs.size());

			for (JWEAlgorithm alg: idTokenJWEAlgs)
				stringList.add(alg.getName());

			o.put("id_token_encryption_alg_values_supported", stringList);
		}

		if (idTokenJWEEncs != null) {

			stringList = new ArrayList<>(idTokenJWEEncs.size());

			for (EncryptionMethod m: idTokenJWEEncs)
				stringList.add(m.getName());

			o.put("id_token_encryption_enc_values_supported", stringList);
		}

		if (userInfoJWSAlgs != null) {

			stringList = new ArrayList<>(userInfoJWSAlgs.size());

			for (JWSAlgorithm alg: userInfoJWSAlgs)
				stringList.add(alg.getName());

			o.put("userinfo_signing_alg_values_supported", stringList);
		}

		if (userInfoJWEAlgs != null) {

			stringList = new ArrayList<>(userInfoJWEAlgs.size());

			for (JWEAlgorithm alg: userInfoJWEAlgs)
				stringList.add(alg.getName());

			o.put("userinfo_encryption_alg_values_supported", stringList);
		}

		if (userInfoJWEEncs != null) {

			stringList = new ArrayList<>(userInfoJWEEncs.size());

			for (EncryptionMethod m: userInfoJWEEncs)
				stringList.add(m.getName());

			o.put("userinfo_encryption_enc_values_supported", stringList);
		}

		if (displays != null) {

			stringList = new ArrayList<>(displays.size());

			for (Display d: displays)
				stringList.add(d.toString());

			o.put("display_values_supported", stringList);
		}

		if (claimTypes != null) {

			stringList = new ArrayList<>(claimTypes.size());

			for (ClaimType ct: claimTypes)
				stringList.add(ct.toString());

			o.put("claim_types_supported", stringList);
		}

		if (claims != null)
			o.put("claims_supported", claims);

		if (claimsLocales != null) {

			stringList = new ArrayList<>(claimsLocales.size());

			for (LangTag l: claimsLocales)
				stringList.add(l.toString());

			o.put("claims_locales_supported", stringList);
		}

		if (claimsParamSupported) {
			o.put("claims_parameter_supported", true);
		}
		
		// Always output, for OP metadata default value is true, for
		// AS metadata implied default is false
		o.put("request_uri_parameter_supported", supportsRequestURIParam());
		
		// optional front and back-channel logout
		if (frontChannelLogoutSupported) {
			o.put("frontchannel_logout_supported", true);
		}
		
		if (frontChannelLogoutSupported) {
			o.put("frontchannel_logout_session_supported", frontChannelLogoutSessionSupported);
		}
		
		if (backChannelLogoutSupported) {
			o.put("backchannel_logout_supported", true);
		}
		
		if (backChannelLogoutSupported) {
			o.put("backchannel_logout_session_supported", backChannelLogoutSessionSupported);
		}

		if (nativeSSOSupported) {
			o.put("native_sso_supported", true);
		}
		
		// OpenID Connect for Identity Assurance 1.0
		if (verifiedClaimsSupported) {
			o.put("verified_claims_supported", true);
			if (trustFrameworks != null) {
				o.put("trust_frameworks_supported", Identifier.toStringList(trustFrameworks));
			}
			if (evidenceTypes != null) {
				o.put("evidence_supported", Identifier.toStringList(evidenceTypes));
			}
			if (
				(CollectionUtils.contains(evidenceTypes, IdentityEvidenceType.DOCUMENT) || CollectionUtils.contains(evidenceTypes, IdentityEvidenceType.ID_DOCUMENT))
				&& documentTypes != null) {
				
				o.put("documents_supported", Identifier.toStringList(documentTypes));
				
				// TODO await resolution of
				//  https://bitbucket.org/openid/ekyc-ida/issues/1275/clarification-regarding-op-metadata
				if (documentMethods != null) {
					o.put("documents_methods_supported", Identifier.toStringList(documentMethods));
				}
				if (documentValidationMethods != null) {
					o.put("documents_validation_methods_supported", Identifier.toStringList(documentValidationMethods));
				}
				if (documentVerificationMethods != null) {
					o.put("documents_verification_methods_supported", Identifier.toStringList(documentVerificationMethods));
				}
			}
			if (idDocumentTypes != null) {
				// deprecated
				o.put("id_documents_supported", Identifier.toStringList(idDocumentTypes));
			}
			if (idVerificationMethods != null) {
				// deprecated
				o.put("id_documents_verification_methods_supported", Identifier.toStringList(idVerificationMethods));
			}
			if (electronicRecordTypes != null) {
				o.put("electronic_records_supported", Identifier.toStringList(electronicRecordTypes));
			}
			if (verifiedClaims != null) {
				o.put("claims_in_verified_claims_supported", verifiedClaims);
			}
			if (attachmentTypes != null) {
				List<String> strings = new LinkedList<>();
				for (AttachmentType type: attachmentTypes) {
					strings.add(type.toString());
				}
				o.put("attachments_supported", strings);
				
				if (attachmentTypes.contains(AttachmentType.EXTERNAL) && attachmentDigestAlgs != null) {
					o.put("digest_algorithms_supported", Identifier.toStringList(attachmentDigestAlgs));
				}
			}
		}
		
		return o;
	}
	
	
	/**
	 * Parses an OpenID Provider metadata from the specified JSON object.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The OpenID Provider metadata.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        OpenID Provider metadata.
	 */
	public static OIDCProviderMetadata parse(final JSONObject jsonObject)
		throws ParseException {
		
		AuthorizationServerMetadata as = AuthorizationServerMetadata.parse(jsonObject);

		List<SubjectType> subjectTypes = new ArrayList<>();
		for (String v: JSONObjectUtils.getStringArray(jsonObject, "subject_types_supported")) {
			subjectTypes.add(SubjectType.parse(v));
		}
		
		OIDCProviderMetadata op;
		if (jsonObject.get("client_registration_types_supported") != null) {
			// OIDC Federation 1.0 constructor
			List<ClientRegistrationType> clientRegistrationTypes = new LinkedList<>();
			for (String v: JSONObjectUtils.getStringList(jsonObject, "client_registration_types_supported")) {
				clientRegistrationTypes.add(new ClientRegistrationType(v));
			}
			try {
				JWKSet jwkSet = null;
				if (jsonObject.get("jwks") != null) {
					jwkSet = JWKSet.parse(JSONObjectUtils.getJSONObject(jsonObject, "jwks"));
				}
				
				op = new OIDCProviderMetadata(
					as.getIssuer(),
					Collections.unmodifiableList(subjectTypes),
					clientRegistrationTypes,
					as.getJWKSetURI(),
					JSONObjectUtils.getURI(jsonObject, "signed_jwks_uri", null),
					jwkSet);
			} catch (java.text.ParseException | IllegalArgumentException e) {
				throw new ParseException(e.getMessage(), e);
			}
		} else {
			// Regular constructor
			op = new OIDCProviderMetadata(
				as.getIssuer(),
				Collections.unmodifiableList(subjectTypes),
				as.getJWKSetURI());
		}
		

		// Endpoints
		op.setAuthorizationEndpointURI(as.getAuthorizationEndpointURI());
		op.setTokenEndpointURI(as.getTokenEndpointURI());
		op.setRegistrationEndpointURI(as.getRegistrationEndpointURI());
		op.setIntrospectionEndpointURI(as.getIntrospectionEndpointURI());
		op.setRevocationEndpointURI(as.getRevocationEndpointURI());
		op.setRequestObjectEndpoint(as.getRequestObjectEndpoint());
		op.setPushedAuthorizationRequestEndpointURI(as.getPushedAuthorizationRequestEndpointURI());
		op.setDeviceAuthorizationEndpointURI(as.getDeviceAuthorizationEndpointURI());
		op.userInfoEndpoint = JSONObjectUtils.getURI(jsonObject, "userinfo_endpoint", null);
		op.checkSessionIframe = JSONObjectUtils.getURI(jsonObject, "check_session_iframe", null);
		op.endSessionEndpoint = JSONObjectUtils.getURI(jsonObject, "end_session_endpoint", null);

		// Capabilities
		op.setScopes(as.getScopes());
		op.setResponseTypes(as.getResponseTypes());
		op.setResponseModes(as.getResponseModes());
		op.setGrantTypes(as.getGrantTypes());
		
		op.setTokenEndpointAuthMethods(as.getTokenEndpointAuthMethods());
		op.setTokenEndpointJWSAlgs(as.getTokenEndpointJWSAlgs());
		
		op.setIntrospectionEndpointAuthMethods(as.getIntrospectionEndpointAuthMethods());
		op.setIntrospectionEndpointJWSAlgs(as.getIntrospectionEndpointJWSAlgs());
		
		op.setRevocationEndpointAuthMethods(as.getRevocationEndpointAuthMethods());
		op.setRevocationEndpointJWSAlgs(as.getRevocationEndpointJWSAlgs());
		
		op.setRequestObjectJWSAlgs(as.getRequestObjectJWSAlgs());
		op.setRequestObjectJWEAlgs(as.getRequestObjectJWEAlgs());
		op.setRequestObjectJWEEncs(as.getRequestObjectJWEEncs());
		
		op.setSupportsRequestParam(as.supportsRequestParam());
		op.setSupportsRequestURIParam(as.supportsRequestURIParam());
		op.setRequiresRequestURIRegistration(as.requiresRequestURIRegistration());
		
		op.requiresPushedAuthorizationRequests(as.requiresPushedAuthorizationRequests());
		
		op.setSupportsAuthorizationResponseIssuerParam(as.supportsAuthorizationResponseIssuerParam());
		
		op.setCodeChallengeMethods(as.getCodeChallengeMethods());
		

		op.setBackChannelAuthenticationEndpointURI(as.getBackChannelAuthenticationEndpointURI());
		op.setBackChannelAuthenticationRequestJWSAlgs(as.getBackChannelAuthenticationRequestJWSAlgs());
		op.setSupportsBackChannelUserCodeParam(as.supportsBackChannelUserCodeParam());
		op.setBackChannelTokenDeliveryModes(as.getBackChannelTokenDeliveryModes());
		
		op.setPromptTypes(as.getPromptTypes());
		
		op.setOrganizationName(as.getOrganizationName());
		op.setJWKSet(as.getJWKSet());
		op.setSignedJWKSetURI(as.getSignedJWKSetURI());
		op.setClientRegistrationTypes(as.getClientRegistrationTypes());
		op.setClientRegistrationAuthnMethods(as.getClientRegistrationAuthnMethods());
		op.setClientRegistrationAuthnJWSAlgs(as.getClientRegistrationAuthnJWSAlgs());
		op.setFederationRegistrationEndpointURI(as.getFederationRegistrationEndpointURI());

		if (jsonObject.get("acr_values_supported") != null) {

			op.acrValues = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "acr_values_supported")) {

				if (v != null)
					op.acrValues.add(new ACR(v));
			}
		}
		
		// ID token

		if (jsonObject.get("id_token_signing_alg_values_supported") != null) {

			op.idTokenJWSAlgs = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "id_token_signing_alg_values_supported")) {

				if (v != null)
					op.idTokenJWSAlgs.add(JWSAlgorithm.parse(v));
			}
		}


		if (jsonObject.get("id_token_encryption_alg_values_supported") != null) {

			op.idTokenJWEAlgs = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "id_token_encryption_alg_values_supported")) {

				if (v != null)
					op.idTokenJWEAlgs.add(JWEAlgorithm.parse(v));
			}
		}


		if (jsonObject.get("id_token_encryption_enc_values_supported") != null) {

			op.idTokenJWEEncs = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "id_token_encryption_enc_values_supported")) {

				if (v != null)
					op.idTokenJWEEncs.add(EncryptionMethod.parse(v));
			}
		}

		// UserInfo

		if (jsonObject.get("userinfo_signing_alg_values_supported") != null) {

			op.userInfoJWSAlgs = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "userinfo_signing_alg_values_supported")) {

				if (v != null)
					op.userInfoJWSAlgs.add(JWSAlgorithm.parse(v));
			}
		}


		if (jsonObject.get("userinfo_encryption_alg_values_supported") != null) {

			op.userInfoJWEAlgs = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "userinfo_encryption_alg_values_supported")) {

				if (v != null)
					op.userInfoJWEAlgs.add(JWEAlgorithm.parse(v));
			}
		}


		if (jsonObject.get("userinfo_encryption_enc_values_supported") != null) {

			op.userInfoJWEEncs = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "userinfo_encryption_enc_values_supported")) {

					if (v != null)
						op.userInfoJWEEncs.add(EncryptionMethod.parse(v));
			}
		}

		
		// Misc

		if (jsonObject.get("display_values_supported") != null) {

			op.displays = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "display_values_supported")) {

				if (v != null)
					op.displays.add(Display.parse(v));
			}
		}
		
		if (jsonObject.get("claim_types_supported") != null) {
			
			op.claimTypes = new ArrayList<>();
			
			for (String v: JSONObjectUtils.getStringArray(jsonObject, "claim_types_supported")) {
				
				if (v != null)
					op.claimTypes.add(ClaimType.parse(v));
			}
		}


		if (jsonObject.get("claims_supported") != null) {

			op.claims = new ArrayList<>();

			for (String v: JSONObjectUtils.getStringArray(jsonObject, "claims_supported")) {

				if (v != null)
					op.claims.add(v);
			}
		}
		
		if (jsonObject.get("claims_locales_supported") != null) {
			
			op.claimsLocales = new ArrayList<>();
			
			for (String v : JSONObjectUtils.getStringArray(jsonObject, "claims_locales_supported")) {
				
				if (v != null) {
					
					try {
						op.claimsLocales.add(LangTag.parse(v));
					
					} catch (LangTagException e) {
						
						throw new ParseException("Invalid claims_locales_supported field: " + e.getMessage(), e);
					}
				}
			}
		}
		
		op.setUILocales(as.getUILocales());
		op.setServiceDocsURI(as.getServiceDocsURI());
		op.setPolicyURI(as.getPolicyURI());
		op.setTermsOfServiceURI(as.getTermsOfServiceURI());
		
		if (jsonObject.get("claims_parameter_supported") != null)
			op.claimsParamSupported = JSONObjectUtils.getBoolean(jsonObject, "claims_parameter_supported");
		
		if (jsonObject.get("request_uri_parameter_supported") == null) {
			op.setSupportsRequestURIParam(true);
		}
		
		// Optional front and back-channel logout
		if (jsonObject.get("frontchannel_logout_supported") != null)
			op.frontChannelLogoutSupported = JSONObjectUtils.getBoolean(jsonObject, "frontchannel_logout_supported");
		
		if (op.frontChannelLogoutSupported && jsonObject.get("frontchannel_logout_session_supported") != null)
			op.frontChannelLogoutSessionSupported = JSONObjectUtils.getBoolean(jsonObject, "frontchannel_logout_session_supported");
		
		if (jsonObject.get("backchannel_logout_supported") != null)
			op.backChannelLogoutSupported = JSONObjectUtils.getBoolean(jsonObject, "backchannel_logout_supported");
		
		if (op.backChannelLogoutSupported && jsonObject.get("backchannel_logout_session_supported") != null)
			op.backChannelLogoutSessionSupported = JSONObjectUtils.getBoolean(jsonObject, "backchannel_logout_session_supported");

		// Native SSO
		if (jsonObject.get("native_sso_supported") != null)
			op.setSupportsNativeSSO(JSONObjectUtils.getBoolean(jsonObject, "native_sso_supported"));

		if (jsonObject.get("mtls_endpoint_aliases") != null)
			op.setMtlsEndpointAliases(OIDCProviderEndpointMetadata.parse(JSONObjectUtils.getJSONObject(jsonObject, "mtls_endpoint_aliases")));
		
		op.setSupportsTLSClientCertificateBoundAccessTokens(as.supportsTLSClientCertificateBoundAccessTokens());
		
		// DPoP
		op.setDPoPJWSAlgs(as.getDPoPJWSAlgs());
		
		// JARM
		op.setAuthorizationJWSAlgs(as.getAuthorizationJWSAlgs());
		op.setAuthorizationJWEAlgs(as.getAuthorizationJWEAlgs());
		op.setAuthorizationJWEEncs(as.getAuthorizationJWEEncs());

		// RAR
		op.setAuthorizationDetailsTypes(as.getAuthorizationDetailsTypes());
		
		// Incremental authz
		op.setIncrementalAuthorizationTypes(as.getIncrementalAuthorizationTypes());
		
		// OpenID Connect for Identity Assurance 1.0
		if (jsonObject.get("verified_claims_supported") != null) {
			op.verifiedClaimsSupported = JSONObjectUtils.getBoolean(jsonObject, "verified_claims_supported");
			if (op.verifiedClaimsSupported) {
				if (jsonObject.get("trust_frameworks_supported") != null) {
					op.trustFrameworks = new LinkedList<>();
					for (String v : JSONObjectUtils.getStringList(jsonObject, "trust_frameworks_supported")) {
						op.trustFrameworks.add(new IdentityTrustFramework(v));
					}
				}
				if (jsonObject.get("evidence_supported") != null) {
					op.evidenceTypes = new LinkedList<>();
					for (String v: JSONObjectUtils.getStringList(jsonObject, "evidence_supported")) {
						op.evidenceTypes.add(new IdentityEvidenceType(v));
					}
				}
				
				if (
					(CollectionUtils.contains(op.evidenceTypes, IdentityEvidenceType.DOCUMENT) || CollectionUtils.contains(op.evidenceTypes, IdentityEvidenceType.ID_DOCUMENT))
					&& jsonObject.get("documents_supported") != null) {
					
					op.documentTypes = new LinkedList<>();
					for (String v: JSONObjectUtils.getStringList(jsonObject, "documents_supported")) {
						op.documentTypes.add(new DocumentType(v));
					}
					
					// TODO await resolution of
					//  https://bitbucket.org/openid/ekyc-ida/issues/1275/clarification-regarding-op-metadata
					if (jsonObject.get("documents_methods_supported") != null) {
						op.documentMethods = new LinkedList<>();
						for (String v: JSONObjectUtils.getStringList(jsonObject, "documents_methods_supported")) {
							op.documentMethods.add(new IdentityVerificationMethod(v));
						}
					}
					
					if (jsonObject.get("documents_validation_methods_supported") != null) {
						op.documentValidationMethods = new LinkedList<>();
						for (String v: JSONObjectUtils.getStringList(jsonObject, "documents_validation_methods_supported")) {
							op.documentValidationMethods.add(new ValidationMethodType(v));
						}
					}
					
					if (jsonObject.get("documents_verification_methods_supported") != null) {
						op.documentVerificationMethods = new LinkedList<>();
						for (String v: JSONObjectUtils.getStringList(jsonObject, "documents_verification_methods_supported")) {
							op.documentVerificationMethods.add(new VerificationMethodType(v));
						}
					}
				}
				
				if (jsonObject.get("id_documents_supported") != null) {
					// deprecated
					op.idDocumentTypes = new LinkedList<>();
					for (String v: JSONObjectUtils.getStringList(jsonObject, "id_documents_supported")) {
						op.idDocumentTypes.add(new IDDocumentType(v));
					}
				}
				if (jsonObject.get("id_documents_verification_methods_supported") != null) {
					// deprecated
					op.idVerificationMethods = new LinkedList<>();
					for (String v: JSONObjectUtils.getStringList(jsonObject, "id_documents_verification_methods_supported")) {
						op.idVerificationMethods.add(new IdentityVerificationMethod(v));
					}
				}
				if (jsonObject.get("electronic_records_supported") != null) {
					op.electronicRecordTypes = new LinkedList<>();
					for (String v: JSONObjectUtils.getStringList(jsonObject, "electronic_records_supported")) {
						op.electronicRecordTypes.add(new ElectronicRecordType(v));
					}
				}
				if (jsonObject.get("claims_in_verified_claims_supported") != null) {
					op.verifiedClaims = JSONObjectUtils.getStringList(jsonObject, "claims_in_verified_claims_supported");
				}
				if (jsonObject.get("attachments_supported") != null) {
					op.attachmentTypes = new LinkedList<>();
					for (String v: JSONObjectUtils.getStringList(jsonObject, "attachments_supported")) {
						op.attachmentTypes.add(AttachmentType.parse(v));
					}
					
					if (op.attachmentTypes.contains(AttachmentType.EXTERNAL) && jsonObject.get("digest_algorithms_supported") != null) {
						op.attachmentDigestAlgs = new LinkedList<>();
						for (String v: JSONObjectUtils.getStringList(jsonObject, "digest_algorithms_supported")) {
							op.attachmentDigestAlgs.add(new HashAlgorithm(v));
						}
					}
				}
			}
		}
		
		// Parse custom (not registered) parameters
		for (Map.Entry<String,?> entry: as.getCustomParameters().entrySet()) {
			if (REGISTERED_PARAMETER_NAMES.contains(entry.getKey()))
				continue; // skip
			op.setCustomParameter(entry.getKey(), entry.getValue());
		}

		return op;
	}


	/**
	 * Parses an OpenID Provider metadata from the specified JSON object
	 * string.
	 *
	 * @param s The JSON object sting to parse. Must not be {@code null}.
	 *
	 * @return The OpenID Provider metadata.
	 *
	 * @throws ParseException If the JSON object string couldn't be parsed
	 *                        to an OpenID Provider metadata.
	 */
	public static OIDCProviderMetadata parse(final String s)
		throws ParseException {

		return parse(JSONObjectUtils.parse(s));
	}
	
	
	/**
	 * Resolves OpenID Provider metadata URL from the specified issuer
	 * identifier.
	 *
	 * @param issuer The OpenID Provider issuer identifier. Must represent
	 *               a valid HTTPS or HTTP URL. Must not be {@code null}.
	 *
	 * @return The OpenID Provider metadata URL.
	 *
	 * @throws GeneralException If the issuer identifier is invalid.
	 */
	public static URL resolveURL(final Issuer issuer)
		throws GeneralException {
		
		try {
			URL issuerURL = new URL(issuer.getValue());
			
			// Validate but don't insist on HTTPS, see
			// http://openid.net/specs/openid-connect-core-1_0.html#Terminology
			if (issuerURL.getQuery() != null && ! issuerURL.getQuery().trim().isEmpty()) {
				throw new GeneralException("The issuer identifier must not contain a query component");
			}
			
			if (issuerURL.getPath() != null && issuerURL.getPath().endsWith("/")) {
				return new URL(issuerURL + ".well-known/openid-configuration");
			} else {
				return new URL(issuerURL + "/.well-known/openid-configuration");
			}
			
		} catch (MalformedURLException e) {
			throw new GeneralException("The issuer identifier doesn't represent a valid URL: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Resolves OpenID Provider metadata from the specified issuer
	 * identifier. The metadata is downloaded by HTTP GET from
	 * {@code [issuer-url]/.well-known/openid-configuration}.
	 *
	 * @param issuer The OpenID Provider issuer identifier. Must represent
	 *               a valid HTTPS or HTTP URL. Must not be {@code null}.
	 *
	 * @return The OpenID Provider metadata.
	 *
	 * @throws GeneralException If the issuer identifier or the downloaded
	 *                          metadata are invalid.
	 * @throws IOException      On a HTTP exception.
	 */
	public static OIDCProviderMetadata resolve(final Issuer issuer)
		throws GeneralException, IOException {
		
		return resolve(issuer, 0, 0);
	}


	/**
	 * Resolves OpenID Provider metadata from the specified issuer
	 * identifier. The metadata is downloaded by HTTP GET from
	 * {@code [issuer-url]/.well-known/openid-configuration}, using the
	 * specified HTTP timeouts.
	 *
	 * @param issuer         The issuer identifier. Must represent a valid
	 *                       HTTPS or HTTP URL. Must not be {@code null}.
	 * @param connectTimeout The HTTP connect timeout, in milliseconds.
	 *                       Zero implies no timeout. Must not be negative.
	 * @param readTimeout    The HTTP response read timeout, in
	 *                       milliseconds. Zero implies no timeout. Must
	 *                       not be negative.
	 *
	 * @return The OpenID Provider metadata.
	 *
	 * @throws GeneralException If the issuer identifier or the downloaded
	 *                          metadata are invalid.
	 * @throws IOException      On an HTTP exception.
	 */
	public static OIDCProviderMetadata resolve(final Issuer issuer,
						   final int connectTimeout,
						   final int readTimeout)
		throws GeneralException, IOException {

		HTTPRequestConfigurator requestConfigurator = new HTTPRequestConfigurator() {
			@Override
			public void configure(HTTPRequest httpRequest) {
				httpRequest.setConnectTimeout(connectTimeout);
				httpRequest.setReadTimeout(readTimeout);
			}
		};

		return resolve(issuer, requestConfigurator);
	}


	/**
	 * Resolves OpenID Provider metadata from the specified issuer
	 * identifier. The metadata is downloaded by HTTP GET from
	 * {@code [issuer-url]/.well-known/openid-configuration}, using the
	 * specified HTTP request configurator.
	 *
	 * @param issuer              The issuer identifier. Must represent a
	 *                            valid HTTPS or HTTP URL. Must not be
	 *                            {@code null}.
	 * @param requestConfigurator An {@link HTTPRequestConfigurator}
	 *                            instance to perform additional
	 *                            {@link HTTPRequest} configuration to
	 *                            fetch the OpenID Provider metadata. Must
	 *                            not be {@code null}.
	 *
	 * @return The OpenID Provider metadata.
	 *
	 * @throws GeneralException If the issuer identifier or the downloaded
	 *                          metadata are invalid.
	 * @throws IOException      On an HTTP exception.
	 */
	public static OIDCProviderMetadata resolve(final Issuer issuer,
						   final HTTPRequestConfigurator requestConfigurator)
		throws GeneralException, IOException {

		URL configURL = resolveURL(issuer);

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, configURL);
		requestConfigurator.configure(httpRequest);

		HTTPResponse httpResponse = httpRequest.send();

		if (httpResponse.getStatusCode() != 200) {
			throw new IOException("Couldn't download OpenID Provider metadata from " + configURL +
				  ": Status code " + httpResponse.getStatusCode());
		}

		JSONObject jsonObject = httpResponse.getContentAsJSONObject();

		OIDCProviderMetadata op = OIDCProviderMetadata.parse(jsonObject);

		if (! issuer.equals(op.getIssuer())) {
			throw new GeneralException("The returned issuer doesn't match the expected: " + op.getIssuer());
		}

		return op;
	}
}