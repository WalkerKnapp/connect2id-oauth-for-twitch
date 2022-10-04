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

package com.nimbusds.openid.connect.sdk.op;


import java.util.List;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.langtag.LangTag;
import com.nimbusds.oauth2.sdk.as.ReadOnlyAuthorizationServerMetadata;
import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.assurance.IdentityTrustFramework;
import com.nimbusds.openid.connect.sdk.assurance.evidences.*;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.AttachmentType;
import com.nimbusds.openid.connect.sdk.assurance.evidences.attachment.HashAlgorithm;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimType;


/**
 * Read-only OpenID Provider (OP) metadata.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Discovery 1.0, section 3
 *     <li>OpenID Connect Session Management 1.0, section 2.1 (draft 28)
 *     <li>OpenID Connect Front-Channel Logout 1.0, section 3 (draft 02)
 *     <li>OpenID Connect Back-Channel Logout 1.0, section 2.1 (draft 07)
 *     <li>OpenID Connect for Identity Assurance 1.0 (draft 12)
 *     <li>OpenID Connect Federation 1.0 (draft 22)
 *     <li>OAuth 2.0 Authorization Server Metadata (RFC 8414)
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (RFC 8705)
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM)
 *     <li>OAuth 2.0 Authorization Server Issuer Identification (RFC 9207)
 * </ul>
 */
public interface ReadOnlyOIDCProviderMetadata extends ReadOnlyAuthorizationServerMetadata, ReadOnlyOIDCProviderEndpointMetadata {
	
	
	@Override
	ReadOnlyOIDCProviderEndpointMetadata getReadOnlyMtlsEndpointAliases();
	
	
	/**
	 * Gets the supported Authentication Context Class References (ACRs).
	 * Corresponds to the {@code acr_values_supported} metadata field.
	 *
	 * @return The supported ACRs, {@code null} if not specified.
	 */
	List<ACR> getACRs();
	
	
	/**
	 * Gets the supported subject types. Corresponds to the
	 * {@code subject_types_supported} metadata field.
	 *
	 * @return The supported subject types.
	 */
	List<SubjectType> getSubjectTypes();
	
	
	/**
	 * Gets the supported JWS algorithms for ID tokens. Corresponds to the
	 * {@code id_token_signing_alg_values_supported} metadata field.
	 *
	 * @return The supported JWS algorithms, {@code null} if not specified.
	 */
	List<JWSAlgorithm> getIDTokenJWSAlgs();
	
	
	/**
	 * Gets the supported JWE algorithms for ID tokens. Corresponds to the
	 * {@code id_token_encryption_alg_values_supported} metadata field.
	 *
	 * @return The supported JWE algorithms, {@code null} if not specified.
	 */
	List<JWEAlgorithm> getIDTokenJWEAlgs();
	
	
	/**
	 * Gets the supported encryption methods for ID tokens. Corresponds to
	 * the {@code id_token_encryption_enc_values_supported} metadata field.
	 *
	 * @return The supported encryption methods, {@code null} if not
	 * specified.
	 */
	List<EncryptionMethod> getIDTokenJWEEncs();
	
	
	/**
	 * Gets the supported JWS algorithms for UserInfo JWTs. Corresponds to
	 * the {@code userinfo_signing_alg_values_supported} metadata field.
	 *
	 * @return The supported JWS algorithms, {@code null} if not specified.
	 */
	List<JWSAlgorithm> getUserInfoJWSAlgs();
	
	
	/**
	 * Gets the supported JWE algorithms for UserInfo JWTs. Corresponds to
	 * the {@code userinfo_encryption_alg_values_supported} metadata field.
	 *
	 * @return The supported JWE algorithms, {@code null} if not specified.
	 */
	List<JWEAlgorithm> getUserInfoJWEAlgs();
	
	
	/**
	 * Gets the supported encryption methods for UserInfo JWTs. Corresponds
	 * to the {@code userinfo_encryption_enc_values_supported} metadata
	 * field.
	 *
	 * @return The supported encryption methods, {@code null} if not
	 * specified.
	 */
	List<EncryptionMethod> getUserInfoJWEEncs();
	
	
	/**
	 * Gets the supported displays. Corresponds to the
	 * {@code display_values_supported} metadata field.
	 *
	 * @return The supported displays, {@code null} if not specified.
	 */
	List<Display> getDisplays();
	
	
	/**
	 * Gets the supported claim types. Corresponds to the
	 * {@code claim_types_supported} metadata field.
	 *
	 * @return The supported claim types, {@code null} if not specified.
	 */
	List<ClaimType> getClaimTypes();
	
	
	/**
	 * Gets the supported claims names. Corresponds to the
	 * {@code claims_supported} metadata field.
	 *
	 * @return The supported claims names, {@code null} if not specified.
	 */
	List<String> getClaims();
	
	
	/**
	 * Gets the supported claims locales. Corresponds to the
	 * {@code claims_locales_supported} metadata field.
	 *
	 * @return The supported claims locales, {@code null} if not specified.
	 */
	List<LangTag> getClaimsLocales();
	
	
	/**
	 * Gets the support for the {@code claims} authorisation request
	 * parameter. Corresponds to the {@code claims_parameter_supported}
	 * metadata field.
	 *
	 * @return {@code true} if the {@code claim} parameter is supported,
	 * else {@code false}.
	 */
	boolean supportsClaimsParam();
	
	
	/**
	 * Gets the support for front-channel logout. Corresponds to the
	 * {@code frontchannel_logout_supported} metadata field.
	 *
	 * @return {@code true} if front-channel logout is supported, else
	 * {@code false}.
	 */
	boolean supportsFrontChannelLogout();
	
	
	/**
	 * Gets the support for front-channel logout with a session ID.
	 * Corresponds to the {@code frontchannel_logout_session_supported}
	 * metadata field.
	 *
	 * @return {@code true} if front-channel logout with a session ID is
	 * supported, else {@code false}.
	 */
	boolean supportsFrontChannelLogoutSession();
	
	
	/**
	 * Gets the support for back-channel logout. Corresponds to the
	 * {@code backchannel_logout_supported} metadata field.
	 *
	 * @return {@code true} if back-channel logout is supported, else
	 * {@code false}.
	 */
	boolean supportsBackChannelLogout();
	
	
	/**
	 * Gets the support for back-channel logout with a session ID.
	 * Corresponds to the {@code backchannel_logout_session_supported}
	 * metadata field.
	 *
	 * @return {@code true} if back-channel logout with a session ID is
	 * supported, else {@code false}.
	 */
	boolean supportsBackChannelLogoutSession();
	
	
	/**
	 * Gets support for verified claims. Corresponds to the
	 * {@code verified_claims_supported} metadata field.
	 *
	 * @return {@code true} if verified claims are supported, else
	 * {@code false}.
	 */
	boolean supportsVerifiedClaims();
	
	
	/**
	 * Gets the supported identity trust frameworks. Corresponds to the
	 * {@code trust_frameworks_supported} metadata field.
	 *
	 * @return The supported identity trust frameworks, {@code null} if not
	 * specified.
	 */
	List<IdentityTrustFramework> getIdentityTrustFrameworks();
	
	
	/**
	 * Gets the supported identity evidence types. Corresponds to the
	 * {@code evidence_supported} metadata field.
	 *
	 * @return The supported identity evidence types, {@code null} if not
	 * specified.
	 */
	List<IdentityEvidenceType> getIdentityEvidenceTypes();
	
	
	/**
	 * Gets the supported identity document types. Corresponds to the
	 * {@code documents_supported} metadata field.
	 *
	 * @return The supported identity document types, {@code null} if not
	 * specified.
	 */
	List<DocumentType> getDocumentTypes();
	
	
	/**
	 * Gets the supported identity document types. Corresponds to the
	 * {@code id_documents_supported} metadata field.
	 *
	 * @return The supported identity documents types, {@code null} if not
	 * specified.
	 * @deprecated Use {@link #getDocumentTypes} instead.
	 */
	@Deprecated
	List<IDDocumentType> getIdentityDocumentTypes();
	
	
	/**
	 * Gets the supported coarse identity verification methods for
	 * evidences of type document. Corresponds to the
	 * {@code documents_methods_supported} metadata field.
	 *
	 * @return The supported identity verification methods for document
	 * evidences, {@code null} if not specified.
	 */
	List<IdentityVerificationMethod> getDocumentMethods();
	
	
	/**
	 * Gets the supported validation methods for evidences of type
	 * document. Corresponds to the
	 * {@code documents_validation_methods_supported} metadata field.
	 *
	 * @return The validation methods for document evidences, {@code null}
	 * if not specified.
	 */
	List<ValidationMethodType> getDocumentValidationMethods();
	
	
	/**
	 * Gets the supported verification methods for evidences of type
	 * document. Corresponds to the
	 * {@code documents_verification_methods_supported} metadata field.
	 *
	 * @return The verification methods for document evidences, {@code null}
	 * if not specified.
	 */
	List<VerificationMethodType> getDocumentVerificationMethods();
	
	
	/**
	 * Gets the supported electronic record types. Corresponds to the
	 * {@code electronic_records_supported} metadata field.
	 *
	 * @return The supported electronic record types, {@code null} if not
	 * specified.
	 */
	List<ElectronicRecordType> getElectronicRecordTypes();
	
	
	/**
	 * Gets the supported identity verification methods. Corresponds to the
	 * {@code id_documents_verification_methods_supported} metadata field.
	 *
	 * @return The supported identity verification methods, {@code null} if
	 * not specified.
	 */
	@Deprecated
	List<IdentityVerificationMethod> getIdentityVerificationMethods();
	
	
	/**
	 * Gets the names of the supported verified claims. Corresponds to the
	 * {@code claims_in_verified_claims_supported} metadata field.
	 *
	 * @return The supported verified claims names, {@code null} if not
	 * specified.
	 */
	List<String> getVerifiedClaims();
	
	
	/**
	 * Gets the supported evidence attachment types. Corresponds to the
	 * {@code attachments_supported} metadata field.
	 *
	 * @return The supported evidence attachment types, empty if
	 * attachments are not supported, {@code null} if not
	 * specified.
	 */
	List<AttachmentType> getAttachmentTypes();
	
	
	/**
	 * Gets the supported digest algorithms for the external evidence
	 * attachments. Corresponds to the {@code digest_algorithms_supported}
	 * metadata field.
	 *
	 * @return The supported digest algorithms, {@code null} if not
	 * specified.
	 */
	List<HashAlgorithm> getAttachmentDigestAlgs();
}
