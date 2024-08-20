/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.rp.statement;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import net.jcip.annotations.ThreadSafe;
import net.minidev.json.JSONObject;

import java.net.URL;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;


/**
 * Processor of software statements for client registrations.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)
 * </ul>
 *
 * @param <C> Optional security context to pass to the underlying JWK source.
 */
@ThreadSafe
public class SoftwareStatementProcessor <C extends SecurityContext> {
	
	
	private final boolean required;
	
	
	private final DefaultJWTProcessor<C> processor;
	
	
	/**
	 * Creates a new software statement processor.
	 *
	 * @param issuer   The allowed software statement issuer. Must not be
	 *                 {@code null}.
	 * @param required If {@code true} the processed client metadata must
	 *                 include a software statement and if missing this
	 *                 will result in a {@code invalid_software_statement}
	 *                 error. If {@code false} client metadata with missing
	 *                 software statement will be returned unmodified by
	 *                 the processor.
	 * @param jwsAlgs  The allowed JWS algorithms of the software
	 *                 statements. Must not be empty or {@code null}.
	 * @param jwkSet   The public JWK set for verifying the software
	 *                 statement signatures.
	 */
	public SoftwareStatementProcessor(final Issuer issuer,
					  final boolean required,
					  final Set<JWSAlgorithm> jwsAlgs,
					  final JWKSet jwkSet) {
		
		this(issuer, required, jwsAlgs, new ImmutableJWKSet<C>(jwkSet));
	}
	
	
	/**
	 * Creates a new software statement processor.
	 *
	 * @param issuer           The allowed software statement issuer. Must
	 *                         not be {@code null}.
	 * @param required         If {@code true} the processed client
	 *                         metadata must include a software statement
	 *                         and if missing this will result in a
	 *                         {@code invalid_software_statement} error. If
	 *                         {@code false} client metadata with missing
	 *                         software statement will be returned
	 *                         unmodified by the processor.
	 * @param jwsAlgs          The allowed JWS algorithms of the software
	 *                         statements. Must not be empty or
	 *                         {@code null}.
	 * @param jwkSetURL        The public JWK set URL for verifying the
	 *                         software statement signatures.
	 * @param connectTimeoutMs The HTTP connect timeout in milliseconds for
	 *                         retrieving the JWK set, zero implies no
	 *                         timeout (determined by the underlying HTTP
	 *                         client).
	 * @param readTimeoutMs    The HTTP read timeout in milliseconds for
	 *                         retrieving the JWK set, zero implies no
	 *                         timeout (determined by the underlying HTTP
	 *                         client).
	 * @param sizeLimitBytes   The HTTP entity size limit in bytes when
	 *                         retrieving the JWK set, zero implies no
	 *                         limit.
	 */
	public SoftwareStatementProcessor(final Issuer issuer,
					  final boolean required,
					  final Set<JWSAlgorithm> jwsAlgs,
					  final URL jwkSetURL,
					  final int connectTimeoutMs,
					  final int readTimeoutMs,
					  final int sizeLimitBytes) {
		
		this(issuer, required, jwsAlgs,
			new RemoteJWKSet<C>(
				jwkSetURL,
				new DefaultResourceRetriever(
					connectTimeoutMs,
					readTimeoutMs,
					sizeLimitBytes)));
	}
	
	
	/**
	 * Creates a new software statement processor.
	 *
	 * @param issuer    The allowed software statement issuer. Must not be
	 *                  {@code null}.
	 * @param required  If {@code true} the processed client metadata must
	 *                  include a software statement and if missing this
	 *                  will result in a {@code invalid_software_statement}
	 *                  error. If {@code false} client metadata with
	 *                  missing software statement will be returned
	 *                  unmodified by the processor.
	 * @param jwsAlgs   The allowed JWS algorithms of the software
	 *                  statements. Must not be empty or {@code null}.
	 * @param jwkSource The public JWK source to use for verifying the
	 *                  software statement signatures.
	 */
	public SoftwareStatementProcessor(final Issuer issuer,
					  final boolean required,
					  final Set<JWSAlgorithm> jwsAlgs,
					  final JWKSource<C> jwkSource) {
		
		this(issuer, required, jwsAlgs, jwkSource, Collections.<String>emptySet());
	}
	
	
	/**
	 * Creates a new software statement processor.
	 *
	 * @param issuer                   The allowed software statement
	 *                                 issuer. Must not be {@code null}.
	 * @param required                 If {@code true} the processed client
	 *                                 metadata must include a software
	 *                                 statement and if missing this will
	 *                                 result in a
	 *                                 {@code invalid_software_statement}
	 *                                 error. If {@code false} client
	 *                                 metadata with missing software
	 *                                 statement will be returned
	 *                                 unmodified by the processor.
	 * @param jwsAlgs                  The allowed JWS algorithms of the
	 *                                 software statements. Must not be
	 *                                 empty or {@code null}.
	 * @param jwkSource                The public JWK source to use for
	 *                                 verifying the software statement
	 *                                 signatures.
	 * @param additionalRequiredClaims The names of any additional JWT
	 *                                 claims other than "iss" (issuer)
	 *                                 that must be present in the software
	 *                                 statement, empty or {@code null} if
	 *                                 none.
	 */
	@Deprecated
	public SoftwareStatementProcessor(final Issuer issuer,
					  final boolean required,
					  final Set<JWSAlgorithm> jwsAlgs,
					  final JWKSource<C> jwkSource,
					  final Set<String> additionalRequiredClaims) {
		
		this(issuer, required, jwsAlgs, null, jwkSource, additionalRequiredClaims);
	}


	/**
	 * Creates a new software statement processor.
	 *
	 * @param issuer                   The allowed software statement
	 *                                 issuer. Must not be {@code null}.
	 * @param required                 If {@code true} the processed client
	 *                                 metadata must include a software
	 *                                 statement and if missing this will
	 *                                 result in a
	 *                                 {@code invalid_software_statement}
	 *                                 error. If {@code false} client
	 *                                 metadata with missing software
	 *                                 statement will be returned
	 *                                 unmodified by the processor.
	 * @param jwsAlgs                  The allowed JWS algorithms of the
	 *                                 software statements. Must not be
	 *                                 empty or {@code null}.
	 * @param jwtTypes                 The allowed JWT "typ" (type) header
	 *                                 values of the software statements,
	 *                                 {@code null} or empty to accept
	 *                                 {@code JWT} or none.
	 * @param jwkSource                The public JWK source to use for
	 *                                 verifying the software statement
	 *                                 signatures.
	 * @param additionalRequiredClaims The names of any additional JWT
	 *                                 claims other than "iss" (issuer)
	 *                                 that must be present in the software
	 *                                 statement, empty or {@code null} if
	 *                                 none.
	 */
	public SoftwareStatementProcessor(final Issuer issuer,
					  final boolean required,
					  final Set<JWSAlgorithm> jwsAlgs,
					  final Set<JOSEObjectType> jwtTypes,
					  final JWKSource<C> jwkSource,
					  final Set<String> additionalRequiredClaims) {

		this.required = required;

		Set<String> allRequiredClaims = new HashSet<>();
		allRequiredClaims.add("iss");
		if (CollectionUtils.isNotEmpty(additionalRequiredClaims)) {
			allRequiredClaims.addAll(additionalRequiredClaims);
		}

		processor = new DefaultJWTProcessor<>();

		if (CollectionUtils.isNotEmpty(jwtTypes)) {
			processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<C>(jwtTypes));
		}
		processor.setJWSKeySelector(new JWSVerificationKeySelector<>(jwsAlgs, jwkSource));
		processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<C>(
			new JWTClaimsSet.Builder()
				.issuer(issuer.getValue())
				.build(),
			allRequiredClaims));
	}
	
	
	/**
	 * Processes an optional software statement in the specified client
	 * metadata.
	 *
	 * @param clientMetadata The client metadata, must not be {@code null}.
	 *
	 * @return The processed client metadata, with the merged software
	 *         statement.
	 *
	 * @throws InvalidSoftwareStatementException On a invalid or missing
	 *                                           required software
	 *                                           statement.
	 * @throws JOSEException                     On a internal JOSE
	 *                                           signature verification
	 *                                           exception.
	 */
	public OIDCClientMetadata process(final OIDCClientMetadata clientMetadata)
		throws InvalidSoftwareStatementException, JOSEException {
		
		return process(clientMetadata, null);
	}
	
	
	/**
	 * Processes an optional software statement in the specified client
	 * metadata.
	 *
	 * @param clientMetadata The client metadata, must not be {@code null}.
	 * @param context        Optional security context to pass to the
	 *                       underlying JWK source, {@code null} if not
	 *                       specified.
	 *
	 * @return The processed client metadata, with the merged software
	 *         statement.
	 *
	 * @throws InvalidSoftwareStatementException On a invalid or missing
	 *                                           required software
	 *                                           statement.
	 * @throws JOSEException                     On a internal JOSE
	 *                                           signature verification
	 *                                           exception.
	 */
	public OIDCClientMetadata process(final OIDCClientMetadata clientMetadata, C context)
		throws InvalidSoftwareStatementException, JOSEException {
		
		SignedJWT softwareStatement = clientMetadata.getSoftwareStatement();
		
		if (softwareStatement == null) {
			
			if (required) {
				throw new InvalidSoftwareStatementException("Missing required software statement");
			}
			
			return clientMetadata;
		}
		
		JWTClaimsSet statementClaims;
		try {
			statementClaims = processor.process(softwareStatement, context);
		} catch (BadJOSEException e) {
			throw new InvalidSoftwareStatementException("Invalid software statement JWT: " + e.getMessage(), e);
		} catch (RemoteKeySourceException e) {
			throw new InvalidSoftwareStatementException("Software statement JWT validation failed: " + e.getMessage(), e);
		}
		
		JSONObject mergedMetadataJSONObject = new JSONObject();
		mergedMetadataJSONObject.putAll(clientMetadata.toJSONObject());
		mergedMetadataJSONObject.remove("software_statement");
		
		JSONObject statementJSONObject = JSONObjectUtils.toJSONObject(statementClaims);
		statementJSONObject.remove("iss");
		mergedMetadataJSONObject.putAll(statementJSONObject);
		
		try {
			return OIDCClientMetadata.parse(mergedMetadataJSONObject);
		} catch (ParseException e) {
			throw new InvalidSoftwareStatementException("Error merging software statement: " + e.getMessage(), e);
		}
	}
}
