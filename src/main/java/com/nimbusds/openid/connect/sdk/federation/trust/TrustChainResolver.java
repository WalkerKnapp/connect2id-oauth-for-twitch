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

package com.nimbusds.openid.connect.sdk.federation.trust;


import java.util.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.oauth2.sdk.util.MapUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.trust.constraints.TrustChainConstraints;


/**
 * Trust chain resolver.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 9.
 * </ul>
 */
public class TrustChainResolver {
	
	
	/**
	 * The configured trust anchors with their public JWK sets.
	 */
	private final Map<EntityID, JWKSet> trustAnchors;
	
	
	/**
	 * The entity statement retriever.
	 */
	private final EntityStatementRetriever statementRetriever;
	
	
	/**
	 * The trust chain constraints.
	 */
	private final TrustChainConstraints constraints;
	
	
	/**
	 * Creates a new trust chain resolver with a single trust anchor, with
	 * {@link TrustChainConstraints#NO_CONSTRAINTS no trust chain
	 * constraints}.
	 *
	 * @param trustAnchor The trust anchor. Must not be {@code null}.
	 */
	public TrustChainResolver(final EntityID trustAnchor) {
		this(trustAnchor, null);
	}
	
	
	/**
	 * Creates a new trust chain resolver with a single trust anchor, with
	 * {@link TrustChainConstraints#NO_CONSTRAINTS no trust chain
	 * constraints}.
	 *
	 * @param trustAnchor       The trust anchor. Must not be {@code null}.
	 * @param trustAnchorJWKSet The trust anchor public JWK set,
	 *                          {@code null} if not available.
	 */
	public TrustChainResolver(final EntityID trustAnchor,
				  final JWKSet trustAnchorJWKSet) {
		this(
			Collections.singletonMap(trustAnchor, trustAnchorJWKSet),
			TrustChainConstraints.NO_CONSTRAINTS,
			new DefaultEntityStatementRetriever()
		);
	}
	
	
	/**
	 * Creates a new trust chain resolver with multiple trust anchors, with
	 * {@link TrustChainConstraints#NO_CONSTRAINTS no trust chain
	 * constraints}.
	 *
	 * @param trustAnchors         The trust anchors with their public JWK
	 *                             sets (if available). Must contain at
	 *                             least one anchor.
	 * @param httpConnectTimeoutMs The HTTP connect timeout in
	 *                             milliseconds, zero means timeout
	 *                             determined by the underlying HTTP
	 *                             client.
	 * @param httpReadTimeoutMs    The HTTP read timeout in milliseconds,
	 *                             zero means timeout determined by the
	 *                             underlying HTTP client.
	 */
	public TrustChainResolver(final Map<EntityID, JWKSet> trustAnchors,
				  final int httpConnectTimeoutMs,
				  final int httpReadTimeoutMs) {
		this(
			trustAnchors,
			TrustChainConstraints.NO_CONSTRAINTS,
			new DefaultEntityStatementRetriever(httpConnectTimeoutMs, httpReadTimeoutMs)
		);
	}
	
	
	/**
	 * Creates new trust chain resolver.
	 *
	 * @param trustAnchors       The trust anchors with their public JWK
	 *                           sets. Must contain at least one anchor.
	 * @param statementRetriever The entity statement retriever to use.
	 *                           Must not be {@code null}.
	 */
	public TrustChainResolver(final Map<EntityID, JWKSet> trustAnchors,
				  final TrustChainConstraints constraints,
				  final EntityStatementRetriever statementRetriever) {
		
		if (MapUtils.isEmpty(trustAnchors)) {
			throw new IllegalArgumentException("The trust anchors map must not be empty or null");
		}
		this.trustAnchors = trustAnchors;
		
		if (constraints == null) {
			throw new IllegalArgumentException("The trust chain constraints must not be null");
		}
		this.constraints = constraints;
		
		if (statementRetriever == null) {
			throw new IllegalArgumentException("The entity statement retriever must not be null");
		}
		this.statementRetriever = statementRetriever;
	}
	
	
	/**
	 * Returns the configured trust anchors.
	 *
	 * @return The trust anchors with their public JWK sets (if available).
	 *         Contains at least one anchor.
	 */
	public Map<EntityID, JWKSet> getTrustAnchors() {
		return Collections.unmodifiableMap(trustAnchors);
	}
	
	
	/**
	 * Returns the configured entity statement retriever.
	 *
	 * @return The entity statement retriever.
	 */
	public EntityStatementRetriever getEntityStatementRetriever() {
		return statementRetriever;
	}
	
	
	/**
	 * Returns the configured trust chain constraints.
	 *
	 * @return The constraints.
	 */
	public TrustChainConstraints getConstraints() {
		return constraints;
	}
	
	
	/**
	 * Resolves the trust chains for the specified target.
	 *
	 * @param target The target. Must not be {@code null}.
	 *
	 * @return The resolved trust chains, containing at least one valid and
	 *         verified chain.
	 *
	 * @throws ResolveException If no trust chain could be resolved.
	 */
	public TrustChainSet resolveTrustChains(final EntityID target)
		throws ResolveException {
		
		try {
			return resolveTrustChains(target, null);
		} catch (InvalidEntityMetadataException e) {
			// Should never occur if target metadata validator omitted
			throw new IllegalStateException("Unexpected exception: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Resolves the trust chains for the specified target, with optional
	 * validation of the target entity metadata. The validator can for
	 * example check that for an entity which is expected to be an OpenID
	 * relying party the required party metadata is present.
	 *
	 * @param target                  The target. Must not be {@code null}.
	 * @param targetMetadataValidator To perform optional validation of the
	 *                                retrieved target entity metadata,
	 *                                before proceeding with retrieving the
	 *                                entity statements from the
	 *                                authorities, {@code null} if not
	 *                                specified.
	 *
	 * @return The resolved trust chains, containing at least one valid and
	 *         verified chain.
	 *
	 * @throws ResolveException               If a trust chain could not be
	 *                                        resolved.
	 * @throws InvalidEntityMetadataException If the optional target entity
	 *                                        metadata validation didn't
	 *                                        pass.
	 */
	public TrustChainSet resolveTrustChains(final EntityID target,
						final EntityMetadataValidator targetMetadataValidator)
		throws ResolveException, InvalidEntityMetadataException {
		
		if (trustAnchors.get(target) != null) {
			throw new ResolveException("Target is trust anchor");
		}
		
		TrustChainRetriever retriever = new DefaultTrustChainRetriever(statementRetriever, constraints);
		Set<TrustChain> fetchedTrustChains = retriever.retrieve(target, targetMetadataValidator, trustAnchors.keySet());
		return verifyTrustChains(
			fetchedTrustChains,
			retriever.getAccumulatedTrustAnchorJWKSets(),
			retriever.getAccumulatedExceptions());
	}
	
	
	/**
	 * Resolves the trust chains for the specified target.
	 *
	 * @param targetStatement The target entity statement. Must not be
	 *                        {@code null}.
	 *
	 * @return The resolved trust chains, containing at least one valid and
	 *         verified chain.
	 *
	 * @throws ResolveException If no trust chain could be resolved.
	 */
	public TrustChainSet resolveTrustChains(final EntityStatement targetStatement)
		throws ResolveException {
		
		if (trustAnchors.get(targetStatement.getEntityID()) != null) {
			throw new ResolveException("Target is trust anchor");
		}
		
		TrustChainRetriever retriever = new DefaultTrustChainRetriever(statementRetriever, constraints);
		Set<TrustChain> fetchedTrustChains = retriever.retrieve(targetStatement, trustAnchors.keySet());
		return verifyTrustChains(
			fetchedTrustChains,
			retriever.getAccumulatedTrustAnchorJWKSets(),
			retriever.getAccumulatedExceptions());
	}
	
	
	/**
	 * Verifies the specified fetched trust chains.
	 *
	 * @param fetchedTrustChains            The fetched trust chains. Must
	 *                                      not be {@code null},
	 * @param accumulatedTrustAnchorJWKSets The accumulated trust anchor(s)
	 *                                      JWK sets, empty if none. Must
	 *                                      not be {@code null}.
	 * @param accumulatedExceptions         The accumulated exceptions,
	 *                                      empty if none. Must not be
	 *                                      {@code null}.
	 * @return The verified trust chain set.
	 *
	 * @throws ResolveException If no trust chain could be verified.
	 */
	private TrustChainSet verifyTrustChains(final Set<TrustChain> fetchedTrustChains,
						final Map<EntityID, JWKSet> accumulatedTrustAnchorJWKSets,
						final List<Throwable> accumulatedExceptions)
		throws ResolveException {
		
		if (fetchedTrustChains.isEmpty()) {
			if (accumulatedExceptions.isEmpty()) {
				throw new ResolveException("No trust chain leading up to a trust anchor");
			} else if (accumulatedExceptions.size() == 1){
				Throwable cause = accumulatedExceptions.get(0);
				throw new ResolveException("Couldn't resolve trust chain: " + cause.getMessage(), cause);
			} else {
				throw new ResolveException("Couldn't resolve trust chain due to multiple causes", accumulatedExceptions);
			}
		}
		
		List<Throwable> verificationExceptions = new LinkedList<>();
		
		TrustChainSet verifiedTrustChains = new TrustChainSet();
		
		for (TrustChain chain: fetchedTrustChains) {
			
			EntityID anchor = chain.getTrustAnchorEntityID();
			JWKSet anchorJWKSet = trustAnchors.get(anchor);
			if (anchorJWKSet == null) {
				anchorJWKSet = accumulatedTrustAnchorJWKSets.get(anchor);
			}
			
			try {
				chain.verifySignatures(anchorJWKSet);
			} catch (BadJOSEException | JOSEException e) {
				verificationExceptions.add(e);
				continue;
			}
			
			verifiedTrustChains.add(chain);
		}
		
		if (verifiedTrustChains.isEmpty()) {
			
			List<Throwable> moreAccumulatedExceptions = new LinkedList<>(accumulatedExceptions);
			moreAccumulatedExceptions.addAll(verificationExceptions);
			
			if (verificationExceptions.size() == 1) {
				Throwable cause = verificationExceptions.get(0);
				throw new ResolveException("Couldn't resolve trust chain: " + cause.getMessage(), moreAccumulatedExceptions);
			} else {
				throw new ResolveException("Couldn't resolve trust chain due to multiple causes", moreAccumulatedExceptions);
			}
		}
		
		return verifiedTrustChains;
	}
}
