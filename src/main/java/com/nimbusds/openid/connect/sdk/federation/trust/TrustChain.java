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


import java.security.ProviderException;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.oauth2.sdk.util.ListUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityStatement;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;
import com.nimbusds.openid.connect.sdk.federation.policy.MetadataPolicy;
import com.nimbusds.openid.connect.sdk.federation.policy.MetadataPolicyEntry;
import com.nimbusds.openid.connect.sdk.federation.policy.language.PolicyViolationException;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.DefaultPolicyOperationCombinationValidator;
import com.nimbusds.openid.connect.sdk.federation.policy.operations.PolicyOperationCombinationValidator;


/**
 * Federation entity trust chain.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, sections 3.2 and 7.1.
 * </ul>
 */
@Immutable
public final class TrustChain {
	
	
	/**
	 * The leaf entity configuration.
	 */
	private final EntityStatement leaf;
	
	
	/**
	 * The superior entity statements.
	 */
	private final List<EntityStatement> superiors;
	
	
	/**
	 * The optional trust anchor entity configuration.
	 */
	private final EntityStatement trustAnchor;
	
	
	/**
	 * Caches the resolved expiration time for this trust chain.
	 */
	private Date exp;
	
	
	/**
	 * Creates a new trust chain. Validates the subject - issuer chain, the
	 * signatures are not verified.
	 *
	 * @param leaf      The leaf entity configuration. Must not be
	 *                  {@code null}.
	 * @param superiors The superior entity statements, starting with a
	 *                  statement of the first superior about the leaf,
	 *                  ending with the statement of the trust anchor about
	 *                  the last intermediate or the leaf (for a minimal
	 *                  trust chain). Must contain at least one entity
	 *                  statement.
	 *
	 * @throws IllegalArgumentException If the subject - issuer chain is
	 *                                  broken.
	 */
	public TrustChain(final EntityStatement leaf, final List<EntityStatement> superiors) {
		this(leaf, superiors, null);
	}
	
	
	/**
	 * Creates a new trust chain. Validates the subject - issuer chain, the
	 * signatures are not verified.
	 *
	 * @param leaf        The leaf entity configuration. Must not be
	 *                    {@code null}.
	 * @param superiors   The superior entity statements, starting with a
	 *                    statement of the first superior about the leaf,
	 *                    ending with the statement of the trust anchor
	 *                    about the last intermediate or the leaf (for a
	 *                    minimal trust chain). Must contain at least one
	 *                    entity statement.
	 * @param trustAnchor The optional trust anchor entity configuration,
	 *                    {@code null} if not specified.
	 *
	 * @throws IllegalArgumentException If the subject - issuer chain is
	 *                                  broken.
	 */
	public TrustChain(final EntityStatement leaf, final List<EntityStatement> superiors, final EntityStatement trustAnchor) {
		
		// leaf config checks
		if (leaf == null) {
			throw new IllegalArgumentException("The leaf entity configuration must not be null");
		}
		if (! leaf.getClaimsSet().isSelfStatement()) {
			throw new IllegalArgumentException("The leaf entity configuration must be a self-statement");
		}
		this.leaf = leaf;
		
		// superior statements check
		if (CollectionUtils.isEmpty(superiors)) {
			throw new IllegalArgumentException("There must be at least one superior statement (issued by the trust anchor)");
		}
		this.superiors = superiors;
		
		// optional trust anchor config checks
		this.trustAnchor = trustAnchor;
		
		if (trustAnchor != null && ! trustAnchor.getClaimsSet().isSelfStatement()) {
			throw new IllegalArgumentException("The trust anchor entity configuration must be a self-statement");
		}
		
		if (! hasValidIssuerSubjectChain(leaf, superiors, trustAnchor)) {
			throw new IllegalArgumentException("Broken subject - issuer chain");
		}
	}
	
	
	private static boolean hasValidIssuerSubjectChain(final EntityStatement leaf,
							  final List<EntityStatement> superiors,
							  final EntityStatement trustAnchor) {
		
		Subject nextExpectedSubject = leaf.getClaimsSet().getSubject();
		
		for (EntityStatement superiorStmt : superiors) {
			if (! nextExpectedSubject.equals(superiorStmt.getClaimsSet().getSubject())) {
				return false; // chain breaks
			}
			nextExpectedSubject = new Subject(superiorStmt.getClaimsSet().getIssuer().getValue());
		}
		
		if (trustAnchor == null) {
			// No optional trust anchor config
			return true;
		}
		
		// The last issuer in the chain is the trust anchor
		EntityStatement topSuperior = superiors.get(superiors.size() - 1);
		return topSuperior.getClaimsSet().getIssuer().equals(trustAnchor.getClaimsSet().getIssuer());
	}
	
	
	/**
	 * Returns the leaf entity configuration.
	 *
	 * @return The leaf entity configuration.
	 */
	public EntityStatement getLeafConfiguration() {
		return leaf;
	}
	
	
	/**
	 * Returns the superior entity statements.
	 *
	 * @return The superior entity statements, starting with a statement of
	 *         the first superior about the leaf, ending with the statement
	 *         of the trust anchor about the last intermediate or the leaf
	 *         (for a minimal trust chain).
	 */
	public List<EntityStatement> getSuperiorStatements() {
		return superiors;
	}
	
	
	/**
	 * Returns the optional trust anchor entity configuration.
	 *
	 * @return The trust anchor entity configuration, {@code null} if not
	 *         specified.
	 */
	public EntityStatement getTrustAnchorConfiguration() {
		return trustAnchor;
	}
	
	
	/**
	 * Returns the entity ID of the trust anchor.
	 *
	 * @return The entity ID of the trust anchor.
	 */
	public EntityID getTrustAnchorEntityID() {
		
		// Return last in superiors
		return getSuperiorStatements()
			.get(getSuperiorStatements().size() - 1)
			.getClaimsSet()
			.getIssuerEntityID();
	}
	
	
	/**
	 * Returns the length of this trust chain. A minimal trust chain with a
	 * leaf and anchor has a length of one.
	 *
	 * @return The trust chain length, with a minimal length of one.
	 */
	public int length() {
		
		return getSuperiorStatements().size();
	}
	
	
	/**
	 * Resolves the combined metadata policy for this trust chain. Uses the
	 * {@link DefaultPolicyOperationCombinationValidator default policy
	 * combination validator}.
	 *
	 * @param type The entity type, such as {@code openid_relying_party}.
	 *             Must not be {@code null}.
	 *
	 * @return The combined metadata policy, with no policy operations if
	 *         no policies were found.
	 *
	 * @throws PolicyViolationException On a policy violation exception.
	 */
	public MetadataPolicy resolveCombinedMetadataPolicy(final EntityType type)
		throws PolicyViolationException {
		
		return resolveCombinedMetadataPolicy(type, MetadataPolicyEntry.DEFAULT_POLICY_COMBINATION_VALIDATOR);
	}
	
	
	/**
	 * Resolves the combined metadata policy for this trust chain.
	 *
	 * @param type                 The entity type, such as
	 *                             {@code openid_relying_party}. Must not
	 *                             be {@code null}.
	 * @param combinationValidator The policy operation combination
	 *                             validator. Must not be {@code null}.
	 *
	 * @return The combined metadata policy, with no policy operations if
	 *         no policies were found.
	 *
	 * @throws PolicyViolationException On a policy violation exception.
	 */
	public MetadataPolicy resolveCombinedMetadataPolicy(final EntityType type,
							    final PolicyOperationCombinationValidator combinationValidator)
		throws PolicyViolationException {
		
		List<MetadataPolicy> policies = new LinkedList<>();
		
		for (EntityStatement stmt: getSuperiorStatements()) {
			
			MetadataPolicy metadataPolicy = stmt.getClaimsSet().getMetadataPolicy(type);
			
			if (metadataPolicy == null) {
				continue;
			}
			
			policies.add(metadataPolicy);
		}
		
		return MetadataPolicy.combine(policies, combinationValidator);
	}
	
	
	/**
	 * Return an iterator starting from the leaf entity statement. The
	 * optional trust anchor entity configuration is omitted.
	 *
	 * @return The iterator.
	 */
	public Iterator<EntityStatement> iteratorFromLeaf() {
		
		// Init
		final AtomicReference<EntityStatement> next = new AtomicReference<>(leaf);
		final Iterator<EntityStatement> superiorsIterator = superiors.iterator();
		
		return new Iterator<EntityStatement>() {
			@Override
			public boolean hasNext() {
				return next.get() != null;
			}
			
			
			@Override
			public EntityStatement next() {
				EntityStatement toReturn = next.get();
				if (toReturn == null) {
					return null; // reached end on last iteration
				}
				
				// Set statement to return on next iteration
				if (toReturn.equals(leaf)) {
					// Return first superior
					next.set(superiorsIterator.next());
				} else {
					// Return next superior or end
					if (superiorsIterator.hasNext()) {
						next.set(superiorsIterator.next());
					} else {
						next.set(null);
					}
				}
				
				return toReturn;
			}
			
			
			@Override
			public void remove() {
				throw new UnsupportedOperationException();
			}
		};
	}
	
	
	/**
	 * Resolves the expiration time for this trust chain. Equals the next
	 * expiration in time when all entity statements in the trust chain are
	 * considered.
	 *
	 * @return The expiration time for this trust chain.
	 */
	public Date resolveExpirationTime() {
		
		if (exp != null) {
			return exp;
		}
		
		Iterator<EntityStatement> it = iteratorFromLeaf();
		
		Date nearestExp = null;
		
		while (it.hasNext()) {
			
			Date stmtExp = it.next().getClaimsSet().getExpirationTime();
			
			if (nearestExp == null) {
				nearestExp = stmtExp; // on first iteration
			} else if (stmtExp.before(nearestExp)) {
				nearestExp = stmtExp; // replace nearest
			}
		}
		
		exp = nearestExp;
		return exp;
	}
	
	
	/**
	 * Verifies the signatures in this trust chain.
	 *
	 * @param trustAnchorJWKSet The trust anchor JWK set. Must not be
	 *                          {@code null}.
	 *
	 * @throws BadJOSEException If a signature is invalid or a statement is
	 *                          expired or before the issue time.
	 * @throws JOSEException    On an internal JOSE exception.
	 */
	public void verifySignatures(final JWKSet trustAnchorJWKSet)
		throws BadJOSEException, JOSEException {
		
		Base64URL signingJWKThumbprint;
		try {
			signingJWKThumbprint = leaf.verifySignatureOfSelfStatement();
		} catch (BadJOSEException e) {
			throw new BadJOSEException("Invalid leaf entity configuration: " + e.getMessage(), e);
		}
		
		for (int i=0; i < superiors.size(); i++) {
			
			EntityStatement stmt = superiors.get(i);
			
			JWKSet verificationJWKSet;
			if (i+1 == superiors.size()) {
				verificationJWKSet = trustAnchorJWKSet;
			} else {
				verificationJWKSet = superiors.get(i+1).getClaimsSet().getJWKSet();
			}
			
			// Check that the signing JWK is registered with the superior
			if (! hasJWKWithThumbprint(stmt.getClaimsSet().getJWKSet(), signingJWKThumbprint)) {
				throw new BadJOSEException("Signing JWK with thumbprint " + signingJWKThumbprint + " not found in entity statement issued from superior " + stmt.getClaimsSet().getIssuerEntityID());
			}
			
			try {
				signingJWKThumbprint = stmt.verifySignature(verificationJWKSet);
			} catch (BadJOSEException e) {
				throw new BadJOSEException("Invalid statement from " + stmt.getClaimsSet().getIssuer() + ": " + e.getMessage(), e);
			}
		}
		
		if (trustAnchor != null) {
			
			if (! hasJWKWithThumbprint(trustAnchor.getClaimsSet().getJWKSet(), signingJWKThumbprint)) {
				throw new BadJOSEException("Signing JWK with thumbprint " + signingJWKThumbprint + " not found in trust anchor entity configuration");
			}
			
			try {
				trustAnchor.verifySignatureOfSelfStatement();
			} catch (BadJOSEException e) {
				throw new BadJOSEException("Invalid trust anchor entity configuration: " + e.getMessage(), e);
			}
		}
	}
	
	
	private static boolean hasJWKWithThumbprint(final JWKSet jwkSet, final Base64URL thumbprint) {
		
		if (jwkSet == null) {
			return false;
		}
		
		for (JWK jwk: jwkSet.getKeys()) {
			try {
				if (thumbprint.equals(jwk.computeThumbprint())) {
					return true;
				}
			} catch (JOSEException e) {
				throw new ProviderException(e.getMessage(), e);
			}
		}
		
		return false;
	}
	
	
	/**
	 * Returns a JWT list representation of this trust chain.
	 *
	 * @return The JWT list.
	 */
	public List<SignedJWT> toJWTs() {
	
		List<SignedJWT> out = new LinkedList<>();
		out.add(leaf.getSignedStatement());
		for (EntityStatement s: superiors) {
			out.add(s.getSignedStatement());
		}
		if (trustAnchor != null) {
			out.add(trustAnchor.getSignedStatement());
		}
		return out;
	}
	
	
	/**
	 * Returns a serialised JWT list representation of this trust chain.
	 *
	 * @return The serialised JWT list.
	 */
	public List<String> toSerializedJWTs() {
		
		List<String> out = new LinkedList<>();
		for (SignedJWT jwt: toJWTs()) {
			out.add(jwt.serialize());
		}
		return out;
	}
	
	
	/**
	 * Parses a trust chain from the specified JWT list.
	 *
	 * @param statementJWTs The JWT list. Must not be {@code null}.
	 *
	 * @return The trust chain.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static TrustChain parse(final List<SignedJWT> statementJWTs)
		throws ParseException {
		
		if (statementJWTs.size() < 2) {
			throw new ParseException("There must be at least 2 statement JWTs");
		}
		
		EntityStatement leaf = null;
		List<EntityStatement> superiors = new LinkedList<>();
		EntityStatement trustAnchor = null;
		
		for (SignedJWT jwt: ListUtils.removeNullItems(statementJWTs)) {
			
			if (leaf == null) {
				try {
					leaf = EntityStatement.parse(jwt);
				} catch (ParseException e) {
					throw new ParseException("Invalid leaf entity configuration: " + e.getMessage(), e);
				}
			} else {
				EntityStatement statement;
				try {
					statement = EntityStatement.parse(jwt);
				} catch (ParseException e) {
					throw new ParseException("Invalid superior entity statement: " + e.getMessage(), e);
				}
				if (! statement.getClaimsSet().isSelfStatement()) {
					superiors.add(statement);
				} else {
					trustAnchor = statement; // assume optional TA config
				}
			}
		}
		try {
			return new TrustChain(leaf, superiors, trustAnchor);
		} catch (Exception e) {
			throw new ParseException("Illegal trust chain: " + e.getMessage(), e);
		}
	}
	
	
	/**
	 * Parses a trust chain from the specified serialised JWT list.
	 *
	 * @param statementJWTs The serialised JWT list. Must not be
	 *                      {@code null}.
	 *
	 * @return The trust chain.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static TrustChain parseSerialized(final List<String> statementJWTs)
		throws ParseException {
		
		List<SignedJWT> jwtList = new LinkedList<>();
		
		for (String s: ListUtils.removeNullItems(statementJWTs)) {
			try {
				jwtList.add(SignedJWT.parse(s));
			} catch (java.text.ParseException e) {
				throw new ParseException("Invalid JWT in trust chain: " + e.getMessage(), e);
			}
		}
		
		return parse(jwtList);
	}
}
