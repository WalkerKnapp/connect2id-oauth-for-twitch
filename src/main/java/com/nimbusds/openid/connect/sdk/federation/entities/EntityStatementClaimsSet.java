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

package com.nimbusds.openid.connect.sdk.federation.entities;


import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import net.minidev.json.JSONObject;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.MapUtils;
import com.nimbusds.openid.connect.sdk.claims.CommonClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;


/**
 * Federation entity statement claims set, serialisable to a JSON object.
 *
 * <p>Example claims set:
 *
 * <pre>
 * {
 *   "iss": "https://feide.no",
 *   "sub": "https://ntnu.no",
 *   "iat": 1516239022,
 *   "exp": 1516298022,
 *   "crit": ["jti"],
 *   "jti": "7l2lncFdY6SlhNia",
 *   "policy_language_crit": ["regexp"],
 *   "metadata_policy": {
 *     "openid_provider": {
 *       "issuer": {"value": "https://ntnu.no"},
 *       "organization_name": {"value": "NTNU"},
 *       "id_token_signing_alg_values_supported":
 *         {"subset_of": ["RS256", "RS384", "RS512"]},
 *       "op_policy_uri": {
 *         "regexp": "^https:\/\/[\w-]+\.example\.com\/[\w-]+\.html"}
 *     },
 *     "openid_relying_party": {
 *       "organization_name": {"value": "NTNU"},
 *       "grant_types_supported": {
 *         "subset_of": ["authorization_code", "implicit"]},
 *       "scopes": {
 *         "subset_of": ["openid", "profile", "email", "phone"]}
 *     }
 *   },
 *   "constraints": {
 *     "max_path_length": 2
 *   }
 *   "jwks": {
 *     "keys": [
 *       {
 *         "alg": "RS256",
 *         "e": "AQAB",
 *         "ext": true,
 *         "key_ops": ["verify"],
 *         "kid": "key1",
 *         "kty": "RSA",
 *         "n": "pnXBOusEANuug6ewezb9J_...",
 *         "use": "sig"
 *       }
 *     ]
 *   },
 *   "authority_hints": [
 *     "https://edugain.org/federation"
 *   ]
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 2.1.
 * </ul>
 */
public class EntityStatementClaimsSet extends CommonClaimsSet {
	
	
	/**
	 * The expiration time claim name.
	 */
	public static final String EXP_CLAIM_NAME = "exp";
	
	
	/**
	 * The JWK set claim name.
	 */
	public static final String JWKS_CLAIM_NAME = "jwks";
	
	
	/**
	 * The authority hints claim name.
	 */
	public static final String AUTHORITY_HINTS_CLAIM_NAME = "authority_hints";
	
	
	/**
	 * The metadata claim name.
	 */
	public static final String METADATA_CLAIM_NAME = "metadata";
	
	
	/**
	 * The metadata policy claim name.
	 */
	public static final String METADATA_POLICY_CLAIM_NAME = "metadata_policy";
	
	
	/**
	 * The constraints claim name.
	 */
	public static final String CONSTRAINTS_CLAIM_NAME = "constraints";
	
	
	/**
	 * The critical claim name.
	 */
	public static final String CRITICAL_CLAIM_NAME = "crit";
	
	
	/**
	 * The policy critical claim name.
	 */
	public static final String POLICY_LANGUAGE_CRITICAL_CLAIM_NAME = "policy_language_crit";
	
	
	/**
	 * Creates a new federation entity statement claims set with the
	 * minimum required claims.
	 *
	 * @param iss  The issuer. Must not be {@code null}.
	 * @param sub  The subject. Must not be {@code null}.
	 * @param iat  The issue time. Must not be {@code null}.
	 * @param exp  The expiration time. Must not be {@code null}.
	 * @param jwks The entity public JWK set. Must not be {@code null}.
	 */
	public EntityStatementClaimsSet(final Issuer iss,
					final Subject sub,
					final Date iat,
					final Date exp,
					final JWKSet jwks) {
		
		setClaim(ISS_CLAIM_NAME, iss.getValue());
		setClaim(SUB_CLAIM_NAME, sub.getValue());
		setDateClaim(IAT_CLAIM_NAME, iat);
		setDateClaim(EXP_CLAIM_NAME, exp);
		setClaim(JWKS_CLAIM_NAME, jwks.toJSONObject(true)); // public JWKs only
	}
	
	
	/**
	 * Creates a new federation entity statement claims set from the
	 * specified JWT claims set.
	 *
	 * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
	 *
	 * @throws ParseException If the JWT claims set doesn't represent a
	 * 	                  valid federation entity statement claims set.
	 */
	public EntityStatementClaimsSet(final JWTClaimsSet jwtClaimsSet)
		throws ParseException {
		
		super(jwtClaimsSet.toJSONObject());
		
		validateRequiredClaimsPresence();
	}
	
	
	/**
	 * Validates this claims set for having all minimum required claims for
	 * an entity statement. If a {@link #isSelfStatement() selt-statement}
	 * check for the {@link #hasMetadata() presence of metadata}. If
	 * {@link #getCriticalExtensionClaims() critical extension claims} are
	 * listed their presence is also checked.
	 *
	 * @throws ParseException If the validation failed and a required claim
	 *                        is missing.
	 */
	public void validateRequiredClaimsPresence()
		throws ParseException {
		
		if (getIssuer() == null) {
			throw new ParseException("Missing iss (issuer) claim");
		}
		
		if (getSubject() == null) {
			throw new ParseException("Missing sub (subject) claim");
		}
		
		if (getIssueTime() == null) {
			throw new ParseException("Missing iat (issued-at) claim");
		}
		
		if (getExpirationTime() == null) {
			throw new ParseException("Missing exp (expiration) claim");
		}
		
		if (getJWKSet() == null) {
			throw new ParseException("Missing jwks (JWK set) claim");
		}
		
		if (isSelfStatement() && ! hasMetadata()) {
			throw new ParseException("Missing required metadata claim for self-statement");
		}
		
		List<String> crit = getCriticalExtensionClaims();
		
		if (crit != null) {
			for (String claimName: crit) {
				if (getClaim(claimName) == null) {
					throw new ParseException("Missing critical " + claimName + " claim");
				}
			}
		}
	}
	
	
	/**
	 * Returns {@code true} if this is a self-statement (issuer and subject
	 * match).
	 *
	 * @return {@code true} for a self-statement, {@code false} if not.
	 */
	public boolean isSelfStatement() {
		
		Issuer issuer = getIssuer();
		Subject subject = getSubject();
		
		return issuer != null && subject != null && issuer.getValue().equals(subject.getValue());
	}
	
	
	/**
	 * Gets the entity statement expiration time. Corresponds to the
	 * {@code exp} claim.
	 *
	 * @return The expiration time, {@code null} if not specified or
	 *         parsing failed.
	 */
	public Date getExpirationTime() {
		
		return getDateClaim(EXP_CLAIM_NAME);
	}
	
	
	/**
	 * Gets the entity JWK set.
	 *
	 * @return The entity JWK set, {@code null} if not specified or parsing
	 *         failed.
	 */
	public JWKSet getJWKSet() {
		
		try {
			return JWKSet.parse(getJSONObjectClaim(JWKS_CLAIM_NAME));
		} catch (java.text.ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Gets the entity IDs of the intermediate entities or trust anchors.
	 *
	 * @return The entity IDs, {@code null} or empty list for a trust
	 *         anchor, or if parsing failed.
	 */
	public List<EntityID> getAuthorityHints() {
		
		List<String> strings = getStringListClaim(AUTHORITY_HINTS_CLAIM_NAME);
		
		if (strings == null) {
			return null;
		}
		
		List<EntityID> trustChain = new LinkedList<>();
		for (String s: strings) {
			trustChain.add(new EntityID(s));
		}
		return trustChain;
	}
	
	
	/**
	 * Sets the entity IDs of the intermediate entities or trust anchors.
	 *
	 * @param trustChain The entity IDs, {@code null} or empty list for a
	 *                   trust anchor.
	 */
	public void setAuthorityHints(final List<EntityID> trustChain) {
		
		if (trustChain != null) {
			setClaim(AUTHORITY_HINTS_CLAIM_NAME, Identifier.toStringList(trustChain));
		} else {
			setClaim(AUTHORITY_HINTS_CLAIM_NAME, null);
		}
	}
	
	
	/**
	 * Returns {@code true} if a metadata field is present.
	 *
	 * @return {@code true} if for a metadata field for an OpenID relying
	 *         party, OpenID provider, OAuth authorisation server, OAuth
	 *         client, OAuth protected resource or a federation entity is
	 *         present.
	 */
	public boolean hasMetadata() {
	
		JSONObject metadataObject = getJSONObjectClaim(METADATA_CLAIM_NAME);
		
		if (MapUtils.isEmpty(metadataObject)) {
			return false;
		}
		
		if (metadataObject.get(FederationMetadataType.OPENID_RELYING_PARTY.getValue()) != null) return true;
		if (metadataObject.get(FederationMetadataType.OPENID_PROVIDER.getValue()) != null) return true;
		if (metadataObject.get(FederationMetadataType.OAUTH_AUTHORIZATION_SERVER.getValue()) != null) return true;
		if (metadataObject.get(FederationMetadataType.OAUTH_CLIENT.getValue()) != null) return true;
		if (metadataObject.get(FederationMetadataType.OAUTH_RESOURCE.getValue()) != null) return true;
		if (metadataObject.get(FederationMetadataType.FEDERATION_ENTITY.getValue()) != null) return true;
		
		return false;
	}
	
	
	/**
	 * Gets the OpenID relying party metadata if present for this entity.
	 *
	 * @return The RP metadata, {@code null} if not specified or if parsing
	 *         failed.
	 */
	public OIDCClientMetadata getRPMetadata() {
		
		JSONObject o = getJSONObjectClaim(METADATA_CLAIM_NAME);
		
		if (o == null) {
			return null;
		}
		
		try {
			JSONObject rpo = JSONObjectUtils.getJSONObject(o, FederationMetadataType.OPENID_RELYING_PARTY.getValue(), null);
			if (rpo == null) {
				return null;
			}
			return OIDCClientMetadata.parse(rpo);
			
		} catch (com.nimbusds.oauth2.sdk.ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Sets the OpenID relying party metadata if present for this entity.
	 *
	 * @param rpMetadata The RP metadata, {@code null} if not specified.
	 */
	public void setRPMetadata(final OIDCClientMetadata rpMetadata) {
		
		JSONObject o = getJSONObjectClaim(METADATA_CLAIM_NAME);
		
		if (o == null) {
			if (rpMetadata == null) {
				return; // nothing to clear
			}
			o = new JSONObject();
		}
		
		if (rpMetadata != null) {
			o.put(FederationMetadataType.OPENID_RELYING_PARTY.getValue(), rpMetadata.toJSONObject());
		} else {
			o.put(FederationMetadataType.OPENID_RELYING_PARTY.getValue(), null);
		}
		
		setClaim(METADATA_CLAIM_NAME, o);
	}
	
	
	/**
	 * Gets the OpenID provider metadata if present for this entity.
	 *
	 * @return The OP metadata, {@code null} if not specified or if parsing
	 * 	   failed.
	 */
	public OIDCProviderMetadata getOPMetadata() {
		
		JSONObject o = getJSONObjectClaim(METADATA_CLAIM_NAME);
		
		if (o == null) {
			return null;
		}
		
		try {
			JSONObject opo = JSONObjectUtils.getJSONObject(o, FederationMetadataType.OPENID_PROVIDER.getValue(), null);
			if (opo == null) {
				return null;
			}
			return OIDCProviderMetadata.parse(opo);
			
		} catch (com.nimbusds.oauth2.sdk.ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Gets the OpenID provider metadata if present for this entity.
	 *
	 * @param opMetadata The OP metadata, {@code null} if not specified.
	 */
	public void setOPMetadata(final OIDCProviderMetadata opMetadata) {
		
		JSONObject o = getJSONObjectClaim(METADATA_CLAIM_NAME);
		
		if (o == null) {
			if (opMetadata == null) {
				return; // nothing to clear
			}
			o = new JSONObject();
		}
		
		if (opMetadata != null) {
			o.put(FederationMetadataType.OPENID_PROVIDER.getValue(), opMetadata.toJSONObject());
		} else {
			o.put(FederationMetadataType.OPENID_PROVIDER.getValue(), null);
		}
		
		setClaim(METADATA_CLAIM_NAME, o);
	}
	
	
	/**
	 * Gets the OAuth 2.0 client metadata if present for this entity.
	 *
	 * @return The client metadata, {@code null} if not specified or if
	 *         parsing failed.
	 */
	public ClientMetadata getOAuthClientMetadata() {
		
		JSONObject o = getJSONObjectClaim(METADATA_CLAIM_NAME);
		
		if (o == null) {
			return null;
		}
		
		try {
			JSONObject aco = JSONObjectUtils.getJSONObject(o, FederationMetadataType.OAUTH_CLIENT.getValue(), null);
			if (aco == null) {
				return null;
			}
			return ClientMetadata.parse(aco);
			
		} catch (com.nimbusds.oauth2.sdk.ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Sets the OAuth 2.0 client metadata if present for this entity.
	 *
	 * @param clientMetadata The client metadata, {@code null} if not
	 *                       specified.
	 */
	public void setOAuthClientMetadata(final ClientMetadata clientMetadata) {
		
		JSONObject o = getJSONObjectClaim(METADATA_CLAIM_NAME);
		
		if (o == null) {
			if (clientMetadata == null) {
				return; // nothing to clear
			}
			o = new JSONObject();
		}
		
		if (clientMetadata != null) {
			o.put(FederationMetadataType.OAUTH_CLIENT.getValue(), clientMetadata.toJSONObject());
		} else {
			o.put(FederationMetadataType.OAUTH_CLIENT.getValue(), null);
		}
		
		setClaim(METADATA_CLAIM_NAME, o);
	}
	
	
	/**
	 * Gets the OAuth 2.0 authorisation server metadata if present for this
	 * entity.
	 *
	 * @return The AS metadata, {@code null} if not specified or if parsing
	 * 	   failed.
	 */
	public AuthorizationServerMetadata getASMetadata() {
		
		JSONObject o = getJSONObjectClaim(METADATA_CLAIM_NAME);
		
		if (o == null) {
			return null;
		}
		
		try {
			JSONObject opo = JSONObjectUtils.getJSONObject(o, FederationMetadataType.OAUTH_AUTHORIZATION_SERVER.getValue(), null);
			if (opo == null) {
				return null;
			}
			return AuthorizationServerMetadata.parse(opo);
			
		} catch (com.nimbusds.oauth2.sdk.ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Sets the OAuth 2.0 authorisation server metadata if present for this
	 * entity.
	 *
	 * @param asMetadata The AS metadata, {@code null} if not specified.
	 */
	public void setASMetadata(final AuthorizationServerMetadata asMetadata) {
		
		JSONObject o = getJSONObjectClaim(METADATA_CLAIM_NAME);
		
		if (o == null) {
			if (asMetadata == null) {
				return; // nothing to clear
			}
			o = new JSONObject();
		}
		
		if (asMetadata != null) {
			o.put(FederationMetadataType.OAUTH_AUTHORIZATION_SERVER.getValue(), asMetadata.toJSONObject());
		} else {
			o.put(FederationMetadataType.OAUTH_AUTHORIZATION_SERVER.getValue(), null);
		}
		
		setClaim(METADATA_CLAIM_NAME, o);
	}
	
	
	/**
	 * Gets the federation entity metadata if present for this entity.
	 *
	 * @return The federation entity metadata, {@code null} if not
	 *         specified or if parsing failed.
	 */
	public FederationEntityMetadata getFederationEntityMetadata() {
		
		JSONObject o = getJSONObjectClaim(METADATA_CLAIM_NAME);
		
		if (o == null) {
			return null;
		}
		
		try {
			JSONObject feo = JSONObjectUtils.getJSONObject(o, FederationMetadataType.FEDERATION_ENTITY.getValue(), null);
			if (feo == null) {
				return null;
			}
			return FederationEntityMetadata.parse(feo);
			
		} catch (com.nimbusds.oauth2.sdk.ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Sets the federation entity metadata if present for this entity.
	 *
	 * @param entityMetadata The federation entity metadata, {@code null}
	 *                       if not specified.
	 */
	public void setFederationEntityMetadata(final FederationEntityMetadata entityMetadata) {
		
		JSONObject o = getJSONObjectClaim(METADATA_CLAIM_NAME);
		
		if (o == null) {
			if (entityMetadata == null) {
				return; // nothing to clear
			}
			o = new JSONObject();
		}
		
		if (entityMetadata != null) {
			o.put(FederationMetadataType.FEDERATION_ENTITY.getValue(), entityMetadata.toJSONObject());
		} else {
			o.put(FederationMetadataType.FEDERATION_ENTITY.getValue(), null);
		}
		
		setClaim(METADATA_CLAIM_NAME, o);
	}
	
	
	/**
	 * Gets the metadata policy JSON object.
	 *
	 * @return The metadata policy JSON object, {@code null} if not
	 *         specified or if parsing failed.
	 */
	public JSONObject getMetadataPolicyJSONObject() {
		
		return getJSONObjectClaim(METADATA_POLICY_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the metadata policy JSON object.
	 *
	 * @param metadataPolicy The metadata policy JSON object, {@code null}
	 *                       if not specified.
	 */
	public void setMetadataPolicyJSONObject(final JSONObject metadataPolicy) {
	
		setClaim(METADATA_POLICY_CLAIM_NAME, metadataPolicy);
	}
	
	
	/**
	 * Gets the trust chain constraints for subordinate entities.
	 *
	 * @return The trust chain constraints, {@code null} if not specified
	 *          or if parsing failed.
	 */
	public TrustChainConstraints getConstraints() {
		
		JSONObject o = getJSONObjectClaim(CONSTRAINTS_CLAIM_NAME);
		
		if (o == null) {
			return null;
		}
		
		try {
			return TrustChainConstraints.parse(o);
		} catch (com.nimbusds.oauth2.sdk.ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Sets the trust chain constraints for subordinate entities.
	 *
	 * @param constraints The trust chain constraints, {@code null} if not
	 *                    specified.
	 */
	public void setConstraints(final TrustChainConstraints constraints) {
	
		if (constraints != null) {
			setClaim(CONSTRAINTS_CLAIM_NAME, constraints.toJSONObject());
		} else {
			setClaim(CONSTRAINTS_CLAIM_NAME, null);
		}
	}
	
	
	/**
	 * Gets the names of the critical extension claims.
	 *
	 * @return The names of the critical extension claims, {@code null} if
	 *         not specified or if parsing failed.
	 */
	public List<String> getCriticalExtensionClaims() {
		
		return getStringListClaim(CRITICAL_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the names of the critical extension claims.
	 *
	 * @param claimNames The names of the critical extension claims,
	 *                   {@code null} if not specified. Must not be an
	 *                   empty list.
	 */
	public void setCriticalExtensionClaims(final List<String> claimNames) {
	
		if (claimNames != null && claimNames.isEmpty()) {
			throw new IllegalArgumentException("The critical extension claim names must not be empty");
		}
		
		setClaim(CRITICAL_CLAIM_NAME, claimNames);
	}
	
	
	/**
	 * Gets the names of the critical policy extensions.
	 *
	 * @return The names of the critical policy extensions or if parsing
	 *         failed.
	 */
	public List<String> getCriticalPolicyExtensions() {
		
		return getStringListClaim(POLICY_LANGUAGE_CRITICAL_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the names of the critical policy extensions.
	 *
	 * @param extNames The names of the critical policy extensions,
	 *                 {@code null} if not specified. Must not be an empty
	 *                 list.
	 */
	public void setCriticalPolicyExtensions(final List<String> extNames) {
	
		if (extNames != null && extNames.isEmpty()) {
			throw new IllegalArgumentException("The critical policy extension names must not be empty");
		}
		
		setClaim(POLICY_LANGUAGE_CRITICAL_CLAIM_NAME, extNames);
	}
}
