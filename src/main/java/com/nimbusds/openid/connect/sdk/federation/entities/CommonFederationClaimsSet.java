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

package com.nimbusds.openid.connect.sdk.federation.entities;


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.claims.CommonClaimsSet;
import com.nimbusds.openid.connect.sdk.federation.trust.marks.TrustMarkEntry;
import com.nimbusds.openid.connect.sdk.federation.trust.marks.TrustMarkIssuerMetadata;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;


/**
 * Common federation claims set.
 */
public abstract class CommonFederationClaimsSet extends CommonClaimsSet {
	
	
	/**
	 * The expiration time claim name.
	 */
	public static final String EXP_CLAIM_NAME = "exp";
	
	
	/**
	 * The metadata claim name.
	 */
	public static final String METADATA_CLAIM_NAME = "metadata";
	
	
	/**
	 * The trust marks claim name.
	 */
	public static final String TRUST_MARKS_CLAIM_NAME = "trust_marks";
	
	
	/**
	 * Creates a new empty common federation claims set.
	 */
	protected CommonFederationClaimsSet() {
		super();
	}
	
	
	/**
	 * Creates a new common federation claims set from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 */
	protected CommonFederationClaimsSet(final JSONObject jsonObject) {
		super(jsonObject);
	}
	
	
	/**
	 * Validates this claims set for having all minimum required claims.
	 *
	 * @throws ParseException If the validation failed and a required claim
	 *                        is missing.
	 */
	protected void validateRequiredClaimsPresence()
		throws ParseException {
		
		if (getIssuer() == null) {
			throw new ParseException("Missing iss (issuer) claim");
		}
		
		EntityID.parse(getIssuer()); // ensure URI
		
		if (getSubject() == null) {
			throw new ParseException("Missing sub (subject) claim");
		}
		
		EntityID.parse(getSubject()); // ensure URI
		
		if (getIssueTime() == null) {
			throw new ParseException("Missing iat (issued-at) claim");
		}
		
		if (getExpirationTime() == null) {
			throw new ParseException("Missing exp (expiration) claim");
		}
	}
	
	
	/**
	 * Returns the issuer as entity ID. Corresponds to the {@code iss}
	 * claim.
	 *
	 * @return The issuer as entity ID.
	 */
	public EntityID getIssuerEntityID() {
		
		return new EntityID(getIssuer().getValue());
	}
	
	
	/**
	 * Returns the subject as entity ID. Corresponds to the {@code iss}
	 * claim.
	 *
	 * @return The subject as entity ID.
	 */
	public EntityID getSubjectEntityID() {
		
		return new EntityID(getSubject().getValue());
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
	 * Gets the metadata for the specified entity type. Use a typed getter,
	 * such as {@link #getRPMetadata}, when available. Corresponds to the
	 * {@code metadata} claim.
	 *
	 * @param type The entity type. Must not be {@code null}.
	 *
	 * @return The metadata, {@code null} if not specified or if parsing
	 *         failed.
	 */
	public JSONObject getMetadata(final EntityType type) {
		
		JSONObject o = getJSONObjectClaim(METADATA_CLAIM_NAME);
		
		if (o == null) {
			return null;
		}
		
		try {
			return JSONObjectUtils.getJSONObject(o, type.getValue(), null);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Sets the metadata for the specified entity type. Use a typed setter,
	 * such as {@link #setRPMetadata}, when available. Corresponds to the
	 * {@code metadata} claim.
	 *
	 * @param type     The type. Must not be {@code null}.
	 * @param metadata The metadata, {@code null} if not specified.
	 */
	public void setMetadata(final EntityType type, final JSONObject metadata) {

		JSONObject o = getJSONObjectClaim(METADATA_CLAIM_NAME);

		if (o == null) {
			if (metadata == null) {
				return; // nothing to clear
			}
			o = new JSONObject();
		}

		o.put(type.getValue(), metadata);

		setClaim(METADATA_CLAIM_NAME, o);
	}
	
	
	/**
	 * Gets the OpenID relying party metadata if present for this entity.
	 * Corresponds to the {@code metadata.openid_relying_party} claim.
	 *
	 * @return The RP metadata, {@code null} if not specified or if parsing
	 *         failed.
	 */
	public OIDCClientMetadata getRPMetadata() {
		
		JSONObject o = getMetadata(EntityType.OPENID_RELYING_PARTY);
		
		if (o == null) {
			return null;
		}
		
		try {
			return OIDCClientMetadata.parse(o);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Sets the OpenID relying party metadata if present for this entity.
	 * Corresponds to the {@code metadata.openid_relying_party} claim.
	 *
	 * @param rpMetadata The RP metadata, {@code null} if not specified.
	 */
	public void setRPMetadata(final OIDCClientMetadata rpMetadata) {

		JSONObject o = rpMetadata != null ? rpMetadata.toJSONObject() : null;
		setMetadata(EntityType.OPENID_RELYING_PARTY, o);
	}
	
	
	/**
	 * Gets the OpenID provider metadata if present for this entity.
	 * Corresponds to the {@code metadata.openid_provider} claim.
	 *
	 * @return The OP metadata, {@code null} if not specified or if parsing
	 * 	   failed.
	 */
	public OIDCProviderMetadata getOPMetadata() {
		
		JSONObject o = getMetadata(EntityType.OPENID_PROVIDER);
		
		if (o == null) {
			return null;
		}
		
		try {
			return OIDCProviderMetadata.parse(o);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Gets the OpenID provider metadata if present for this entity.
	 * Corresponds to the {@code metadata.openid_provider} claim.
	 *
	 * @param opMetadata The OP metadata, {@code null} if not specified.
	 */
	public void setOPMetadata(final OIDCProviderMetadata opMetadata) {

		JSONObject o = opMetadata != null ? opMetadata.toJSONObject() : null;
		setMetadata(EntityType.OPENID_PROVIDER, o);
	}
	
	
	/**
	 * Gets the OAuth 2.0 client metadata if present for this entity.
	 * Corresponds to the {@code metadata.oauth_client} claim.
	 *
	 * @return The client metadata, {@code null} if not specified or if
	 *         parsing failed.
	 */
	public ClientMetadata getOAuthClientMetadata() {
		
		JSONObject o = getMetadata(EntityType.OAUTH_CLIENT);
		
		if (o == null) {
			return null;
		}
		
		try {
			return ClientMetadata.parse(o);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Sets the OAuth 2.0 client metadata if present for this entity.
	 * Corresponds to the {@code metadata.oauth_client} claim.
	 *
	 * @param clientMetadata The client metadata, {@code null} if not
	 *                       specified.
	 */
	public void setOAuthClientMetadata(final ClientMetadata clientMetadata) {

		JSONObject o = clientMetadata != null ? clientMetadata.toJSONObject() : null;
		setMetadata(EntityType.OAUTH_CLIENT, o);
	}
	
	
	/**
	 * Gets the OAuth 2.0 authorisation server metadata if present for this
	 * entity. Corresponds to the
	 * {@code metadata.oauth_authorization_server} claim.
	 *
	 * @return The AS metadata, {@code null} if not specified or if parsing
	 * 	   failed.
	 */
	public AuthorizationServerMetadata getASMetadata() {
		
		JSONObject o = getMetadata(EntityType.OAUTH_AUTHORIZATION_SERVER);
		
		if (o == null) {
			return null;
		}
		
		try {
			return AuthorizationServerMetadata.parse(o);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Sets the OAuth 2.0 authorisation server metadata if present for this
	 * entity. Corresponds to the
	 * {@code metadata.oauth_authorization_server} claim.
	 *
	 * @param asMetadata The AS metadata, {@code null} if not specified.
	 */
	public void setASMetadata(final AuthorizationServerMetadata asMetadata) {

		JSONObject o = asMetadata != null ? asMetadata.toJSONObject() : null;
		setMetadata(EntityType.OAUTH_AUTHORIZATION_SERVER, o);
	}
	
	
	/**
	 * Gets the federation entity metadata if present for this entity.
	 * Corresponds to the {@code metadata.federation_entity} claim.
	 *
	 * @return The federation entity metadata, {@code null} if not
	 *         specified or if parsing failed.
	 */
	public FederationEntityMetadata getFederationEntityMetadata() {
		
		JSONObject o = getMetadata(EntityType.FEDERATION_ENTITY);
		
		if (o == null) {
			return null;
		}
		
		try {
			return FederationEntityMetadata.parse(o);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Sets the federation entity metadata if present for this entity.
	 * Corresponds to the {@code metadata.federation_entity} claim.
	 *
	 * @param entityMetadata The federation entity metadata, {@code null}
	 *                       if not specified.
	 */
	public void setFederationEntityMetadata(final FederationEntityMetadata entityMetadata) {

		JSONObject o = entityMetadata != null ? entityMetadata.toJSONObject() : null;
		setMetadata(EntityType.FEDERATION_ENTITY, o);
	}
	
	
	/**
	 * Gets the trust mark issuer metadata if present for this entity.
	 * Corresponds to the {@code metadata.trust_mark_issuer} claim.
	 *
	 * @return The trust mark issuer metadata, {@code null} if not
	 *         specified or if parsing failed.
	 */
	@Deprecated
	public TrustMarkIssuerMetadata getTrustMarkIssuerMetadata() {
		
		JSONObject o = getMetadata(EntityType.TRUST_MARK_ISSUER);
		
		if (o == null) {
			return null;
		}
		
		try {
			return TrustMarkIssuerMetadata.parse(o);
		} catch (ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Gets the trust marks. Corresponds to the {@code trust_marks} claim.
	 *
	 * @return The trust marks, {@code null} if not specified or parsing
	 *         failed.
	 */
	public List<TrustMarkEntry> getTrustMarks() {
		
		JSONArray array = getJSONArrayClaim(TRUST_MARKS_CLAIM_NAME);
		
		if (array == null) {
			return null;
		}
		
		List<JSONObject> jsonObjects;
		try {
			jsonObjects = JSONArrayUtils.toJSONObjectList(array);
		} catch (ParseException e) {
			return null;
		}
		
		List<TrustMarkEntry> marks = new LinkedList<>();
		
		for (JSONObject o: jsonObjects) {
			try {
				marks.add(TrustMarkEntry.parse(o));
			} catch (ParseException e) {
				return null;
			}
		}
		
		return marks;
	}
	
	
	/**
	 * Sets the trust marks. Corresponds to the {@code trust_marks} claim.
	 *
	 * @param marks The trust marks, {@code null} if not specified.
	 */
	public void setTrustMarks(final List<TrustMarkEntry> marks) {
		
		if (marks != null) {
			JSONArray array = new JSONArray();
			for (TrustMarkEntry en: marks) {
				array.add(en.toJSONObject());
			}
			setClaim(TRUST_MARKS_CLAIM_NAME, array);
		} else {
			setClaim(TRUST_MARKS_CLAIM_NAME, null);
		}
	}
}
