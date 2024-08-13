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

package com.nimbusds.openid.connect.sdk;


import java.util.*;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;


/**
 * Specifies the individual OpenID claims to return from the UserInfo endpoint
 * and / or in the ID Token.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
@Deprecated
public class ClaimsRequest implements JSONAware {
	
	
	/**
	 * Individual OpenID claim request.
	 *
	 * <p>Related specifications:
	 *
	 * <ul>
	 *     <li>OpenID Connect Core 1.0
	 *     <li>OpenID Connect for Identity Assurance 1.0
	 * </ul>
	 */
	@Immutable
	public static class Entry {
		
		
		/**
		 * The claim name.
		 */
		private final String claimName;
		
		
		/**
		 * The claim requirement.
		 */
		private final ClaimRequirement requirement;
		
		
		/**
		 * Optional language tag.
		 */
		private final LangTag langTag;
		
		
		/**
		 * Optional claim value.
		 */
		private final String value;
		
		
		/**
		 * Optional claim values.
		 */
		private final List<String> values;
		
		
		/**
		 * The claim purpose.
		 */
		private final String purpose;
		
		
		/**
		 * Optional additional claim information.
		 *
		 * <p>Example additional information in the "info" member:
		 *
		 * <pre>
		 * {
		 *   "userinfo" : {
		 *       "email": null,
		 *       "email_verified": null,
		 *       "http://example.info/claims/groups" : { "info" : "custom information" } }
		 * }
		 * </pre>
		 */
		private final Map<String, Object> additionalInformation;
		
		
		/**
		 * Creates a new individual claim request. The claim
                 * requirement is set to voluntary (the default) and no
                 * expected value(s) or other parameters are specified.
		 *
		 * @param claimName The claim name. Must not be {@code null}.
		 */
		public Entry(final String claimName) {
			
			this(claimName, ClaimRequirement.VOLUNTARY, null, null, null, null, null);
		}
		
		
		/**
		 * Creates a new individual claim request. The claim
                 * requirement is set to voluntary (the default) and no
                 * expected value(s) are specified.
		 *
		 * @param claimName The claim name. Must not be {@code null}.
		 * @param langTag   Optional language tag for the claim.
		 */
		@Deprecated
		public Entry(final String claimName, final LangTag langTag) {
			
			this(claimName, ClaimRequirement.VOLUNTARY, langTag, null, null);
		}
		
		
		/**
		 * Creates a new individual claim request.
		 *
		 * @param claimName   The claim name. Must not be {@code null}.
		 * @param requirement The claim requirement. Must not be
                 *                    {@code null}.
		 */
		@Deprecated
		public Entry(final String claimName, final ClaimRequirement requirement) {
			
			this(claimName, requirement, null, null, null);
		}
		
		
		/**
		 * Creates a new individual claim request.
		 *
		 * @param claimName   The claim name. Must not be {@code null}.
		 * @param requirement The claim requirement. Must not be
                 *                    {@code null}.
		 * @param langTag     Optional language tag for the claim.
		 * @param value       Optional expected value for the claim.
		 */
		@Deprecated
		public Entry(final String claimName, final ClaimRequirement requirement,
			     final LangTag langTag, final String value) {
			
			this(claimName, requirement, langTag, value, null);
		}
		
		
		/**
		 * Creates a new individual claim request.
		 *
		 * @param claimName   The claim name. Must not be {@code null}.
		 * @param requirement The claim requirement. Must not be
                 *                    {@code null}.
		 * @param langTag     Optional language tag for the claim.
		 * @param values      Optional expected values for the claim.
		 */
		@Deprecated
		public Entry(final String claimName, final ClaimRequirement requirement,
			     final LangTag langTag, final List<String> values) {
			
			this(claimName, requirement, langTag, null, values, null, null);
		}
		
		
		/**
		 * Creates a new individual claim request. This constructor is
		 * to be used privately. Ensures that {@code value} and
                 * {@code values} are not simultaneously specified.
		 *
		 * @param claimName   The claim name. Must not be {@code null}.
		 * @param requirement The claim requirement. Must not be
                 *                    {@code null}.
		 * @param langTag     Optional language tag for the claim.
		 * @param value       Optional expected value for the claim. If
		 *                    set, then the {@code values} parameter
		 *                    must not be set.
		 * @param values      Optional expected values for the claim.
                 *                    If set, then the {@code value} parameter
                 *                    must not be set.
		 */
		@Deprecated
		private Entry(final String claimName, final ClaimRequirement requirement, final LangTag langTag,
			      final String value, final List<String> values) {
			this(claimName, requirement, langTag, value, values, null, null);
		}
		
		
		/**
		 * Creates a new individual claim request. This constructor is
		 * to be used privately. Ensures that {@code value} and
                 * {@code values} are not simultaneously specified.
		 *
		 * @param claimName             The claim name. Must not be
		 *                              {@code null}.
		 * @param requirement           The claim requirement. Must not
		 *                              be {@code null}.
		 * @param langTag               Optional language tag for the
		 *                              claim.
		 * @param value                 Optional expected value for the
		 *                              claim. If set, then the {@code
		 *                              values} parameter must not be
		 *                              set.
		 * @param values                Optional expected values for
                 *                              the claim. If set, then the
                 *                              {@code value} parameter must
                 *                              not be set.
		 * @param purpose               The purpose for the requested
		 *                              claim, {@code null} if not
		 *                              specified.
		 * @param additionalInformation Optional additional information
		 */
		private Entry(final String claimName,
			      final ClaimRequirement requirement,
			      final LangTag langTag,
			      final String value,
			      final List<String> values,
			      final String purpose,
			      final Map<String, Object> additionalInformation) {
			
			if (claimName == null)
				throw new IllegalArgumentException("The claim name must not be null");
			
			this.claimName = claimName;
			
			
			if (requirement == null)
				throw new IllegalArgumentException("The claim requirement must not be null");
			
			this.requirement = requirement;
			
			
			this.langTag = langTag;
			
			
			if (value != null && values == null) {
				
				this.value = value;
				this.values = null;
				
			} else if (value == null && values != null) {
				
				this.value = null;
				this.values = values;
				
			} else if (value == null && values == null) {
				
				this.value = null;
				this.values = null;
				
			} else {
				
				throw new IllegalArgumentException("Either value or values must be specified, but not both");
			}
			
			this.purpose = purpose;
			
			this.additionalInformation = additionalInformation;
		}
		
		
		/**
		 * Returns the claim name.
		 *
		 * @return The claim name.
		 */
		public String getClaimName() {
			
			return claimName;
		}
		
		
		/**
		 * Returns the claim name, optionally with the language tag
		 * appended.
		 *
		 * <p>Example with language tag:
		 *
		 * <pre>
		 * name#de-DE
		 * </pre>
		 *
		 * @param withLangTag If {@code true} the language tag will be
		 *                    appended to the name (if any), else not.
                 *
		 * @return The claim name, with optionally appended language
		 *         tag.
		 */
		public String getClaimName(final boolean withLangTag) {
			
			if (withLangTag && langTag != null)
				return claimName + "#" + langTag;
			else
				return claimName;
		}
		
		
		/**
		 * Returns a new claim entry with the specified requirement.
		 *
		 * @param requirement The claim requirement.
		 *
		 * @return The new entry.
		 */
		public Entry withClaimRequirement(final ClaimRequirement requirement) {
			
			return new Entry(claimName, requirement, langTag, value, values, purpose, additionalInformation);
		}
		
		
		/**
		 * Returns the claim requirement.
		 *
		 * @return The claim requirement.
		 */
		public ClaimRequirement getClaimRequirement() {
			
			return requirement;
		}
		
		
		/**
		 * Returns a new claim entry with the specified language tag
		 * for the claim.
		 *
		 * @param langTag The language tag, {@code null} if not
		 *                specified.
		 *
		 * @return The new entry.
		 */
		public Entry withLangTag(final LangTag langTag) {
			
			return new Entry(claimName, requirement, langTag, value, values, purpose, additionalInformation);
		}
		
		
		/**
		 * Returns the optional language tag for the claim.
		 *
		 * @return The language tag, {@code null} if not specified.
		 */
		public LangTag getLangTag() {
			
			return langTag;
		}
		
		
		/**
		 * Returns a new claim entry with the specified requested value
		 * for the claim.
		 *
		 * @param value The value, {@code null} if not specified.
		 *
		 * @return The new entry.
		 */
		public Entry withValue(final String value) {
			
			return new Entry(claimName, requirement, langTag, value, null, purpose, additionalInformation);
		}
		
		
		/**
		 * Returns the requested value for the claim.
		 *
		 * @return The value, {@code null} if not specified.
		 */
		public String getValue() {
			
			return value;
		}
		
		
		/**
		 * Returns a new claim entry with the specified requested
		 * values for the claim.
		 *
		 * @param values The values, {@code null} if not specified.
		 *
		 * @return The new entry.
		 */
		public Entry withValues(final List<String> values) {
			
			return new Entry(claimName, requirement, langTag, null, values, purpose, additionalInformation);
		}
		
		
		/**
		 * Returns the optional values for the claim.
		 *
		 * @return The values, {@code null} if not specified.
		 */
		public List<String> getValues() {
			
			return values;
		}
		
		
		/**
		 * Returns a new claim entry with the specified purpose for the
		 * requested claim.
		 *
		 * @param purpose The purpose, {@code null} if not specified.
		 *
		 * @return The new entry.
		 */
		public Entry withPurpose(final String purpose) {
			
			return new Entry(claimName, requirement, langTag, value, values, purpose, additionalInformation);
		}
		
		
		/**
		 * Returns the optional purpose for the requested claim.
		 *
		 * @return The purpose, {@code null} if not specified.
		 */
		public String getPurpose() {
			
			return purpose;
		}
		
		
		/**
		 * Returns a new claim entry with the specified additional
		 * information for the claim.
		 *
		 * <p>Example additional information in the "info" member:
		 *
		 * <pre>
		 * {
		 *   "userinfo" : {
		 *       "email": null,
		 *       "email_verified": null,
		 *       "http://example.info/claims/groups" : { "info" : "custom information" } }
		 * }
		 * </pre>
		 *
		 * @param additionalInformation The additional information,
		 *                              {@code null} if not specified.
		 *
		 * @return The new entry.
		 */
		public Entry withAdditionalInformation(final Map<String, Object> additionalInformation) {
			
			return new Entry(claimName, requirement, langTag, value, values, purpose, additionalInformation);
		}
		
		
		/**
		 * Returns the additional information for the claim.
		 *
		 * <p>Example additional information in the "info" member:
		 *
		 * <pre>
		 * {
		 *   "userinfo" : {
		 *       "email": null,
		 *       "email_verified": null,
		 *       "http://example.info/claims/groups" : { "info" : "custom information" } }
		 * }
		 * </pre>
		 *
		 * @return The additional information, {@code null} if not
		 *         specified.
		 */
		public Map<String, Object> getAdditionalInformation() {
			return additionalInformation;
		}
		
		
		/**
		 * Returns the JSON object representation of the specified
		 * collection of individual claim requests.
		 *
		 * <p>Example:
		 *
		 * <pre>
		 * {
		 *   "given_name": {"essential": true},
		 *   "nickname": null,
		 *   "email": {"essential": true},
		 *   "email_verified": {"essential": true},
		 *   "picture": null,
		 *   "http://example.info/claims/groups": null
		 * }
		 * </pre>
		 *
		 * @param entries The entries to serialise. Must not be
                 *                {@code null}.
		 * @return The corresponding JSON object, empty if no claims
		 *         were found.
		 */
		public static JSONObject toJSONObject(final Collection<Entry> entries) {
			
			JSONObject o = new JSONObject();
			
			for (Entry entry : entries) {
				
				// Compose the optional value
				JSONObject entrySpec = null;
				
				if (entry.getValue() != null) {
					
					entrySpec = new JSONObject();
					entrySpec.put("value", entry.getValue());
				}
				
				if (entry.getValues() != null) {
					
					// Either "value" or "values", or none
					// may be defined
					entrySpec = new JSONObject();
					entrySpec.put("values", entry.getValues());
				}
				
				if (entry.getClaimRequirement().equals(ClaimRequirement.ESSENTIAL)) {
					
					if (entrySpec == null)
						entrySpec = new JSONObject();
					
					entrySpec.put("essential", true);
				}
				
				if (entry.getPurpose() != null) {
					if (entrySpec == null) {
						entrySpec = new JSONObject();
					}
					entrySpec.put("purpose", entry.getPurpose());
				}
				
				if (entry.getAdditionalInformation() != null) {
					if (entrySpec == null) {
						entrySpec = new JSONObject();
					}
					for (Map.Entry<String, Object> additionalInformationEntry : entry.getAdditionalInformation().entrySet()) {
						entrySpec.put(additionalInformationEntry.getKey(), additionalInformationEntry.getValue());
					}
				}
				
				o.put(entry.getClaimName(true), entrySpec);
			}
			
			return o;
		}
		
		
		/**
		 * Parses a collection of individual claim requests from the
		 * specified JSON object. Request entries that are not
		 * understood are silently ignored.
		 *
		 * @param jsonObject The JSON object to parse. Must not be
		 *                   {@code null}.
                 *
		 * @return The collection of claim requests.
		 */
		public static Collection<Entry> parseEntries(final JSONObject jsonObject) {
			
			Collection<Entry> entries = new LinkedList<>();
			
			if (jsonObject.isEmpty())
				return entries;
			
			for (Map.Entry<String, Object> member : jsonObject.entrySet()) {
				
				// Process the key
				String claimNameWithOptLangTag = member.getKey();
				
				String claimName;
				LangTag langTag = null;
				
				if (claimNameWithOptLangTag.contains("#")) {
					
					String[] parts = claimNameWithOptLangTag.split("#", 2);
					
					claimName = parts[0];
					
					try {
						langTag = LangTag.parse(parts[1]);
						
					} catch (LangTagException e) {
						
						// Ignore and continue
						continue;
					}
					
				} else {
					claimName = claimNameWithOptLangTag;
				}
				
				// Parse the optional value
				if (member.getValue() == null) {
					
					// Voluntary claim with no value(s)
					entries.add(new Entry(claimName, langTag));
					continue;
				}
				
				try {
					JSONObject entrySpec = (JSONObject) member.getValue();
					
					ClaimRequirement requirement = ClaimRequirement.VOLUNTARY;
					
					if (entrySpec.containsKey("essential")) {
						
						boolean isEssential = (Boolean) entrySpec.get("essential");
						
						if (isEssential)
							requirement = ClaimRequirement.ESSENTIAL;
					}
					
					String purpose = null;
					if (entrySpec.containsKey("purpose")) {
						purpose = (String) entrySpec.get("purpose");
					}
					
					if (entrySpec.containsKey("value")) {
						
						String expectedValue = (String) entrySpec.get("value");
						Map<String, Object> additionalInformation = getAdditionalInformationFromClaim(entrySpec);
						entries.add(new Entry(claimName, requirement, langTag, expectedValue, null, purpose, additionalInformation));
						
					} else if (entrySpec.containsKey("values")) {
						
						List<String> expectedValues = new LinkedList<>();
						
						for (Object v : (List) entrySpec.get("values")) {
							
							expectedValues.add((String) v);
						}
						Map<String, Object> additionalInformation = getAdditionalInformationFromClaim(entrySpec);
						
						entries.add(new Entry(claimName, requirement, langTag, null, expectedValues, purpose, additionalInformation));
						
					} else {
						Map<String, Object> additionalInformation = getAdditionalInformationFromClaim(entrySpec);
						entries.add(new Entry(claimName, requirement, langTag, null, null, purpose, additionalInformation));
					}
					
				} catch (Exception e) {
					// Ignore and continue
				}
			}
			
			return entries;
		}
		
		
		private static Map<String, Object> getAdditionalInformationFromClaim(final JSONObject entrySpec) {
			
			Set<String> stdKeys = new HashSet<>(Arrays.asList("essential", "value", "values", "purpose"));
			
			Map<String, Object> additionalClaimInformation = new HashMap<>();
			
			for (Map.Entry<String, Object> additionalClaimInformationEntry : entrySpec.entrySet()) {
				if (stdKeys.contains(additionalClaimInformationEntry.getKey())) {
					continue; // skip std key
				}
				additionalClaimInformation.put(additionalClaimInformationEntry.getKey(), additionalClaimInformationEntry.getValue());
			}
			
			return additionalClaimInformation.isEmpty() ? null : additionalClaimInformation;
		}
	}
	
	
	/**
	 * The requested ID token claims, keyed by claim name and language tag.
	 */
	private final Map<Map.Entry<String, LangTag>, Entry> idTokenClaims = new HashMap<>();
	
	
	/**
	 * The requested verified ID token claims, keyed by claim name and
	 * language tag.
	 */
	private final Map<Map.Entry<String, LangTag>, Entry> verifiedIDTokenClaims = new HashMap<>();
	
	
	/**
	 * The verification element for the requested verified ID token claims.
	 */
	private JSONObject idTokenClaimsVerification;
	
	
	/**
	 * The requested UserInfo claims, keyed by claim name and language tag.
	 */
	private final Map<Map.Entry<String, LangTag>, Entry> userInfoClaims = new HashMap<>();
	
	
	/**
	 * The requested verified UserInfo claims, keyed by claim name and
	 * language tag.
	 */
	private final Map<Map.Entry<String, LangTag>, Entry> verifiedUserInfoClaims = new HashMap<>();
	
	
	/**
	 * The verification element for the requested verified UserInfo claims.
	 */
	private JSONObject userInfoClaimsVerification;
	
	
	/**
	 * Creates a new empty claims request.
	 */
	public ClaimsRequest() {
		
		// Nothing to initialise
	}
	
	
	/**
	 * Adds the entries from the specified other claims request.
	 *
	 * @param other The other claims request. If {@code null} no claims
	 *              request entries will be added to this claims request.
	 */
	public void add(final ClaimsRequest other) {
		
		if (other == null)
			return;
		
		idTokenClaims.putAll(other.idTokenClaims);
		verifiedIDTokenClaims.putAll(other.verifiedIDTokenClaims);
		idTokenClaimsVerification = other.idTokenClaimsVerification;
		
		userInfoClaims.putAll(other.userInfoClaims);
		verifiedUserInfoClaims.putAll(other.verifiedUserInfoClaims);
		userInfoClaimsVerification = other.userInfoClaimsVerification;
	}
	
	
	/**
	 * Adds the specified ID token claim to the request. It is marked as
	 * voluntary and no language tag and value(s) are associated with it.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
	 */
	public void addIDTokenClaim(final String claimName) {
		
		addIDTokenClaim(claimName, ClaimRequirement.VOLUNTARY);
	}
	
	
	/**
	 * Adds the specified ID token claim to the request. No language tag
         * and value(s) are associated with it.
	 *
	 * @param claimName   The claim name. Must not be {@code null}.
	 * @param requirement The claim requirement. Must not be {@code null}.
	 */
	public void addIDTokenClaim(final String claimName, final ClaimRequirement requirement) {
		
		addIDTokenClaim(claimName, requirement, null);
	}
	
	
	/**
	 * Adds the specified ID token claim to the request. No value(s) are
	 * associated with it.
	 *
	 * @param claimName   The claim name. Must not be {@code null}.
	 * @param requirement The claim requirement. Must not be {@code null}.
	 * @param langTag     The associated language tag, {@code null} if not
	 *                    specified.
	 */
	public void addIDTokenClaim(final String claimName, final ClaimRequirement requirement,
				    final LangTag langTag) {
		
		addIDTokenClaim(claimName, requirement, langTag, (String) null);
	}
	
	
	/**
	 * Adds the specified ID token claim to the request.
	 *
	 * @param claimName   The claim name. Must not be {@code null}.
	 * @param requirement The claim requirement. Must not be {@code null}.
	 * @param langTag     The associated language tag, {@code null} if not
	 *                    specified.
	 * @param value       The expected claim value, {@code null} if not
	 *                    specified.
	 */
	public void addIDTokenClaim(final String claimName, final ClaimRequirement requirement,
				    final LangTag langTag, final String value) {
		
		addIDTokenClaim(new Entry(claimName, requirement, langTag, value));
	}
	
	
	/**
	 * Adds the specified ID token claim to the request.
	 *
	 * @param claimName             The claim name. Must not be
         *                              {@code null}.
	 * @param requirement           The claim requirement. Must not be
	 *                              {@code null}.
	 * @param langTag               The associated language tag,
         *                              {@code null} if not specified.
	 * @param value                 The expected claim value, {@code null}
	 *                              if not specified.
	 * @param additionalInformation The additional information for this
	 *                              claim, {@code null} if not specified.
	 */
	public void addIDTokenClaim(final String claimName, final ClaimRequirement requirement,
				    final LangTag langTag, final String value, final Map<String, Object> additionalInformation) {
		
		addIDTokenClaim(new Entry(claimName, requirement, langTag, value, null, null, additionalInformation));
	}
	
	
	/**
	 * Adds the specified ID token claim to the request.
	 *
	 * @param claimName   The claim name. Must not be {@code null}.
	 * @param requirement The claim requirement. Must not be {@code null}.
	 * @param langTag     The associated language tag, {@code null} if not
	 *                    specified.
	 * @param values      The expected claim values, {@code null} if not
	 *                    specified.
	 */
	public void addIDTokenClaim(final String claimName, final ClaimRequirement requirement,
				    final LangTag langTag, final List<String> values) {
		
		addIDTokenClaim(new Entry(claimName, requirement, langTag, values));
	}
	
	
	/**
	 * Adds the specified ID token claim to the request.
	 *
	 * @param claimName             The claim name. Must not be
         *                              {@code null}.
	 * @param requirement           The claim requirement. Must not be
	 *                              {@code null}.
	 * @param langTag               The associated language tag,
         *                              {@code null} if not specified.
	 * @param values                The expected claim values, {@code null}
	 *                              if not specified.
	 * @param additionalInformation The additional information for this
	 *                              claim, {@code null} if not specified.
	 */
	public void addIDTokenClaim(final String claimName, final ClaimRequirement requirement,
				    final LangTag langTag, final List<String> values, final Map<String, Object> additionalInformation) {
		
		addIDTokenClaim(new Entry(claimName, requirement, langTag, null, values, null, additionalInformation));
	}
	
	
	private static Map.Entry<String, LangTag> toKey(final Entry entry) {
		
		return new AbstractMap.SimpleImmutableEntry<>(
			entry.getClaimName(),
			entry.getLangTag());
	}
	
	
	/**
	 * Adds the specified ID token claim to the request.
	 *
	 * @param entry The individual ID token claim request. Must not be
	 *              {@code null}.
	 */
	public void addIDTokenClaim(final Entry entry) {
		
		idTokenClaims.put(toKey(entry), entry);
	}
	
	
	/**
	 * Adds the specified verified ID token claim to the request.
	 *
	 * @param entry The individual verified ID token claim request. Must
	 *              not be {@code null}.
	 */
	public void addVerifiedIDTokenClaim(final Entry entry) {
		
		verifiedIDTokenClaims.put(toKey(entry), entry);
	}
	
	
	/**
	 * Sets the {@code verification} element for the requested verified ID
	 * token claims.
	 *
	 * @param jsonObject The {@code verification} JSON object, {@code null}
	 *                   if not specified.
	 */
	public void setIDTokenClaimsVerificationJSONObject(final JSONObject jsonObject) {
		
		this.idTokenClaimsVerification = jsonObject;
	}
	
	
	/**
	 * Gets the {@code verification} element for the requested verified ID
	 * token claims.
	 *
	 * @return The {@code verification} JSON object, {@code null} if not
	 *         specified.
	 */
	public JSONObject getIDTokenClaimsVerificationJSONObject() {
		
		return idTokenClaimsVerification;
	}
	
	
	/**
	 * Gets the requested ID token claims.
	 *
	 * @return The ID token claims, as an unmodifiable collection, empty
	 *         set if none.
	 */
	public Collection<Entry> getIDTokenClaims() {
		
		return Collections.unmodifiableCollection(idTokenClaims.values());
	}
	
	
	/**
	 * Gets the requested verified ID token claims.
	 *
	 * @return The verified ID token claims, as an unmodifiable collection,
	 *         empty set if none.
	 */
	public Collection<Entry> getVerifiedIDTokenClaims() {
		
		return Collections.unmodifiableCollection(verifiedIDTokenClaims.values());
	}
	
	
	private static Set<String> getClaimNames(final Map<Map.Entry<String, LangTag>, Entry> claims, final boolean withLangTag) {
		
		Set<String> names = new HashSet<>();
		
		for (Entry en : claims.values())
			names.add(en.getClaimName(withLangTag));
		
		return Collections.unmodifiableSet(names);
	}
	
	
	/**
	 * Gets the names of the requested ID token claim names.
	 *
	 * @param withLangTag If {@code true} the language tags, if any, will
	 *                    be appended to the names, else not.
         *
	 * @return The ID token claim names, as an unmodifiable set, empty set
	 *         if none.
	 */
	public Set<String> getIDTokenClaimNames(final boolean withLangTag) {
		
		return getClaimNames(idTokenClaims, withLangTag);
	}
	
	
	/**
	 * Gets the names of the requested verified ID token claim names.
	 *
	 * @param withLangTag If {@code true} the language tags, if any, will
	 *                    be appended to the names, else not.
         *
	 * @return The ID token claim names, as an unmodifiable set, empty set
	 *         if none.
	 */
	public Set<String> getVerifiedIDTokenClaimNames(final boolean withLangTag) {
		
		return getClaimNames(verifiedIDTokenClaims, withLangTag);
	}
	
	
	private static Map.Entry<String, LangTag> toKey(final String claimName, final LangTag langTag) {
		
		return new AbstractMap.SimpleImmutableEntry<>(claimName, langTag);
	}
	
	
	/**
	 * Removes the specified ID token claim from the request.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
	 * @param langTag   The associated language tag, {@code null} if none.
         *
	 * @return The removed ID token claim, {@code null} if not found.
	 */
	public Entry removeIDTokenClaim(final String claimName, final LangTag langTag) {
		
		return idTokenClaims.remove(toKey(claimName, langTag));
	}
	
	
	/**
	 * Removes the specified verified ID token claim from the request.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
	 * @param langTag   The associated language tag, {@code null} if none.
         *
	 * @return The removed ID token claim, {@code null} if not found.
	 */
	public Entry removeVerifiedIDTokenClaim(final String claimName, final LangTag langTag) {
		
		return verifiedIDTokenClaims.remove(toKey(claimName, langTag));
	}
	
	
	private static Collection<Entry> removeClaims(final Map<Map.Entry<String, LangTag>, Entry> claims, final String claimName) {
		
		Collection<Entry> removedClaims = new LinkedList<>();
		
		Iterator<Map.Entry<Map.Entry<String, LangTag>, Entry>> it = claims.entrySet().iterator();
		
		while (it.hasNext()) {
			
			Map.Entry<Map.Entry<String, LangTag>, Entry> reqEntry = it.next();
			
			if (reqEntry.getKey().getKey().equals(claimName)) {
				
				removedClaims.add(reqEntry.getValue());
				
				it.remove();
			}
		}
		
		return Collections.unmodifiableCollection(removedClaims);
	}
	
	
	/**
	 * Removes the specified ID token claims from the request, in all
	 * existing language tag variations.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
         *
	 * @return The removed ID token claims, as an unmodifiable collection,
	 *         empty set if none were found.
	 */
	public Collection<Entry> removeIDTokenClaims(final String claimName) {
		
		return removeClaims(idTokenClaims, claimName);
	}
	
	
	/**
	 * Removes the specified verified ID token claims from the request, in
	 * all existing language tag variations.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
         *
	 * @return The removed ID token claims, as an unmodifiable collection,
	 *         empty set if none were found.
	 */
	public Collection<Entry> removeVerifiedIDTokenClaims(final String claimName) {
		
		return removeClaims(verifiedIDTokenClaims, claimName);
	}
	
	
	/**
	 * Adds the specified UserInfo claim to the request. It is marked as
	 * voluntary and no language tag and value(s) are associated with it.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
	 */
	public void addUserInfoClaim(final String claimName) {
		
		addUserInfoClaim(claimName, ClaimRequirement.VOLUNTARY);
	}
	
	
	/**
	 * Adds the specified UserInfo claim to the request. No language tag and
	 * value(s) are associated with it.
	 *
	 * @param claimName   The claim name. Must not be {@code null}.
	 * @param requirement The claim requirement. Must not be {@code null}.
	 */
	public void addUserInfoClaim(final String claimName, final ClaimRequirement requirement) {
		
		addUserInfoClaim(claimName, requirement, null);
	}
	
	
	/**
	 * Adds the specified UserInfo claim to the request. No value(s) are
	 * associated with it.
	 *
	 * @param claimName   The claim name. Must not be {@code null}.
	 * @param requirement The claim requirement. Must not be {@code null}.
	 * @param langTag     The associated language tag, {@code null} if not
	 *                    specified.
	 */
	public void addUserInfoClaim(final String claimName, final ClaimRequirement requirement,
				     final LangTag langTag) {
		
		
		addUserInfoClaim(claimName, requirement, langTag, (String) null);
	}
	
	
	/**
	 * Adds the specified UserInfo claim to the request.
	 *
	 * @param claimName   The claim name. Must not be {@code null}.
	 * @param requirement The claim requirement. Must not be {@code null}.
	 * @param langTag     The associated language tag, {@code null} if not
	 *                    specified.
	 * @param value       The expected claim value, {@code null} if not
	 *                    specified.
	 */
	public void addUserInfoClaim(final String claimName, final ClaimRequirement requirement,
				     final LangTag langTag, final String value) {
		
		addUserInfoClaim(new Entry(claimName, requirement, langTag, value));
	}
	
	
	/**
	 * Adds the specified UserInfo claim to the request.
	 *
	 * @param claimName             The claim name. Must not be {@code
	 *                              null}.
	 * @param requirement           The claim requirement. Must not be
	 *                              {@code null}.
	 * @param langTag               The associated language tag, {@code
	 *                              null} if not specified.
	 * @param value                 The expected claim value, {@code null}
	 *                              if not specified.
	 * @param additionalInformation The additional information for this
	 *                              claim, {@code null} if not specified.
	 */
	public void addUserInfoClaim(final String claimName, final ClaimRequirement requirement,
				     final LangTag langTag, final String value, final Map<String, Object> additionalInformation) {
		
		addUserInfoClaim(new Entry(claimName, requirement, langTag, value, null, null, additionalInformation));
	}
	
	
	/**
	 * Adds the specified UserInfo claim to the request.
	 *
	 * @param claimName   The claim name. Must not be {@code null}.
	 * @param requirement The claim requirement. Must not be {@code null}.
	 * @param langTag     The associated language tag, {@code null} if not
	 *                    specified.
	 * @param values      The expected claim values, {@code null} if not
	 *                    specified.
	 */
	public void addUserInfoClaim(final String claimName, final ClaimRequirement requirement,
				     final LangTag langTag, final List<String> values) {
		
		addUserInfoClaim(new Entry(claimName, requirement, langTag, values));
	}
	
	
	/**
	 * Adds the specified UserInfo claim to the request.
	 *
	 * @param claimName             The claim name. Must not be
         *                              {@code null}.
	 * @param requirement           The claim requirement. Must not be
	 *                              {@code null}.
	 * @param langTag               The associated language tag,
         *                              {@code null} if not specified.
	 * @param values                The expected claim values, {@code null}
	 *                              if not specified.
	 * @param additionalInformation The additional information for this
	 *                              claim, {@code null} if not specified.
	 */
	public void addUserInfoClaim(final String claimName, final ClaimRequirement requirement,
				     final LangTag langTag, final List<String> values, final Map<String, Object> additionalInformation) {
		
		addUserInfoClaim(new Entry(claimName, requirement, langTag, null, values, null, additionalInformation));
	}
	
	
	/**
	 * Adds the specified UserInfo claim to the request.
	 *
	 * @param entry The individual UserInfo claim request. Must not be
	 *              {@code null}.
	 */
	public void addUserInfoClaim(final Entry entry) {
		
		userInfoClaims.put(toKey(entry), entry);
	}
	
	
	/**
	 * Adds the specified verified UserInfo claim to the request.
	 *
	 * @param entry The individual verified UserInfo claim request. Must
	 *              not be {@code null}.
	 */
	public void addVerifiedUserInfoClaim(final Entry entry) {
		
		verifiedUserInfoClaims.put(toKey(entry), entry);
	}
	
	
	/**
	 * Sets the {@code verification} element for the requested verified
	 * UserInfo claims.
	 *
	 * @param jsonObject The {@code verification} JSON object, {@code null}
	 *                   if not specified.
	 */
	public void setUserInfoClaimsVerificationJSONObject(final JSONObject jsonObject) {
		
		this.userInfoClaimsVerification = jsonObject;
	}
	
	
	/**
	 * Gets the {@code verification} element for the requested verified
	 * UserInfo claims.
	 *
	 * @return The {@code verification} JSON object, {@code null} if not
	 *         specified.
	 */
	public JSONObject getUserInfoClaimsVerificationJSONObject() {
		
		return userInfoClaimsVerification;
	}
	
	
	/**
	 * Gets the requested UserInfo claims.
	 *
	 * @return The UserInfo claims, as an unmodifiable collection, empty
	 *         set if none.
	 */
	public Collection<Entry> getUserInfoClaims() {
		
		return Collections.unmodifiableCollection(userInfoClaims.values());
	}
	
	
	/**
	 * Gets the requested verified UserInfo claims.
	 *
	 * @return The UserInfo claims, as an unmodifiable collection, empty
	 *         set if none.
	 */
	public Collection<Entry> getVerifiedUserInfoClaims() {
		
		return Collections.unmodifiableCollection(verifiedUserInfoClaims.values());
	}
	
	
	/**
	 * Gets the names of the requested UserInfo claim names.
	 *
	 * @param withLangTag If {@code true} the language tags, if any, will
	 *                    be appended to the names, else not.
         *
	 * @return The UserInfo claim names, as an unmodifiable set, empty set
	 *         if none.
	 */
	public Set<String> getUserInfoClaimNames(final boolean withLangTag) {
		
		return getClaimNames(userInfoClaims, withLangTag);
	}
	
	
	/**
	 * Gets the names of the requested verified UserInfo claim names.
	 *
	 * @param withLangTag If {@code true} the language tags, if any, will
	 *                    be appended to the names, else not.
         *
	 * @return The UserInfo claim names, as an unmodifiable set, empty set
	 *         if none.
	 */
	public Set<String> getVerifiedUserInfoClaimNames(final boolean withLangTag) {
		
		return getClaimNames(verifiedUserInfoClaims, withLangTag);
	}
	
	
	/**
	 * Removes the specified UserInfo claim from the request.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
	 * @param langTag   The associated language tag, {@code null} if none.
         *
	 * @return The removed UserInfo claim, {@code null} if not found.
	 */
	public Entry removeUserInfoClaim(final String claimName, final LangTag langTag) {
		
		return userInfoClaims.remove(toKey(claimName, langTag));
	}
	
	
	/**
	 * Removes the specified verified UserInfo claim from the request.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
	 * @param langTag   The associated language tag, {@code null} if none.
         *
	 * @return The removed UserInfo claim, {@code null} if not found.
	 */
	public Entry removeVerifiedUserInfoClaim(final String claimName, final LangTag langTag) {
		
		return verifiedUserInfoClaims.remove(toKey(claimName, langTag));
	}
	
	
	/**
	 * Removes the specified UserInfo claims from the request, in all
	 * existing language tag variations.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
         *
	 * @return The removed UserInfo claims, as an unmodifiable collection,
	 *         empty set if none were found.
	 */
	public Collection<Entry> removeUserInfoClaims(final String claimName) {
		
		return removeClaims(userInfoClaims, claimName);
	}
	
	
	/**
	 * Removes the specified verified UserInfo claims from the request, in
	 * all existing language tag variations.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
         *
	 * @return The removed UserInfo claims, as an unmodifiable collection,
	 *         empty set if none were found.
	 */
	public Collection<Entry> removeVerifiedUserInfoClaims(final String claimName) {
		
		return removeClaims(verifiedUserInfoClaims, claimName);
	}
	
	
	/**
	 * Returns the JSON object representation of this claims request.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * {
	 *   "userinfo":
	 *    {
	 *     "given_name": {"essential": true},
	 *     "nickname": null,
	 *     "email": {"essential": true},
	 *     "email_verified": {"essential": true},
	 *     "picture": null,
	 *     "http://example.info/claims/groups": null
	 *    },
	 *   "id_token":
	 *    {
	 *     "auth_time": {"essential": true},
	 *     "acr": {"values": ["urn:mace:incommon:iap:silver"] }
	 *    }
	 * }
	 * </pre>
	 *
	 * @return The corresponding JSON object, empty if no ID token and
	 *         UserInfo claims are specified.
	 */
	public JSONObject toJSONObject() {
		
		JSONObject o = new JSONObject();
		
		if (! getIDTokenClaims().isEmpty()) {
			
			o.put("id_token", Entry.toJSONObject(getIDTokenClaims()));
		}
		
		if (! getVerifiedIDTokenClaims().isEmpty()) {
			
			JSONObject idTokenObject;
			if (o.get("id_token") != null) {
				idTokenObject = (JSONObject) o.get("id_token");
			} else {
				idTokenObject = new JSONObject();
			}
			
			JSONObject verifiedClaims = new JSONObject();
			
			verifiedClaims.put("claims", Entry.toJSONObject(getVerifiedIDTokenClaims()));
			
			if (getIDTokenClaimsVerificationJSONObject() != null) {
				verifiedClaims.put("verification", getIDTokenClaimsVerificationJSONObject());
			}
			
			idTokenObject.put("verified_claims", verifiedClaims);
			o.put("id_token", idTokenObject);
		}
		
		if (! getUserInfoClaims().isEmpty()) {
			
			o.put("userinfo", Entry.toJSONObject(getUserInfoClaims()));
		}
		
		if (! getVerifiedUserInfoClaims().isEmpty()) {
			
			JSONObject userInfoObject;
			if (o.get("userinfo") != null) {
				userInfoObject = (JSONObject) o.get("userinfo");
			} else {
				userInfoObject = new JSONObject();
			}
			
			JSONObject verifiedClaims = new JSONObject();
			
			verifiedClaims.put("claims", Entry.toJSONObject(getVerifiedUserInfoClaims()));
			
			if (getUserInfoClaimsVerificationJSONObject() != null) {
				verifiedClaims.put("verification", getUserInfoClaimsVerificationJSONObject());
			}
			
			userInfoObject.put("verified_claims", verifiedClaims);
			o.put("userinfo", userInfoObject);
		}
		
		return o;
	}
	
	
	@Override
	public String toJSONString() {
		return toJSONObject().toJSONString();
	}
	
	
	@Override
	public String toString() {
		
		return toJSONString();
	}
	
	
	/**
	 * Resolves the claims request for the specified response type and
	 * scope. The scope values that are {@link OIDCScopeValue standard
	 * OpenID scope values} are resolved to their respective individual
	 * claims requests, any other scope values are ignored.
	 *
	 * @param responseType The response type. Must not be {@code null}.
	 * @param scope        The scope, {@code null} if not specified (for a
	 *                     plain OAuth 2.0 authorisation request with no
	 *                     scope explicitly specified).
         *
	 * @return The claims request.
	 */
	public static ClaimsRequest resolve(final ResponseType responseType, final Scope scope) {
		
		return resolve(responseType, scope, Collections.<Scope.Value, Set<String>>emptyMap());
	}
	
	
	/**
	 * Resolves the claims request for the specified response type and
	 * scope. The scope values that are {@link OIDCScopeValue standard
	 * OpenID scope values} are resolved to their respective individual
	 * claims requests, any other scope values are checked in the specified
	 * custom claims map and resolved accordingly.
	 *
	 * @param responseType The response type. Must not be {@code null}.
	 * @param scope        The scope, {@code null} if not specified (for a
	 *                     plain OAuth 2.0 authorisation request with no
	 *                     scope explicitly specified).
	 * @param customClaims Custom scope value to set of claim names map,
	 *                     {@code null} if not specified.
         *
	 * @return The claims request.
	 */
	public static ClaimsRequest resolve(final ResponseType responseType,
					    final Scope scope,
					    final Map<Scope.Value, Set<String>> customClaims) {
		
		// Determine the claims target (ID token or UserInfo)
		final boolean switchToIDToken =
			responseType.contains(OIDCResponseTypeValue.ID_TOKEN) &&
				!responseType.contains(ResponseType.Value.CODE) &&
				!responseType.contains(ResponseType.Value.TOKEN);
		
		ClaimsRequest claimsRequest = new ClaimsRequest();
		
		if (scope == null) {
			// Plain OAuth 2.0 mode
			return claimsRequest;
		}
		
		for (Scope.Value value : scope) {
			
			Set<ClaimsRequest.Entry> entries;
			
			if (value.equals(OIDCScopeValue.PROFILE)) {
				
				entries = OIDCScopeValue.PROFILE.toClaimsRequestEntries();
				
			} else if (value.equals(OIDCScopeValue.EMAIL)) {
				
				entries = OIDCScopeValue.EMAIL.toClaimsRequestEntries();
				
			} else if (value.equals(OIDCScopeValue.PHONE)) {
				
				entries = OIDCScopeValue.PHONE.toClaimsRequestEntries();
				
			} else if (value.equals(OIDCScopeValue.ADDRESS)) {
				
				entries = OIDCScopeValue.ADDRESS.toClaimsRequestEntries();
				
			} else if (customClaims != null && customClaims.containsKey(value)) {
				
				// Process custom scope value -> claim names expansion, e.g.
				// "corp_profile" -> ["employeeNumber", "dept", "ext"]
				Set<String> claimNames = customClaims.get(value);
				
				if (claimNames == null || claimNames.isEmpty()) {
					continue; // skip
				}
				
				entries = new HashSet<>();
				
				for (String claimName: claimNames) {
					entries.add(new ClaimsRequest.Entry(claimName, ClaimRequirement.VOLUNTARY));
				}
				
			} else {
				
				continue; // skip
			}
			
			for (ClaimsRequest.Entry en : entries) {
				
				if (switchToIDToken)
					claimsRequest.addIDTokenClaim(en);
				else
					claimsRequest.addUserInfoClaim(en);
			}
		}
		
		return claimsRequest;
	}
	
	
	/**
	 * Resolves the merged claims request from the specified OpenID
	 * authentication request parameters. The scope values that are {@link
	 * OIDCScopeValue standard OpenID scope values} are resolved to their
	 * respective individual claims requests, any other scope values are
	 * ignored.
	 *
	 * @param responseType  The response type. Must not be {@code null}.
	 * @param scope         The scope, {@code null} if not specified (for a
	 *                      plain OAuth 2.0 authorisation request with no
	 *                      scope explicitly specified).
	 * @param claimsRequest The claims request, corresponding to the
	 *                      optional {@code claims} OpenID Connect
	 *                      authorisation request parameter, {@code null}
	 *                      if not specified.
         *
	 * @return The merged claims request.
	 */
	public static ClaimsRequest resolve(final ResponseType responseType,
					    final Scope scope,
					    final ClaimsRequest claimsRequest) {
		
		return resolve(responseType, scope, claimsRequest, Collections.<Scope.Value, Set<String>>emptyMap());
	}
	
	
	/**
	 * Resolves the merged claims request from the specified OpenID
	 * authentication request parameters. The scope values that are {@link
	 * OIDCScopeValue standard OpenID scope values} are resolved to their
	 * respective individual claims requests, any other scope values are
	 * checked in the specified custom claims map and resolved accordingly.
	 *
	 * @param responseType  The response type. Must not be {@code null}.
	 * @param scope         The scope, {@code null} if not specified (for a
	 *                      plain OAuth 2.0 authorisation request with no
	 *                      scope explicitly specified).
	 * @param claimsRequest The claims request, corresponding to the
	 *                      optional {@code claims} OpenID Connect
	 *                      authorisation request parameter, {@code null}
	 *                      if not specified.
	 * @param customClaims  Custom scope value to set of claim names map,
	 *                      {@code null} if not specified.
         *
	 * @return The merged claims request.
	 */
	public static ClaimsRequest resolve(final ResponseType responseType,
					    final Scope scope,
					    final ClaimsRequest claimsRequest,
					    final Map<Scope.Value, Set<String>> customClaims) {
		
		ClaimsRequest mergedClaimsRequest = resolve(responseType, scope, customClaims);
		
		mergedClaimsRequest.add(claimsRequest);
		
		return mergedClaimsRequest;
	}
	
	
	/**
	 * Resolves the merged claims request for the specified OpenID
	 * authentication request. The scope values that are {@link
	 * OIDCScopeValue standard OpenID scope values} are resolved to their
	 * respective individual claims requests, any other scope values are
	 * ignored.
	 *
	 * @param authRequest The OpenID authentication request. Must not be
	 *                    {@code null}.
         *
	 * @return The merged claims request.
	 */
	public static ClaimsRequest resolve(final AuthenticationRequest authRequest) {
		
		return resolve(authRequest.getResponseType(), authRequest.getScope(), authRequest.getClaims());
	}
	
	
	private static JSONObject parseFirstVerifiedClaimsObject(final JSONObject containingObject)
		throws ParseException {
		
		if (containingObject.get("verified_claims") instanceof JSONObject) {
			// JSON object is the simple case
			return JSONObjectUtils.getJSONObject(containingObject, "verified_claims");
		}
		
		if (containingObject.get("verified_claims") instanceof JSONArray) {
			// Try JSON array, take first element, ignore rest (use new OIDCClaimsRequest class to handle this case)
			List<JSONObject> elements = JSONArrayUtils.toJSONObjectList(JSONObjectUtils.getJSONArray(containingObject, "verified_claims"));
			if (elements.size() > 0) {
				return elements.get(0);
			}
		}
		
		return null;
	}
	
	
	/**
	 * Parses a claims request from the specified JSON object
	 * representation. Unexpected members in the JSON object are silently
	 * ignored.
	 *
	 * @param jsonObject The JSON object to parse. Must not be
         *                   {@code null}.
         *
	 * @return The claims request.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ClaimsRequest parse(final JSONObject jsonObject)
		throws ParseException {
		
		ClaimsRequest claimsRequest = new ClaimsRequest();
		
		try {
			JSONObject idTokenObject = JSONObjectUtils.getJSONObject(jsonObject, "id_token", null);
			
			if (idTokenObject != null) {
				
				for (Entry entry : Entry.parseEntries(idTokenObject)) {
					if ("verified_claims".equals(entry.getClaimName())) {
						continue; //skip
					}
					claimsRequest.addIDTokenClaim(entry);
				}
				
				JSONObject verifiedClaimsObject = parseFirstVerifiedClaimsObject(idTokenObject);
				
				if (verifiedClaimsObject != null) {
					// id_token -> verified_claims -> claims
					JSONObject claimsObject = JSONObjectUtils.getJSONObject(verifiedClaimsObject, "claims", null);
					if (claimsObject != null) {
						
						if (claimsObject.isEmpty()) {
							String msg = "Invalid claims object: Empty verification claims object";
							throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
						}
						
						for (Entry entry : Entry.parseEntries(claimsObject)) {
							claimsRequest.addVerifiedIDTokenClaim(entry);
						}
					}
					// id_token -> verified_claims -> verification
					claimsRequest.setIDTokenClaimsVerificationJSONObject(JSONObjectUtils.getJSONObject(verifiedClaimsObject, "verification", null));
				}
			}
			
			JSONObject userInfoObject = JSONObjectUtils.getJSONObject(jsonObject, "userinfo", null);
			
			if (userInfoObject != null) {
				
				for (Entry entry : Entry.parseEntries(userInfoObject)) {
					if ("verified_claims".equals(entry.getClaimName())) {
						continue; //skip
					}
					claimsRequest.addUserInfoClaim(entry);
				}
				
				JSONObject verifiedClaimsObject = parseFirstVerifiedClaimsObject(userInfoObject);
				
				if (verifiedClaimsObject != null) {
					// userinfo -> verified_claims -> claims
					JSONObject claimsObject = JSONObjectUtils.getJSONObject(verifiedClaimsObject, "claims", null);
					
					if (claimsObject != null) {
						
						if (claimsObject.isEmpty()) {
							String msg = "Invalid claims object: Empty verification claims object";
							throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
						}
						
						for (Entry entry : Entry.parseEntries(claimsObject)) {
							claimsRequest.addVerifiedUserInfoClaim(entry);
						}
					}
					// userinfo -> verified_claims -> verification
					claimsRequest.setUserInfoClaimsVerificationJSONObject(JSONObjectUtils.getJSONObject(verifiedClaimsObject, "verification", null));
				}
			}
			
		} catch (Exception e) {
			
			if (e instanceof ParseException) {
				throw e;
			}
		}
		
		return claimsRequest;
	}
	
	
	/**
	 * Parses a claims request from the specified JSON object string
	 * representation. Unexpected members in the JSON object are silently
	 * ignored.
	 *
	 * @param json The JSON object string to parse. Must not be
         *             {@code null}.
         *
	 * @return The claims request.
         *
	 * @throws ParseException If the string couldn't be parsed to a valid
	 *                        JSON object.
	 */
	public static ClaimsRequest parse(final String json)
		throws ParseException {
		
		return parse(JSONObjectUtils.parse(json));
	}
}
