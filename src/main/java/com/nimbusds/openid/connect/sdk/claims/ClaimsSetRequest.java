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

package com.nimbusds.openid.connect.sdk.claims;


import java.util.*;

import net.jcip.annotations.Immutable;
import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


/**
 * OpenID Connect claims set request, intended to represent the
 * {@code userinfo} and {@code id_token} elements in a
 * {@link com.nimbusds.openid.connect.sdk.OIDCClaimsRequest claims} request
 * parameter.
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
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
@Immutable
public class ClaimsSetRequest implements JSONAware {
	
	
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
		 * Optional claim value, as string, number or JSON object.
		 */
		private final Object value;
		
		
		/**
		 * Optional claim values, as an array of JSON entities.
		 */
		private final List<?> values;
		
		
		/**
		 * Optional claim purpose.
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
		 *       "http://example.info/claims/groups" : { "info" : "custom information" }
		 *   }
		 * }
		 * </pre>
		 */
		private final Map<String, Object> additionalInformation;
		
		
		/**
		 * Creates a new individual claim request. The claim
		 * requirement is set to {@link ClaimRequirement#VOLUNTARY
		 * voluntary} (the default) and no expected value(s) or other
		 * parameters are specified.
		 *
		 * @param claimName The claim name. Must not be {@code null}.
		 */
		public Entry(final String claimName) {
			this(claimName, ClaimRequirement.VOLUNTARY, null, null, null, null, null);
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
			      final Object value,
			      final List<?> values,
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
			return getClaimName(false);
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
		 * Sets the claim requirement.
		 *
		 * @param requirement The claim requirement. Must not be
		 *                    {@code null},
		 *
		 * @return The updated entry.
		 */
		public ClaimsSetRequest.Entry withClaimRequirement(final ClaimRequirement requirement) {
			return new ClaimsSetRequest.Entry(claimName, requirement, langTag, value, values, purpose, additionalInformation);
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
		 * Sets the language tag for the claim.
		 *
		 * @param langTag The language tag, {@code null} if not
		 *                specified.
		 *
		 * @return The updated entry.
		 */
		public ClaimsSetRequest.Entry withLangTag(final LangTag langTag) {
			return new ClaimsSetRequest.Entry(claimName, requirement, langTag, value, values, purpose, additionalInformation);
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
		 * Sets the requested value (as string) for the claim.
		 *
		 * @param value The value, {@code null} if not specified.
		 *
		 * @return The updated entry.
		 */
		public ClaimsSetRequest.Entry withValue(final String value) {
			return new ClaimsSetRequest.Entry(claimName, requirement, langTag, value, null, purpose, additionalInformation);
		}
		
		
		/**
		 * Sets the requested value (as number) for the claim.
		 *
		 * @param value The value, {@code null} if not specified.
		 *
		 * @return The updated entry.
		 */
		public ClaimsSetRequest.Entry withValue(final Number value) {
			return new ClaimsSetRequest.Entry(claimName, requirement, langTag, value, null, purpose, additionalInformation);
		}
		
		
		/**
		 * Sets the requested value (as JSON object) for the claim.
		 *
		 * @param value The value, {@code null} if not specified.
		 *
		 * @return The updated entry.
		 */
		public ClaimsSetRequest.Entry withValue(final JSONObject value) {
			return new ClaimsSetRequest.Entry(claimName, requirement, langTag, value, null, purpose, additionalInformation);
		}
		
		
		/**
		 * Sets the requested value (untyped) for the claim.
		 *
		 * @param value The value, {@code null} if not specified.
		 *
		 * @return The updated entry.
		 */
		public ClaimsSetRequest.Entry withValue(final Object value) {
			return new ClaimsSetRequest.Entry(claimName, requirement, langTag, value, null, purpose, additionalInformation);
		}
		
		
		/**
		 * Returns the requested value (as string) for the claim.
		 *
		 * @return The value as string, {@code null} if not specified
		 *         or the value isn't a string.
		 */
		public String getValueAsString() {
			if (value instanceof String) {
				return (String)value;
			} else {
				return null;
			}
		}
		
		
		/**
		 * Returns the requested value (as string) for the claim. Use
		 * {@link #getValueAsString()} instead.
		 *
		 * @return The value as string, {@code null} if not specified
		 *         or the value isn't a string.
		 */
		@Deprecated
		public String getValue() {
			return getValueAsString();
		}
		
		
		/**
		 * Returns the requested value (as number) for the claim.
		 *
		 * @return The value as number, {@code null} if not specified
		 *         or the value isn't a number.
		 */
		public Number getValueAsNumber() {
			if (value instanceof Number) {
				return (Number)value;
			} else {
				return null;
			}
		}
		
		
		/**
		 * Returns the requested value (as JSON object) for the claim.
		 *
		 * @return The value as JSON object, {@code null} if not
		 *         specified or the value isn't a JSON object.
		 */
		public JSONObject getValueAsJSONObject() {
			if (value instanceof JSONObject) {
				return (JSONObject)value;
			} else {
				return null;
			}
		}
		
		
		/**
		 * Returns the requested value (untyped) for the claim.
		 *
		 * @return The value (untyped), {@code null} if not specified.
		 */
		public Object getRawValue() {
			return value;
		}
		
		
		/**
		 * Sets the requested values (untyped) for the claim.
		 *
		 * @param values The values, {@code null} if not specified.
		 *
		 * @return The updated entry.
		 */
		public ClaimsSetRequest.Entry withValues(final List<?> values) {
			return new ClaimsSetRequest.Entry(claimName, requirement, langTag, null, values, purpose, additionalInformation);
		}
		
		
		/**
		 * Returns the requested values (as strings) for the claim.
		 *
		 * @return The values as list of strings, {@code null} if not
		 *         specified or the values aren't strings.
		 */
		public List<String> getValuesAsListOfStrings() {
			if (values == null) {
				return null;
			}
			if (values.isEmpty()) {
				return Collections.emptyList();
			}
			List<String> list = new ArrayList<>(values.size());
			for (Object v: values) {
				if (v instanceof String) {
					list.add((String)v);
				} else {
					return null;
				}
			}
			return list;
		}
		
		
		/**
		 * Returns the requested values (as strings) for the claim. Use
		 * {@link #getValuesAsListOfStrings()} instead.
		 *
		 * @return The values as list of strings, {@code null} if not
		 *         specified or the values aren't strings.
		 */
		@Deprecated
		public List<String> getValues() {
			return getValuesAsListOfStrings();
		}
		
		
		/**
		 * Returns the requested values (as JSON objects) for the
		 * claim.
		 *
		 * @return The values as list of JSON objects, {@code null} if
		 *         not specified or the values aren't JSON objects.
		 */
		public List<JSONObject> getValuesAsListOfJSONObjects() {
			if (values == null) {
				return null;
			}
			if (values.isEmpty()) {
				return Collections.emptyList();
			}
			List<JSONObject> list = new ArrayList<>(values.size());
			for (Object v: values) {
				if (v instanceof JSONObject) {
					list.add((JSONObject) v);
				} else {
					return null;
				}
			}
			return list;
		}
		
		
		/**
		 * Returns the requested values (untyped) for the claim.
		 *
		 * @return The values as list of untyped objects, {@code null}
		 *         if not specified.
		 */
		public List<?> getValuesAsRawList() {
			return values;
		}
		
		
		/**
		 * Sets the purpose for which the claim is requested.
		 *
		 * @param purpose The purpose, {@code null} if not specified.
		 *
		 * @return The updated entry.
		 */
		public ClaimsSetRequest.Entry withPurpose(final String purpose) {
			return new ClaimsSetRequest.Entry(claimName, requirement, langTag, value, values, purpose, additionalInformation);
		}
		
		
		/**
		 * Returns the optional purpose for which the claim is
		 * requested.
		 *
		 * @return The purpose, {@code null} if not specified.
		 */
		public String getPurpose() {
			return purpose;
		}
		
		
		/**
		 * Sets additional information for the requested claim.
		 *
		 * <p>Example additional information in the "info" member:
		 *
		 * <pre>
		 * {
		 *   "userinfo" : {
		 *       "email": null,
		 *       "email_verified": null,
		 *       "http://example.info/claims/groups" : { "info" : "custom information" }
		 *   }
		 * }
		 * </pre>
		 *
		 * @param additionalInformation The additional information,
		 *                              {@code null} if not specified.
		 *
		 * @return The updated entry.
		 */
		public ClaimsSetRequest.Entry withAdditionalInformation(final Map<String, Object> additionalInformation) {
			return new ClaimsSetRequest.Entry(claimName, requirement, langTag, value, values, purpose, additionalInformation);
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
		 *       "http://example.info/claims/groups" : { "info" : "custom information" }
		 *   }
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
		 * Returns the JSON object entry for this individual claim
		 * request.
		 *
		 * @return The JSON object entry.
		 */
		public Map.Entry<String,JSONObject> toJSONObjectEntry() {
			
			// Compose the optional value
			JSONObject entrySpec = null;
			
			if (getRawValue() != null) {
				
				entrySpec = new JSONObject();
				entrySpec.put("value", getRawValue());
			}
			
			if (getValuesAsRawList() != null) {
				
				// Either "value" or "values", or none
				// may be defined
				entrySpec = new JSONObject();
				entrySpec.put("values", getValuesAsRawList());
			}
			
			if (getClaimRequirement().equals(ClaimRequirement.ESSENTIAL)) {
				
				if (entrySpec == null)
					entrySpec = new JSONObject();
				
				entrySpec.put("essential", true);
			}
			
			if (getPurpose() != null) {
				if (entrySpec == null) {
					entrySpec = new JSONObject();
				}
				entrySpec.put("purpose", getPurpose());
			}
			
			if (getAdditionalInformation() != null) {
				if (entrySpec == null) {
					entrySpec = new JSONObject();
				}
				for (Map.Entry<String, Object> additionalInformationEntry : getAdditionalInformation().entrySet()) {
					entrySpec.put(additionalInformationEntry.getKey(), additionalInformationEntry.getValue());
				}
			}
			
			return new AbstractMap.SimpleImmutableEntry<>(getClaimName(true), entrySpec);
		}
		
		
		/**
		 * Parses an individual claim request from the specified JSON
		 * object entry.
		 *
		 * @param jsonObjectEntry The JSON object entry to parse. Must
		 *                        not be {@code null}.
		 *
		 * @return The individual claim request.
		 *
		 * @throws ParseException If parsing failed.
		 */
		public static ClaimsSetRequest.Entry parse(final Map.Entry<String,JSONObject> jsonObjectEntry)
			throws ParseException {
			
			// Process the key
			String claimNameWithOptLangTag = jsonObjectEntry.getKey();
			
			String claimName;
			LangTag langTag = null;
			
			if (claimNameWithOptLangTag.contains("#")) {
				
				String[] parts = claimNameWithOptLangTag.split("#", 2);
				
				claimName = parts[0];
				
				try {
					langTag = LangTag.parse(parts[1]);
				} catch (LangTagException e) {
					throw new ParseException(e.getMessage(), e);
				}
				
			} else {
				claimName = claimNameWithOptLangTag;
			}
			
			// Parse the optional spec
			
			JSONObject spec = jsonObjectEntry.getValue();
			
			if (spec == null) {
				// Voluntary claim with no value(s)
				return new ClaimsSetRequest.Entry(claimName).withLangTag(langTag);
			}
			
			ClaimRequirement requirement = ClaimRequirement.VOLUNTARY;
			
			if (spec.containsKey("essential")) {
				
				boolean isEssential = JSONObjectUtils.getBoolean(spec, "essential");
				
				if (isEssential)
					requirement = ClaimRequirement.ESSENTIAL;
			}
			
			String purpose = JSONObjectUtils.getString(spec, "purpose", null);
			
			if (spec.get("value") != null) {
				
				Object expectedValue = spec.get("value");
				Map<String, Object> additionalInformation = getAdditionalInformationFromClaim(spec);
				return new ClaimsSetRequest.Entry(claimName, requirement, langTag, expectedValue, null, purpose, additionalInformation);
				
			} else if (spec.get("values") != null) {
				
				List<Object> expectedValues = JSONObjectUtils.getList(spec, "values");
				Map<String, Object> additionalInformation = getAdditionalInformationFromClaim(spec);
				return new ClaimsSetRequest.Entry(claimName, requirement, langTag, null, expectedValues, purpose, additionalInformation);
				
			} else {
				Map<String, Object> additionalInformation = getAdditionalInformationFromClaim(spec);
				return new ClaimsSetRequest.Entry(claimName, requirement, langTag, null, null, purpose, additionalInformation);
			}
		}
		
		
		private static Map<String, Object> getAdditionalInformationFromClaim(final JSONObject spec) {
			
			Set<String> stdKeys = new HashSet<>(Arrays.asList("essential", "value", "values", "purpose"));
			
			Map<String, Object> additionalClaimInformation = new HashMap<>();
			
			for (Map.Entry<String, Object> additionalClaimInformationEntry : spec.entrySet()) {
				if (stdKeys.contains(additionalClaimInformationEntry.getKey())) {
					continue; // skip std key
				}
				additionalClaimInformation.put(additionalClaimInformationEntry.getKey(), additionalClaimInformationEntry.getValue());
			}
			
			return additionalClaimInformation.isEmpty() ? null : additionalClaimInformation;
		}
	}
	
	
	/**
	 * The request entries.
	 */
	private final Collection<ClaimsSetRequest.Entry> entries;
	
	
	/**
	 * Creates a new empty OpenID Connect claims set request.
	 */
	public ClaimsSetRequest() {
		this(Collections.<Entry>emptyList());
	}
	
	
	/**
	 * Creates a new OpenID Connect claims set request.
	 *
	 * @param entries The request entries, empty collection if none. Must
	 *                not be {@code null}.
	 */
	public ClaimsSetRequest(final Collection<ClaimsSetRequest.Entry> entries) {
		if (entries == null) {
			throw new IllegalArgumentException("The entries must not be null");
		}
		this.entries = Collections.unmodifiableCollection(entries);
	}
	
	
	/**
	 * Adds the specified claim to the request, using default settings.
	 * Shorthand for {@link #add(Entry)}.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
	 *
	 * @return The updated claims set request.
	 */
	public ClaimsSetRequest add(final String claimName) {
		return add(new ClaimsSetRequest.Entry(claimName));
	}
	
	
	/**
	 * Adds the specified claim to the request.
	 *
	 * @param entry The individual claim request. Must not be {@code null}.
	 *
	 * @return The updated claims set request.
	 */
	public ClaimsSetRequest add(final ClaimsSetRequest.Entry entry) {
		List<Entry> updatedEntries = new LinkedList<>(getEntries());
		updatedEntries.add(entry);
		return new ClaimsSetRequest(updatedEntries);
	}
	
	
	/**
	 * Gets the request entries.
	 *
	 * @return The request entries, empty collection if none.
	 */
	public Collection<ClaimsSetRequest.Entry> getEntries() {
		return entries;
	}
	
	
	/**
	 * Gets the names of the requested claims.
	 *
	 * @param withLangTag If {@code true} the language tags, if any, will
	 *                    be appended to the names, else not.
	 *
	 * @return The claim names, as an unmodifiable set, empty set if none.
	 */
	public Set<String> getClaimNames(final boolean withLangTag) {
		Set<String> names = new HashSet<>();
		for (ClaimsSetRequest.Entry en : entries) {
			names.add(en.getClaimName(withLangTag));
		}
		return Collections.unmodifiableSet(names);
	}
	
	
	/**
	 * Gets the specified claim entry from this request.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
	 *
	 * @return The claim entry, {@code null} if not found.
	 */
	public Entry get(final String claimName) {
		
		return get(claimName, null);
	}
	
	
	/**
	 * Gets the specified claim entry from this request.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
	 * @param langTag   The associated language tag, {@code null} if none.
	 *
	 * @return The claim entry, {@code null} if not found.
	 */
	public Entry get(final String claimName, final LangTag langTag) {
		
		for (ClaimsSetRequest.Entry en: getEntries()) {
			if (claimName.equals(en.getClaimName()) && langTag == null && en.getLangTag() == null) {
				// No lang tag
				return en;
			} else if (claimName.equals(en.getClaimName()) && langTag != null && langTag.equals(en.getLangTag())) {
				// Matching lang tag
				return en;
			}
		}
		return null;
	}
	
	
	/**
	 * Deletes the specified claim from this request.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
	 * @param langTag   The associated language tag, {@code null} if none.
	 *
	 * @return The updated claims set request.
	 */
	public ClaimsSetRequest delete(final String claimName, final LangTag langTag) {
		
		Collection<ClaimsSetRequest.Entry> updatedEntries = new LinkedList<>();
		
		for (ClaimsSetRequest.Entry en: getEntries()) {
			if (claimName.equals(en.getClaimName()) && langTag == null && en.getLangTag() == null) {
				// don't copy
			} else if (claimName.equals(en.getClaimName()) && langTag != null && langTag.equals(en.getLangTag())) {
				// don't copy
			} else {
				updatedEntries.add(en);
			}
		}
		
		return new ClaimsSetRequest(updatedEntries);
	}
	
	
	/**
	 * Deletes the specified claim from this request, in all existing
	 * language tag variations if any.
	 *
	 * @param claimName The claim name. Must not be {@code null}.
	 *
	 * @return The updated claims set request.
	 */
	public ClaimsSetRequest delete(final String claimName) {
		Collection<ClaimsSetRequest.Entry> updatedEntries = new LinkedList<>();
		
		for (ClaimsSetRequest.Entry en: getEntries()) {
			if (claimName.equals(en.getClaimName())) {
				// don't copy
			} else {
				updatedEntries.add(en);
			}
		}
		
		return new ClaimsSetRequest(updatedEntries);
	}
	
	
	/**
	 * Returns the JSON object representation of this claims set request.
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
	 * @return The JSON object, empty if no claims are specified.
	 */
	public JSONObject toJSONObject() {
		JSONObject o = new JSONObject();
		for (ClaimsSetRequest.Entry entry : entries) {
			Map.Entry<String, JSONObject> jsonObjectEntry = entry.toJSONObjectEntry();
			o.put(jsonObjectEntry.getKey(), jsonObjectEntry.getValue());
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
	 * Parses an OpenID Connect claims set request from the specified JSON
	 * object representation.
	 *
	 * @param jsonObject The JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The claims set request.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ClaimsSetRequest parse(final JSONObject jsonObject)
		throws ParseException {
		
		ClaimsSetRequest claimsRequest = new ClaimsSetRequest();

		for (String key: jsonObject.keySet()) {
			
			if ("verified_claims".equals(key)) {
				// Implies nested VerifiedClaimsSetRequest, skip
				continue;
			}
			
			JSONObject value = JSONObjectUtils.getJSONObject(jsonObject, key, null);
			
			claimsRequest = claimsRequest.add(ClaimsSetRequest.Entry.parse(new AbstractMap.SimpleImmutableEntry<>(key, value)));
		}
		
		return claimsRequest;
	}
	
	
	/**
	 * Parses an OpenID Connect claims set request from the specified JSON
	 * object string representation.
	 *
	 * @param json The JSON object string to parse. Must not be
	 *             {@code null}.
	 *
	 * @return The claims set request.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ClaimsSetRequest parse(final String json)
		throws ParseException {
		
		return parse(JSONObjectUtils.parse(json));
	}
}
