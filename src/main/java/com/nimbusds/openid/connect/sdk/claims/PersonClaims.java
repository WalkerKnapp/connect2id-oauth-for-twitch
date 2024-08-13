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

package com.nimbusds.openid.connect.sdk.claims;


import java.net.URI;
import java.util.*;

import net.minidev.json.JSONObject;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.assurance.claims.Birthplace;
import com.nimbusds.openid.connect.sdk.assurance.claims.CountryCode;
import com.nimbusds.openid.connect.sdk.assurance.claims.MSISDN;


/**
 * Person-specific claims set, intended to provide common getters and setters
 * for {@link UserInfo OpenID Connect UserInfo} and
 * {@link com.nimbusds.openid.connect.sdk.assurance.claims.VerifiedClaimsSet
 * OpenID Connect Identity Assurance verified claims}.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
public class PersonClaims extends ClaimsSet {


	/**
	 * The name claim name.
	 */
	public static final String NAME_CLAIM_NAME = "name";


	/**
	 * The given name claim name.
	 */
	public static final String GIVEN_NAME_CLAIM_NAME = "given_name";


	/**
	 * The family name claim name.
	 */
	public static final String FAMILY_NAME_CLAIM_NAME = "family_name";


	/**
	 * The middle name claim name.
	 */
	public static final String MIDDLE_NAME_CLAIM_NAME = "middle_name";


	/**
	 * The nickname claim name.
	 */
	public static final String NICKNAME_CLAIM_NAME = "nickname";


	/**
	 * The preferred username claim name.
	 */
	public static final String PREFERRED_USERNAME_CLAIM_NAME = "preferred_username";


	/**
	 * The profile claim name.
	 */
	public static final String PROFILE_CLAIM_NAME = "profile";


	/**
	 * The picture claim name.
	 */
	public static final String PICTURE_CLAIM_NAME = "picture";


	/**
	 * The website claim name.
	 */
	public static final String WEBSITE_CLAIM_NAME = "website";


	/**
	 * The email claim name.
	 */
	public static final String EMAIL_CLAIM_NAME = "email";


	/**
	 * The email verified claim name.
	 */
	public static final String EMAIL_VERIFIED_CLAIM_NAME = "email_verified";


	/**
	 * The gender claim name.
	 */
	public static final String GENDER_CLAIM_NAME = "gender";


	/**
	 * The birth date claim name.
	 */
	public static final String BIRTHDATE_CLAIM_NAME = "birthdate";


	/**
	 * The zoneinfo claim name.
	 */
	public static final String ZONEINFO_CLAIM_NAME = "zoneinfo";


	/**
	 * The locale claim name.
	 */
	public static final String LOCALE_CLAIM_NAME = "locale";


	/**
	 * The phone number claim name.
	 */
	public static final String PHONE_NUMBER_CLAIM_NAME = "phone_number";


	/**
	 * The phone number verified claim name.
	 */
	public static final String PHONE_NUMBER_VERIFIED_CLAIM_NAME = "phone_number_verified";


	/**
	 * The address claim name.
	 */
	public static final String ADDRESS_CLAIM_NAME = "address";


	/**
	 * The updated at claim name.
	 */
	public static final String UPDATED_AT_CLAIM_NAME = "updated_at";
	
	
	/**
	 * The birthplace claim name (OpenID Connect for Identity Assurance
	 * 1.0). Alternative for {@link #PLACE_OF_BIRTH_CLAIM_NAME}.
	 */
	@Deprecated
	public static final String BIRTHPLACE_CLAIM_NAME = "birthplace";
	
	
	/**
	 * The place of birth claim name (OpenID Connect for Identity Assurance
	 * 1.0). Alternative for {@link #BIRTHPLACE_CLAIM_NAME}.
	 */
	public static final String PLACE_OF_BIRTH_CLAIM_NAME = "place_of_birth";
	
	
	/**
	 * The nationalities claim name (OpenID Connect for Identity Assurance
	 * 1.0).
	 */
	public static final String NATIONALITIES_CLAIM_NAME = "nationalities";
	
	
	/**
	 * The birth family name claim name (OpenID Connect for Identity
	 * Assurance 1.0).
	 */
	public static final String BIRTH_FAMILY_NAME_CLAIM_NAME = "birth_family_name";
	
	
	/**
	 * The birth given name claim name (OpenID Connect for Identity
	 * Assurance 1.0).
	 */
	public static final String BIRTH_GIVEN_NAME_CLAIM_NAME = "birth_given_name";
	
	
	/**
	 * The birth middle name claim name (OpenID Connect for Identity
	 * Assurance 1.0).
	 */
	public static final String BIRTH_MIDDLE_NAME_CLAIM_NAME = "birth_middle_name";
	
	
	/**
	 * The salutation claim name (OpenID Connect for Identity Assurance
	 * 1.0).
	 */
	public static final String SALUTATION_CLAIM_NAME = "salutation";
	
	
	/**
	 * The title claim name (OpenID Connect for Identity Assurance 1.0).
	 */
	public static final String TITLE_CLAIM_NAME = "title";
	
	
	/**
	 * The MSISDN claim name (OpenID Connect for Identity Assurance 1.0).
	 */
	public static final String MSISDN_CLAIM_NAME = "msisdn";
	
	
	/**
	 * The also known as claim name (OpenID Connect for Identity Assurance
	 * 1.0).
	 */
	public static final String ALSO_KNOWN_AS = "also_known_as";
	
	
	/**
	 * Gets the names of the standard top-level UserInfo claims.
	 *
	 * @return The names of the standard top-level UserInfo claims
	 *         (read-only set).
	 */
	public static Set<String> getStandardClaimNames() {
	
		Set<String> names = new HashSet<>(ClaimsSet.getStandardClaimNames());
		names.addAll(Arrays.asList(
			NAME_CLAIM_NAME,
			GIVEN_NAME_CLAIM_NAME,
			FAMILY_NAME_CLAIM_NAME,
			MIDDLE_NAME_CLAIM_NAME,
			NICKNAME_CLAIM_NAME,
			PREFERRED_USERNAME_CLAIM_NAME,
			PROFILE_CLAIM_NAME,
			PICTURE_CLAIM_NAME,
			WEBSITE_CLAIM_NAME,
			EMAIL_CLAIM_NAME,
			EMAIL_VERIFIED_CLAIM_NAME,
			GENDER_CLAIM_NAME,
			BIRTHDATE_CLAIM_NAME,
			ZONEINFO_CLAIM_NAME,
			LOCALE_CLAIM_NAME,
			PHONE_NUMBER_CLAIM_NAME,
			PHONE_NUMBER_VERIFIED_CLAIM_NAME,
			ADDRESS_CLAIM_NAME,
			UPDATED_AT_CLAIM_NAME,
			BIRTHPLACE_CLAIM_NAME,
			PLACE_OF_BIRTH_CLAIM_NAME,
			NATIONALITIES_CLAIM_NAME,
			BIRTH_FAMILY_NAME_CLAIM_NAME,
			BIRTH_GIVEN_NAME_CLAIM_NAME,
			BIRTH_MIDDLE_NAME_CLAIM_NAME,
			SALUTATION_CLAIM_NAME,
			TITLE_CLAIM_NAME,
			MSISDN_CLAIM_NAME,
			ALSO_KNOWN_AS
		));
		return Collections.unmodifiableSet(names);
	}
	
	
	/**
	 * Creates a new empty person-specific claims set.
	 */
	public PersonClaims() {
		this(new JSONObject());
	}


	/**
	 * Creates a new person-specific claims set from the specified JSON
	 * object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 */
	public PersonClaims(final JSONObject jsonObject) {

		super(jsonObject);
	}
	
	
	// name

	
	/**
	 * Gets the full name. Corresponds to the {@code name} claim, with no
	 * language tag.
	 *
	 * @return The full name, {@code null} if not specified.
	 */
	public String getName() {
	
		return getStringClaim(NAME_CLAIM_NAME);
	}
	
	
	/**
	 * Gets the full name. Corresponds to the {@code name} claim, with an
	 * optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get 
	 *                the non-tagged entry.
	 *
	 * @return The full name, {@code null} if not specified.
	 */
	public String getName(final LangTag langTag) {
	
		return getStringClaim(NAME_CLAIM_NAME, langTag);
	}
	
	
	/**
	 * Gets the full name entries. Correspond to the {@code name} claim.
	 *
	 * @return The full name entries, empty map if none.
	 */
	public Map<LangTag,String> getNameEntries() {
	
		return getLangTaggedClaim(NAME_CLAIM_NAME, String.class);
	}


	/**
	 * Sets the full name. Corresponds to the {@code name} claim, with no
	 * language tag.
	 *
	 * @param name The full name. If {@code null} the claim will be 
	 *             removed.
	 */
	public void setName(final String name) {
	
		setClaim(NAME_CLAIM_NAME, name);
	}
	
	
	/**
	 * Sets the full name. Corresponds to the {@code name} claim, with an
	 * optional language tag.
	 *
	 * @param name    The full name. If {@code null} the claim will be 
	 *                removed.
	 * @param langTag The language tag, {@code null} if not specified.
	 */
	public void setName(final String name, final LangTag langTag) {
	
		setClaim(NAME_CLAIM_NAME, name, langTag);
	}
	
	
	// given_name
	
	
	/**
	 * Gets the given or first name. Corresponds to the {@code given_name} 
	 * claim, with no language tag.
	 *
	 * @return The given or first name, {@code null} if not specified.
	 */
	public String getGivenName() {
	
		return getStringClaim(GIVEN_NAME_CLAIM_NAME);
	}
	
	
	/**
	 * Gets the given or first name. Corresponds to the {@code given_name} 
	 * claim, with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get 
	 *                the non-tagged entry.
	 *
	 * @return The given or first name, {@code null} if not specified.
	 */
	public String getGivenName(final LangTag langTag) {
	
		return getStringClaim(GIVEN_NAME_CLAIM_NAME, langTag);
	}
	
	
	/**
	 * Gets the given or first name entries. Correspond to the 
	 * {@code given_name} claim.
	 *
	 * @return The given or first name entries, empty map if none.
	 */
	public Map<LangTag,String> getGivenNameEntries() {
	
		return getLangTaggedClaim(GIVEN_NAME_CLAIM_NAME, String.class);
	}


	/**
	 * Sets the given or first name. Corresponds to the {@code given_name} 
	 * claim, with no language tag.
	 *
	 * @param givenName The given or first name. If {@code null} the claim
	 *                  will be removed.
	 */
	public void setGivenName(final String givenName) {
	
		setClaim(GIVEN_NAME_CLAIM_NAME, givenName);
	}
	
	
	/**
	 * Sets the given or first name. Corresponds to the {@code given_name}
	 * claim, with an optional language tag.
	 *
	 * @param givenName The given or first full name. If {@code null} the 
	 *                  claim will be removed.
	 * @param langTag   The language tag, {@code null} if not specified.
	 */
	public void setGivenName(final String givenName, final LangTag langTag) {
	
		setClaim(GIVEN_NAME_CLAIM_NAME, givenName, langTag);
	}
	
	
	// family_name

	
	/**
	 * Gets the surname or last name. Corresponds to the 
	 * {@code family_name} claim, with no language tag.
	 *
	 * @return The surname or last name, {@code null} if not specified.
	 */
	public String getFamilyName() {
	
		return getStringClaim(FAMILY_NAME_CLAIM_NAME);
	}
	
	
	/**
	 * Gets the surname or last name. Corresponds to the 
	 * {@code family_name} claim, with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get 
	 *                the non-tagged entry.
	 *
	 * @return The surname or last name, {@code null} if not specified.
	 */
	public String getFamilyName(final LangTag langTag) {
	
		return getStringClaim(FAMILY_NAME_CLAIM_NAME, langTag);
	}
	
	
	/**
	 * Gets the surname or last name entries. Correspond to the 
	 * {@code family_name} claim.
	 *
	 * @return The surname or last name entries, empty map if none.
	 */
	public Map<LangTag,String> getFamilyNameEntries() {
	
		return getLangTaggedClaim(FAMILY_NAME_CLAIM_NAME, String.class);
	}


	/**
	 * Sets the surname or last name. Corresponds to the 
	 * {@code family_name} claim, with no language tag.
	 *
	 * @param familyName The surname or last name. If {@code null} the 
	 *                   claim will be removed.
	 */
	public void setFamilyName(final String familyName) {
	
		setClaim(FAMILY_NAME_CLAIM_NAME, familyName);
	}
	
	
	/**
	 * Sets the surname or last name. Corresponds to the 
	 * {@code family_name} claim, with an optional language tag.
	 *
	 * @param familyName The surname or last name. If {@code null} the 
	 *                   claim will be removed.
	 * @param langTag    The language tag, {@code null} if not specified.
	 */
	public void setFamilyName(final String familyName, final LangTag langTag) {
	
		setClaim(FAMILY_NAME_CLAIM_NAME, familyName, langTag);
	}
	
	
	// middle_name

	
	/**
	 * Gets the middle name. Corresponds to the {@code middle_name} claim, 
	 * with no language tag.
	 *
	 * @return The middle name, {@code null} if not specified.
	 */
	public String getMiddleName() {
	
		return getStringClaim(MIDDLE_NAME_CLAIM_NAME);
	}
	
	
	/**
	 * Gets the middle name. Corresponds to the {@code middle_name} claim,
	 * with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get 
	 *                the non-tagged entry.
	 *
	 * @return The middle name, {@code null} if not specified.
	 */
	public String getMiddleName(final LangTag langTag) {
	
		return getStringClaim(MIDDLE_NAME_CLAIM_NAME, langTag);
	}
	
	
	/**
	 * Gets the middle name entries. Correspond to the {@code middle_name}
	 * claim.
	 *
	 * @return The middle name entries, empty map if none.
	 */
	public Map<LangTag,String> getMiddleNameEntries() {
	
		return getLangTaggedClaim(MIDDLE_NAME_CLAIM_NAME, String.class);
	}


	/**
	 * Sets the middle name. Corresponds to the {@code middle_name} claim,
	 * with no language tag.
	 *
	 * @param middleName The middle name. If {@code null} the claim will be
	 *                   removed.
	 */
	public void setMiddleName(final String middleName) {
	
		setClaim(MIDDLE_NAME_CLAIM_NAME, middleName);
	}
	
	
	/**
	 * Sets the middle name. Corresponds to the {@code middle_name} claim, 
	 * with an optional language tag.
	 *
	 * @param middleName The middle name. If {@code null} the claim will be
	 *                   removed.
	 * @param langTag    The language tag, {@code null} if not specified.
	 */
	public void setMiddleName(final String middleName, final LangTag langTag) {
	
		setClaim(MIDDLE_NAME_CLAIM_NAME, middleName, langTag);
	}
	
	
	// nickname
	
	
	/**
	 * Gets the casual name. Corresponds to the {@code nickname} claim, 
	 * with no language tag.
	 *
	 * @return The casual name, {@code null} if not specified.
	 */
	public String getNickname() {
	
		return getStringClaim(NICKNAME_CLAIM_NAME);
	}
	
	
	/**
	 * Gets the casual name. Corresponds to the {@code nickname} claim, 
	 * with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get 
	 *                the non-tagged entry.
	 *
	 * @return The casual name, {@code null} if not specified.
	 */
	public String getNickname(final LangTag langTag) {
	
		return getStringClaim(NICKNAME_CLAIM_NAME, langTag);
	}
	
	
	/**
	 * Gets the casual name entries. Correspond to the {@code nickname} 
	 * claim.
	 *
	 * @return The casual name entries, empty map if none.
	 */
	public Map<LangTag,String> getNicknameEntries() {
	
		return getLangTaggedClaim(NICKNAME_CLAIM_NAME, String.class);
	}


	/**
	 * Sets the casual name. Corresponds to the {@code nickname} claim, 
	 * with no language tag.
	 *
	 * @param nickname The casual name. If {@code null} the claim will be
	 *                 removed.
	 */
	public void setNickname(final String nickname) {
	
		setClaim(NICKNAME_CLAIM_NAME, nickname);
	}
	
	
	/**
	 * Sets the casual name. Corresponds to the {@code nickname} claim, 
	 * with an optional language tag.
	 *
	 * @param nickname The casual name. If {@code null} the claim will be
	 *                 removed.
	 * @param langTag  The language tag, {@code null} if not specified.
	 */
	public void setNickname(final String nickname, final LangTag langTag) {
	
		setClaim(NICKNAME_CLAIM_NAME, nickname, langTag);
	}
	
	
	// preferred_username
	
	
	/**
	 * Gets the preferred username. Corresponds to the 
	 * {@code preferred_username} claim.
	 *
	 * @return The preferred username, {@code null} if not specified.
	 */
	public String getPreferredUsername() {
	
		return getStringClaim(PREFERRED_USERNAME_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the preferred username. Corresponds to the 
	 * {@code preferred_username} claim.
	 *
	 * @param preferredUsername The preferred username. If {@code null} the
	 *                          claim will be removed.
	 */
	public void setPreferredUsername(final String preferredUsername) {
	
		setClaim(PREFERRED_USERNAME_CLAIM_NAME, preferredUsername);
	}
	
	
	// profile
	
	
	/**
	 * Gets the profile page. Corresponds to the {@code profile} claim.
	 *
	 * @return The profile page URI, {@code null} if not specified.
	 */
	public URI getProfile() {
	
		return getURIClaim(PROFILE_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the profile page. Corresponds to the {@code profile} claim.
	 *
	 * @param profile The profile page URI. If {@code null} the claim will
	 *                be removed.
	 */
	public void setProfile(final URI profile) {
	
		setURIClaim(PROFILE_CLAIM_NAME, profile);
	}
	
	
	// picture
	
	
	/**
	 * Gets the picture. Corresponds to the {@code picture} claim.
	 *
	 * @return The picture URI, {@code null} if not specified.
	 */
	public URI getPicture() {
	
		return getURIClaim(PICTURE_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the picture. Corresponds to the {@code picture} claim.
	 *
	 * @param picture The picture URI. If {@code null} the claim will be
	 *                removed.
	 */
	public void setPicture(final URI picture) {
	
		setURIClaim(PICTURE_CLAIM_NAME, picture);
	}
	
	
	// website
	
	
	/**
	 * Gets the web page or blog. Corresponds to the {@code website} claim.
	 *
	 * @return The web page or blog URI, {@code null} if not specified.
	 */
	public URI getWebsite() {
	
		return getURIClaim(WEBSITE_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the web page or blog. Corresponds to the {@code website} claim.
	 *
	 * @param website The web page or blog URI. If {@code null} the claim
	 *                will be removed.
	 */
	public void setWebsite(final URI website) {
	
		setURIClaim(WEBSITE_CLAIM_NAME, website);
	}
	
	
	// email
	
	
	/**
	 * Gets the preferred email address. Corresponds to the {@code email}
	 * claim.
	 *
	 * @return The preferred email address, {@code null} if not specified.
	 */
	public String getEmailAddress() {
	
		return getStringClaim(EMAIL_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the preferred email address. Corresponds to the {@code email}
	 * claim.
	 *
	 * @param email The preferred email address. If {@code null} the claim
	 *              will be removed.
	 */
	public void setEmailAddress(final String email) {
	
		setClaim(EMAIL_CLAIM_NAME, email);
	}
	
	
	// email_verified
	
	
	/**
	 * Gets the email verification status. Corresponds to the 
	 * {@code email_verified} claim.
	 *
	 * @return The email verification status, {@code null} if not 
	 *         specified.
	 */
	public Boolean getEmailVerified() {
	
		return getBooleanClaim(EMAIL_VERIFIED_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the email verification status. Corresponds to the
	 * {@code email_verified} claim.
	 *
	 * @param emailVerified The email verification status. If {@code null} 
	 *                      the claim will be removed.
	 */
	public void setEmailVerified(final Boolean emailVerified) {
	
		setClaim(EMAIL_VERIFIED_CLAIM_NAME, emailVerified);
	}
	
	
	// gender
	
	
	/**
	 * Gets the gender. Corresponds to the {@code gender} claim.
	 *
	 * @return The gender, {@code null} if not specified.
	 */
	public Gender getGender() {
	
		String value = getStringClaim(GENDER_CLAIM_NAME);
		
		if (value == null)
			return null;

		return new Gender(value);
	}
	
	
	/**
	 * Sets the gender. Corresponds to the {@code gender} claim.
	 *
	 * @param gender The gender. If {@code null} the claim will be removed.
	 */
	public void setGender(final Gender gender) {
	
		if (gender != null)
			setClaim(GENDER_CLAIM_NAME, gender.getValue());
		else
			setClaim(GENDER_CLAIM_NAME, null);
	}
	
	
	// birthdate
	
	
	/**
	 * Gets the date of birth. Corresponds to the {@code birthdate} claim.
	 *
	 * @return The date of birth, {@code null} if not specified.
	 */
	public String getBirthdate() {
	
		return getStringClaim(BIRTHDATE_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the date of birth. Corresponds to the {@code birthdate} claim.
	 *
	 * @param birthdate The date of birth. If {@code null} the claim will
	 *                  be removed.
	 */
	public void setBirthdate(final String birthdate) {
	
		setClaim(BIRTHDATE_CLAIM_NAME, birthdate);
	}
	
	
	// zoneinfo
	
	
	/**
	 * Gets the zoneinfo. Corresponds to the {@code zoneinfo} claim.
	 *
	 * @return The zoneinfo, {@code null} if not specified.
	 */
	public String getZoneinfo() {
	
		return getStringClaim(ZONEINFO_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the zoneinfo. Corresponds to the {@code zoneinfo} claim.
	 *
	 * @param zoneinfo The zoneinfo. If {@code null} the claim will be 
	 *                 removed.
	 */
	public void setZoneinfo(final String zoneinfo) {
	
		setClaim(ZONEINFO_CLAIM_NAME, zoneinfo);
	}
	
	
	// locale
	
	
	/**
	 * Gets the locale. Corresponds to the {@code locale} claim.
	 *
	 * @return The locale, {@code null} if not specified.
	 */
	public String getLocale() {
	
		return getStringClaim(LOCALE_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the locale. Corresponds to the {@code locale} claim.
	 *
	 * @param locale The locale. If {@code null} the claim will be 
	 *               removed.
	 */
	public void setLocale(final String locale) {
	
		setClaim(LOCALE_CLAIM_NAME, locale);
	}
	
	
	// phone_number
	
	
	/**
	 * Gets the preferred telephone number. Corresponds to the 
	 * {@code phone_number} claim.
	 *
	 * @return The preferred telephone number, {@code null} if not 
	 *         specified.
	 */
	public String getPhoneNumber() {
	
		return getStringClaim(PHONE_NUMBER_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the preferred telephone number. Corresponds to the 
	 * {@code phone_number} claim.
	 *
	 * @param phoneNumber The preferred telephone number. If {@code null} 
	 *                    the claim will be removed.
	 */
	public void setPhoneNumber(final String phoneNumber) {
	
		setClaim(PHONE_NUMBER_CLAIM_NAME, phoneNumber);
	}
	
	
	// phone_number_verified
	
	
	/**
	 * Gets the phone number verification status. Corresponds to the 
	 * {@code phone_number_verified} claim.
	 *
	 * @return The phone number verification status, {@code null} if not 
	 *         specified.
	 */
	public Boolean getPhoneNumberVerified() {
	
		return getBooleanClaim(PHONE_NUMBER_VERIFIED_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the email verification status. Corresponds to the
	 * {@code phone_number_verified} claim.
	 *
	 * @param phoneNumberVerified The phone number verification status. If 
	 *                            {@code null} the claim will be removed.
	 */
	public void setPhoneNumberVerified(final Boolean phoneNumberVerified) {
	
		setClaim(PHONE_NUMBER_VERIFIED_CLAIM_NAME, phoneNumberVerified);
	}
	
	
	// address


	/**
	 * Gets the preferred address. Corresponds to the {@code address} 
	 * claim, with no language tag.
	 *
	 * @return The preferred address, {@code null} if not specified.
	 */
	public Address getAddress() {
	
		return getAddress(null);
	}
	
	
	/**
	 * Gets the preferred address. Corresponds to the {@code address} 
	 * claim, with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get 
	 *                the non-tagged entry.
	 *
	 * @return The preferred address, {@code null} if not specified.
	 */
	public Address getAddress(final LangTag langTag) {
	
		String name;

		if (langTag!= null)
			name = ADDRESS_CLAIM_NAME + "#" + langTag;
		else
			name = ADDRESS_CLAIM_NAME;

		JSONObject jsonObject = getClaim(name, JSONObject.class);

		if (jsonObject == null)
			return null;

		return new Address(jsonObject);
	}
	
	
	/**
	 * Gets the preferred address entries. Correspond to the 
	 * {@code address} claim.
	 *
	 * @return The preferred address entries, empty map if none.
	 */
	public Map<LangTag,Address> getAddressEntries() {
	
		Map<LangTag,JSONObject> entriesIn = getLangTaggedClaim(ADDRESS_CLAIM_NAME, JSONObject.class);

		Map<LangTag,Address> entriesOut = new HashMap<>();

		for (Map.Entry<LangTag,JSONObject> en: entriesIn.entrySet())
			entriesOut.put(en.getKey(), new Address(en.getValue()));

		return entriesOut;
	}


	/**
	 * Sets the preferred address. Corresponds to the {@code address} 
	 * claim, with no language tag.
	 *
	 * @param address The preferred address. If {@code null} the claim will
	 *                be removed.
	 */
	public void setAddress(final Address address) {
	
		if (address != null)
			setClaim(ADDRESS_CLAIM_NAME, address.toJSONObject());
		else
			setClaim(ADDRESS_CLAIM_NAME, null);
	}
	
	
	/**
	 * Sets the preferred address. Corresponds to the {@code address}
	 * claim, with an optional language tag.
	 *
	 * @param address  The preferred address. If {@code null} the claim 
	 *                 will be removed.
	 * @param langTag The language tag, {@code null} if not specified.
	 */
	public void setAddress(final Address address, final LangTag langTag) {

		String key = langTag == null ? ADDRESS_CLAIM_NAME : ADDRESS_CLAIM_NAME + "#" + langTag;

		if (address != null)
			setClaim(key, address.toJSONObject());
		else
			setClaim(key, null);
	}
	
	
	// updated_at
	
	
	/**
	 * Gets the time the end-user information was last updated. Corresponds 
	 * to the {@code updated_at} claim.
	 *
	 * @return The time the end-user information was last updated, 
	 *         {@code null} if not specified.
	 */
	public Date getUpdatedTime() {
	
		return getDateClaim(UPDATED_AT_CLAIM_NAME);
	}
	
	
	/**
	 * Sets the time the end-user information was last updated. Corresponds
	 * to the {@code updated_at} claim.
	 *
	 * @param updatedTime The time the end-user information was last 
	 *                    updated. If {@code null} the claim will be 
	 *                    removed.
	 */
	public void setUpdatedTime(final Date updatedTime) {
	
		setDateClaim(UPDATED_AT_CLAIM_NAME, updatedTime);
	}
	
	
	// birthplace
	
	
	/**
	 * Gets the birthplace. Corresponds to the {@code birthplace} claim.
	 *
	 * @see #getPlaceOfBirth()
	 *
	 * @return The birthplace, {@code null} if not specified.
	 */
	@Deprecated
	public Birthplace getBirthplace() {
		
		JSONObject jsonObject = getClaim(BIRTHPLACE_CLAIM_NAME, JSONObject.class);
		
		if (jsonObject == null) {
			return null;
		}
		
		return new Birthplace(jsonObject);
	}
	
	
	/**
	 * Sets the birthplace. Corresponds to the {@code birthplace} claim.
	 *
	 * @see #setPlaceOfBirth(Birthplace)
	 *
	 * @param birthplace The birthplace, {@code null} if not specified.
	 */
	@Deprecated
	public void setBirthplace(final Birthplace birthplace) {
		
		if (birthplace != null) {
			setClaim(BIRTHPLACE_CLAIM_NAME, birthplace.toJSONObject());
		}
	}
	
	
	// place_of_birth
	
	
	/**
	 * Gets the birthplace. Corresponds to the {@code place_of_birth} claim
	 * from OpenID Connect for Identity Assurance 1.0.
	 *
	 * @return The birthplace, {@code null} if not specified.
	 */
	public Birthplace getPlaceOfBirth() {
		
		JSONObject jsonObject = getClaim(PLACE_OF_BIRTH_CLAIM_NAME, JSONObject.class);
		
		if (jsonObject == null) {
			return null;
		}
		
		return new Birthplace(jsonObject);
	}
	
	
	/**
	 * Sets the birthplace. Corresponds to the {@code place_of_birth} claim
	 * from OpenID Connect for Identity Assurance 1.0.
	 *
	 * @param birthplace The birthplace, {@code null} if not specified.
	 */
	public void setPlaceOfBirth(final Birthplace birthplace) {
		
		if (birthplace != null) {
			setClaim(PLACE_OF_BIRTH_CLAIM_NAME, birthplace.toJSONObject());
		}
	}
	
	
	// nationalities
	
	/**
	 * Gets the user's nationalities. Corresponds to the
	 * {@code nationalities} claim from OpenID Connect for Identity
	 * Assurance 1.0.
	 *
	 * @return The nationalities, {@code null} if not specified or parsing
	 *         failed.
	 */
	public List<CountryCode> getNationalities() {
	
		List<String> values = getStringListClaim(NATIONALITIES_CLAIM_NAME);
		
		if (values == null) {
			return null;
		}
		
		List<CountryCode> codes = new LinkedList<>();
		for (String v: values) {
			if (v != null) {
				try {
					codes.add(CountryCode.parse(v));
				} catch (ParseException e) {
					return null;
				}
			}
		}
		return codes;
	}
	
	
	/**
	 * Sets the user's nationalities. Corresponds to the
	 * {@code nationalities} claim from OpenID Connect for Identity
	 * Assurance 1.0.
	 *
	 * @param nationalities The nationalities, {@code null} if not
	 *                      specified.
	 */
	public void setNationalities(final List<CountryCode> nationalities) {
	
		List<String> values = null;
		
		if (nationalities != null) {
			values = new LinkedList<>();
			for (CountryCode code: nationalities) {
				if (code != null) {
					values.add(code.getValue());
				}
			}
		}
		
		setClaim(NATIONALITIES_CLAIM_NAME, values);
	}
	
	
	// birth_family_name
	
	/**
	 * Gets the birth family name. Corresponds to the
	 * {@code birth_family_name} claim from OpenID Connect for Identity
	 * Assurance 1.0, with no language tag.
	 *
	 * @return The birth family name, {@code null} if not specified.
	 */
	public String getBirthFamilyName() {
		
		return getStringClaim(BIRTH_FAMILY_NAME_CLAIM_NAME);
	}
	
	
	/**
	 * Gets the birth family name. Corresponds to the 
	 * {@code birth_family_name} claim from OpenID Connect for Identity 
	 * Assurance 1.0, with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get 
	 *                the non-tagged entry.
	 *
	 * @return The birth family name, {@code null} if not specified.
	 */
	public String getBirthFamilyName(final LangTag langTag) {
		
		return getStringClaim(BIRTH_FAMILY_NAME_CLAIM_NAME, langTag);
	}
	
	
	/**
	 * Gets the birth family name entries. Correspond to the 
	 * {@code birth_family_name} claim from OpenID Connect for Identity 
	 * Assurance 1.0.
	 *
	 * @return The birth family name entries, empty map if none.
	 */
	public Map<LangTag,String> getBirthFamilyNameEntries() {
		
		return getLangTaggedClaim(BIRTH_FAMILY_NAME_CLAIM_NAME, String.class);
	}
	
	
	/**
	 * Sets the birth family name. Corresponds to the
	 * {@code birth_family_name} claim from OpenID Connect for Identity
	 * Assurance 1.0, with no language tag.
	 *
	 * @param birthFamilyName The birth family name, {@code null} if not
	 *                        specified.
	 */
	public void setBirthFamilyName(final String birthFamilyName) {
		
		setClaim(BIRTH_FAMILY_NAME_CLAIM_NAME, birthFamilyName);
	}
	
	
	/**
	 * Sets the birth family name. Corresponds to the 
	 * {@code birth_family_name} claim from OpenID Connect for Identity
	 * Assurance 1.0, with an optional language tag.
	 *
	 * @param birthFamilyName The birth family name. If {@code null} the 
	 *                        claim will be removed.
	 * @param langTag         The language tag, {@code null} if not 
	 *                        specified.
	 */
	public void setBirthFamilyName(final String birthFamilyName, final LangTag langTag) {
		
		setClaim(BIRTH_FAMILY_NAME_CLAIM_NAME, birthFamilyName, langTag);
	}
	
	// birth_given_name
	
	/**
	 * Gets the birth given name. Corresponds to the
	 * {@code birth_given_name} claim from OpenID Connect for Identity
	 * Assurance 1.0, with no language tag.
	 *
	 * @return The birth given name, {@code null} if not specified.
	 */
	public String getBirthGivenName() {
		
		return getStringClaim(BIRTH_GIVEN_NAME_CLAIM_NAME);
	}
	
	
	/**
	 * Gets the birth given name. Corresponds to the 
	 * {@code birth_given_name} claim from OpenID Connect for Identity 
	 * Assurance 1.0, with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get 
	 *                the non-tagged entry.
	 *
	 * @return The birth given name, {@code null} if not specified.
	 */
	public String getBirthGivenName(final LangTag langTag) {
		
		return getStringClaim(BIRTH_GIVEN_NAME_CLAIM_NAME, langTag);
	}
	
	
	/**
	 * Gets the birth given name entries. Correspond to the 
	 * {@code birth_given_name} claim from OpenID Connect for Identity 
	 * Assurance 1.0.
	 *
	 * @return The birth given name entries, empty map if none.
	 */
	public Map<LangTag,String> getBirthGivenNameEntries() {
		
		return getLangTaggedClaim(BIRTH_GIVEN_NAME_CLAIM_NAME, String.class);
	}
	
	
	/**
	 * Sets the birth given name. Corresponds to the
	 * {@code birth_given_name} claim from OpenID Connect for Identity
	 * Assurance 1.0.
	 *
	 * @param birthGivenName The birth given name, {@code null} if not
	 *                       specified.
	 */
	public void setBirthGivenName(final String birthGivenName) {
		
		setClaim(BIRTH_GIVEN_NAME_CLAIM_NAME, birthGivenName);
	}
	
	
	/**
	 * Sets the birth given name. Corresponds to the 
	 * {@code birth_given_name} claim from OpenID Connect for Identity
	 * Assurance 1.0, with an optional language tag.
	 *
	 * @param birthGivenName The birth given name. If {@code null} the 
	 *                       claim will be removed.
	 * @param langTag        The language tag, {@code null} if not 
	 *                       specified.
	 */
	public void setBirthGivenName(final String birthGivenName, final LangTag langTag) {
		
		setClaim(BIRTH_GIVEN_NAME_CLAIM_NAME, birthGivenName, langTag);
	}
	
	
	// birth_middle_name
	
	
	/**
	 * Gets the birth middle name. Corresponds to the
	 * {@code birth_middle_name} claim from OpenID Connect for Identity
	 * Assurance 1.0, with no language tag.
	 *
	 * @return The birth middle name, {@code null} if not specified.
	 */
	public String getBirthMiddleName() {
		
		return getStringClaim(BIRTH_MIDDLE_NAME_CLAIM_NAME);
	}
	
	
	/**
	 * Gets the birth middle name. Corresponds to the 
	 * {@code birth_middle_name} claim from OpenID Connect for Identity 
	 * Assurance 1.0, with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get 
	 *                the non-tagged entry.
	 *
	 * @return The birth middle name, {@code null} if not specified.
	 */
	public String getBirthMiddleName(final LangTag langTag) {
		
		return getStringClaim(BIRTH_MIDDLE_NAME_CLAIM_NAME, langTag);
	}
	
	
	/**
	 * Gets the birth middle name entries. Correspond to the 
	 * {@code birth_middle_name} claim from OpenID Connect for Identity 
	 * Assurance 1.0.
	 *
	 * @return The birth middle name entries, empty map if none.
	 */
	public Map<LangTag,String> getBirthMiddleNameEntries() {
		
		return getLangTaggedClaim(BIRTH_MIDDLE_NAME_CLAIM_NAME, String.class);
	}
	
	
	/**
	 * Sets the birth middle name. Corresponds to the
	 * {@code birth_middle_name} claim from OpenID Connect for Identity
	 * Assurance 1.0.
	 *
	 * @param birthMiddleName The birth middle name, {@code null} if not
	 *                        specified.
	 */
	public void setBirthMiddleName(final String birthMiddleName) {
		
		setClaim(BIRTH_MIDDLE_NAME_CLAIM_NAME, birthMiddleName);
	}
	
	
	/**
	 * Sets the birth middle name. Corresponds to the 
	 * {@code birth_middle_name} claim from OpenID Connect for Identity
	 * Assurance 1.0, with an optional language tag.
	 *
	 * @param birthMiddleName The birth middle name. If {@code null} the 
	 *                        claim will be removed.
	 * @param langTag         The language tag, {@code null} if not
	 *                        specified.
	 */
	public void setBirthMiddleName(final String birthMiddleName, final LangTag langTag) {
		
		setClaim(BIRTH_MIDDLE_NAME_CLAIM_NAME, birthMiddleName, langTag);
	}
	
	
	// salutation
	
	
	/**
	 * Gets the salutation. Corresponds to the {@code salutation} claim
	 * from OpenID Connect for Identity Assurance 1.0, with no language 
	 * tag.
	 *
	 * @return The salutation, {@code null} if not specified.
	 */
	public String getSalutation() {
		
		return getStringClaim(SALUTATION_CLAIM_NAME);
	}
	
	
	/**
	 * Gets the salutation. Corresponds to the {@code salutation} claim
	 * from OpenID Connect for Identity Assurance 1.0, with an optional
	 * language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get 
	 *                the non-tagged entry.
	 *
	 * @return The salutation, {@code null} if not specified.
	 */
	public String getSalutation(final LangTag langTag) {
		
		return getStringClaim(SALUTATION_CLAIM_NAME, langTag);
	}
	
	
	/**
	 * Gets the salutation entries. Correspond to the {@code salutation}
	 * claim from OpenID Connect for Identity Assurance 1.0.
	 *
	 * @return The salutation entries, empty map if none.
	 */
	public Map<LangTag,String> getSalutationEntries() {
		
		return getLangTaggedClaim(SALUTATION_CLAIM_NAME, String.class);
	}
	
	
	/**
	 * Sets the salutation. Corresponds to the {@code salutation} claim
	 * from OpenID Connect for Identity Assurance 1.0.
	 *
	 * @param salutation The salutation, {@code null} if not specified.
	 */
	public void setSalutation(final String salutation) {
		
		setClaim(SALUTATION_CLAIM_NAME, salutation);
	}
	
	
	/**
	 * Sets the salutation. Corresponds to the {@code salutation} claim
	 * from OpenID Connect for Identity Assurance 1.0, with an optional
	 * language tag.
	 *
	 * @param salutation The salutation. If {@code null} the claim will be
	 *                   removed.
	 * @param langTag    The language tag, {@code null} if not specified.
	 */
	public void setSalutation(final String salutation, final LangTag langTag) {
		
		setClaim(SALUTATION_CLAIM_NAME, salutation, langTag);
	}
	
	
	// title
	
	
	/**
	 * Gets the title. Corresponds to the {@code title} claim from OpenID
	 * Connect for Identity Assurance 1.0, with no language tag.
	 *
	 * @return The salutation, {@code null} if not specified.
	 */
	public String getTitle() {
		
		return getStringClaim(TITLE_CLAIM_NAME);
	}
	
	
	/**
	 * Gets the title. Corresponds to the {@code title} claim from OpenID 
	 * Connect for Identity Assurance 1.0, with an optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get 
	 *                the non-tagged entry.
	 *
	 * @return The title, {@code null} if not specified.
	 */
	public String getTitle(final LangTag langTag) {
		
		return getStringClaim(TITLE_CLAIM_NAME, langTag);
	}
	
	
	/**
	 * Gets the title entries. Correspond to the {@code title} claim from 
	 * OpenID Connect for Identity Assurance 1.0.
	 *
	 * @return The title entries, empty map if none.
	 */
	public Map<LangTag,String> getTitleEntries() {
		
		return getLangTaggedClaim(TITLE_CLAIM_NAME, String.class);
	}
	
	
	/**
	 * Sets the title. Corresponds to the {@code title} claim from OpenID
	 * Connect for Identity Assurance 1.0.
	 *
	 * @param title The title, {@code null} if not specified.
	 */
	public void setTitle(final String title) {
		
		setClaim(TITLE_CLAIM_NAME, title);
	}
	
	
	/**
	 * Sets the title. Corresponds to the {@code title} claim from OpenID 
	 * Connect for Identity Assurance 1.0, with an optional language tag.
	 *
	 * @param title   The title. If {@code null} the claim will be removed.
	 * @param langTag The language tag, {@code null} if not specified.
	 */
	public void setTitle(final String title, final LangTag langTag) {
		
		setClaim(TITLE_CLAIM_NAME, title, langTag);
	}
	
	
	// msisdn
	
	
	/**
	 * Gets the mobile subscriber ISDN number. Corresponds to the
	 * {@code msisdn} claim.
	 *
	 * @return The mobile subscriber ISDN number, {@code null} if not
	 *         specified.
	 */
	public MSISDN getMSISDN() {
		
		String value = getStringClaim(MSISDN_CLAIM_NAME);
		
		if (value == null) {
			return null;
		}
		
		try {
			return MSISDN.parse(value);
		} catch (ParseException e) {
			return null;
		}
	}
	
	
	/**
	 * Sets the mobile subscriber ISDN number. Corresponds to the
	 * {@code msisdn} claim.
	 *
	 * @param msisdn The mobile subscriber ISDN number. If {@code null} the
	 *              claim will be removed.
	 */
	public void setMSISDN(final MSISDN msisdn) {
		
		String value = msisdn != null ? msisdn.getValue() : null;
		setClaim(MSISDN_CLAIM_NAME, value);
	}
	
	
	// also_known_as
	
	
	/**
	 * Gets the also known as. Corresponds to the {@code also_known_as}
	 * claim from OpenID Connect for Identity Assurance 1.0, with no
	 * language tag.
	 *
	 * @return The also_known_as, {@code null} if not specified.
	 */
	public String getAlsoKnownAs() {
		
		return getStringClaim(ALSO_KNOWN_AS);
	}
	
	
	/**
	 * Gets the also known as. Corresponds to the {@code also_known_as}
	 * claim from OpenID Connect for Identity Assurance 1.0, with an
	 * optional language tag.
	 *
	 * @param langTag The language tag of the entry, {@code null} to get
	 *                the non-tagged entry.
	 *
	 * @return The also known as, {@code null} if not specified.
	 */
	public String getAlsoKnownAs(final LangTag langTag) {
		
		return getStringClaim(ALSO_KNOWN_AS, langTag);
	}
	
	
	/**
	 * Gets the also known as entries. Correspond to the
	 * {@code also_known_as} claim from OpenID Connect for Identity
	 * Assurance 1.0.
	 *
	 * @return The also known as entries, empty map if none.
	 */
	public Map<LangTag,String> getAlsoKnownAsEntries() {
		
		return getLangTaggedClaim(ALSO_KNOWN_AS, String.class);
	}
	
	
	/**
	 * Sets the also known as. Corresponds to the {@code also_known_as}
	 * claim from OpenID Connect for Identity Assurance 1.0.
	 *
	 * @param alsoKnownAs The also known as, {@code null} if not specified.
	 */
	public void setAlsoKnownAs(final String alsoKnownAs) {
		
		setClaim(ALSO_KNOWN_AS, alsoKnownAs);
	}
	
	
	/**
	 * Sets the also known as. Corresponds to the {@code also_known_as}
	 * claim from OpenID Connect for Identity Assurance 1.0, with an
	 * optional language tag.
	 *
	 * @param alsoKnownAs The also known as. If {@code null} the claim will
	 *                    be removed.
	 * @param langTag     The language tag, {@code null} if not specified.
	 */
	public void setAlsoKnownAs(final String alsoKnownAs, final LangTag langTag) {
		
		setClaim(ALSO_KNOWN_AS, alsoKnownAs, langTag);
	}
}
