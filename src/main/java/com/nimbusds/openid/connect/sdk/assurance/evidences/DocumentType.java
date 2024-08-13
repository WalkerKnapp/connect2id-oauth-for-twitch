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

package com.nimbusds.openid.connect.sdk.assurance.evidences;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Identity document type.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 *     <li>https://bitbucket.org/openid/ekyc-ida/wiki/identifiers
 * </ul>
 */
@Immutable
public final class DocumentType extends Identifier {
	
	
	private static final long serialVersionUID = -6631671451012338520L;
	
	
	/**
	 * An identity document issued by a country's government for the
	 * purpose of identifying a citizen.
	 */
	public static final DocumentType IDCARD = new DocumentType("idcard");
	
	
	/**
	 * A passport is a travel document, usually issued by a country's
	 * government, that certifies the identity and nationality of its
	 * holder primarily for the purpose of international
	 * travel.
	 */
	public static final DocumentType PASSPORT = new DocumentType("passport");
	
	
	/**
	 * Official document permitting an individual to operate motorized
	 * vehicles. In the absence of a formal identity document, a driver's
	 * license may be accepted in many countries for identity verification.
	 */
	public static final DocumentType DRIVING_PERMIT = new DocumentType("driving_permit");
	
	
	/**
	 * Official document permitting an individual to reside within a
	 * particular jurisdiction.
	 */
	public static final DocumentType RESIDENCE_PERMIT = new DocumentType("residence_permit");
	
	
	/**
	 * ID Card issued by the German government to foreign nationals.
	 */
	public static final DocumentType DE_IDCARD_FOREIGNERS = new DocumentType("de_idcard_foreigners");
	
	
	/**
	 * ID Card issued by the German government to foreign nationals as
	 * passports replacement.
	 */
	public static final DocumentType DE_EMERGENCY_IDCARD = new DocumentType("de_emergency_idcard");
	
	
	/**
	 * Electronic Resident Permit issued by the German government to
	 * foreign nationals.
	 */
	public static final DocumentType DE_ERP = new DocumentType("de_erp");
	
	
	/**
	 * Electronic Resident Permit issued by the German government to
	 * foreign nationals as replacement for another identity document.
	 */
	public static final DocumentType DE_ERP_REPLACEMENT_IDCARD = new DocumentType("de_erp_replacement_idcard");
	
	
	/**
	 * ID Card issued by the German government to refugees as passports
	 * replacement.
	 */
	public static final DocumentType DE_IDCARD_REFUGEES = new DocumentType("de_idcard_refugees");
	
	
	/**
	 * ID Card issued by the German government to apatrids as passports
	 * replacement.
	 */
	public static final DocumentType DE_IDCARD_APATRIDS = new DocumentType("de_idcard_apatrids");
	
	
	/**
	 * Identity document issued by the German government to refugees in
	 * case of suspension of deportation that are marked as "ID Card
	 * replacement".
	 */
	public static final DocumentType DE_CERTIFICATE_OF_SUSPENSION_OF_DEPORTATION = new DocumentType("de_certificate_of_suspension_of_deportation");
	
	
	/**
	 * Permission to reside issued by the German government to foreign
	 * nationals applying for asylum.
	 */
	public static final DocumentType DE_PERMISSION_TO_RESIDE = new DocumentType("de_permission_to_reside");
	
	
	/**
	 * ID Card replacement document issued by the German government to
	 * foreign nationals (see Act on the Residence, Economic Activity and
	 * Integration of Foreigners in the Federal Territory, Residence Act,
	 * Appendix D1 ID Card replacement according to § 48 Abs. 2 i.V.m. §
	 * 78a Abs. 4).
	 */
	public static final DocumentType DE_REPLACEMENT_IDCARD = new DocumentType("de_replacement_idcard");
	
	
	/**
	 * Japanese drivers license.
	 */
	public static final DocumentType JP_DRIVERS_LICENSE = new DocumentType("jp_drivers_license");
	
	
	/**
	 * Japanese residence card for foreigners.
	 */
	public static final DocumentType JP_RESIDENCY_CARD_FOR_FOREIGNER = new DocumentType("jp_residency_card_for_foreigner");
	
	
	/**
	 * Japanese national ID card.
	 */
	public static final DocumentType JP_INDIVIDUAL_NUMBER_CARD = new DocumentType("jp_individual_number_card");
	
	
	/**
	 * Japanese special residency card for foreigners to permit permanent
	 * residence.
	 */
	public static final DocumentType JP_PERMANENT_RESIDENCY_CARD_FOR_FOREIGNER = new DocumentType("jp_permanent_residency_card_for_foreigner");
	
	
	/**
	 * Japanese health insurance card.
	 */
	public static final DocumentType JP_HEALTH_INSURANCE_CARD = new DocumentType("jp_health_insurance_card");
	
	
	/**
	 * Japanese residency card.
	 */
	public static final DocumentType JP_RESIDENCY_CARD = new DocumentType("jp_residency_card");
	
	
	/**
	 * Bank statement from a recognised banking institution.
	 */
	public static final DocumentType BANK_STATEMENT = new DocumentType("bank_statement");
	
	
	/**
	 * Statement from a recognised utility provider.
	 */
	public static final DocumentType UTILITY_STATEMENT = new DocumentType("utility_statement");
	
	
	/**
	 * Statement from a recognised mortgage provider.
	 */
	public static final DocumentType MORTGAGE_STATEMENT = new DocumentType("mortgage_statement");
	
	
	/**
	 * Statement from a recognised loan provider.
	 */
	public static final DocumentType LOAN_STATEMENT = new DocumentType("loan_statement");
	
	
	/**
	 * Statement from a country's tax authority.
	 */
	public static final DocumentType TAX_STATEMENT = new DocumentType("tax_statement");
	
	
	/**
	 * Statement from a country's social security authority.
	 */
	public static final DocumentType SOCIAL_SECURITY_STATEMENT = new DocumentType("social_security_statement");
	
	
	/**
	 * Official document permitting an individual to operate an aircraft.
	 */
	public static final DocumentType PILOT_PERMIT = new DocumentType("pilot_permit");
	
	
	/**
	 * Official document certifying the circumstances of a birth.
	 */
	public static final DocumentType BIRTH_CERTIFICATE = new DocumentType("birth_certificate");
	
	
	/**
	 * Official document certifying the circumstances of an adoption.
	 */
	public static final DocumentType ADOPTION_CERTIFICATE = new DocumentType("adoption_certificate");
	
	
	/**
	 * Official document certifying the circumstances of a marriage.
	 */
	public static final DocumentType MARRIAGE_CERTIFICATE = new DocumentType("marriage_certificate");
	
	
	/**
	 * Official document certifying that a person has satisfied the criteria for legal recognition in the acquired gender.
	 */
	public static final DocumentType GENDER_CERTIFICATE = new DocumentType("gender_certificate");
	
	
	/**
	 * Official document permitting an individual to use or own a firearm.
	 */
	public static final DocumentType FIREARM_PERMIT = new DocumentType("firearm_permit");
	
	
	/**
	 * Document certifying that a person has received specific education or has passed a test or series of tests.
	 */
	public static final DocumentType EDUCATION_CERTIFICATE = new DocumentType("education_certificate");
	
	
	/**
	 * Document that grants the holder official permission to enter, leave
	 * or stay in a country.
	 */
	public static final DocumentType VISA = new DocumentType("visa");
	
	
	/**
	 *An official military identity document issued by a country's government to its service personnel.
	 */
	public static final DocumentType MILITARY_ID = new DocumentType("military_id");
	
	
	/**
	 * An official voter identity document.
	 */
	public static final DocumentType VOTER_ID = new DocumentType("voter_id");
	
	
	/**
	 * Creates a new identity document type.
	 *
	 * @param value The identity document type value. Must not be
	 *              {@code null}.
	 */
	public DocumentType(final String value) {
		super(value);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof DocumentType &&
			this.toString().equals(object.toString());
	}
}
