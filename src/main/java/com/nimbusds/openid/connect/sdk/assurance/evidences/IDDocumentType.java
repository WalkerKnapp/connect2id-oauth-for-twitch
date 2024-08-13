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
 * </ul>
 */
@Deprecated
@Immutable
public final class IDDocumentType extends Identifier {
	
	
	private static final long serialVersionUID = -6631671451012338520L;
	
	
	/**
	 * An identity document issued by a country's government for the
	 * purpose of identifying a citizen.
	 */
	public static final IDDocumentType IDCARD = new IDDocumentType("idcard");
	
	
	/**
	 * A passport is a travel document, usually issued by a country's
	 * government, that certifies the identity and nationality of its
	 * holder primarily for the purpose of international
	 * travel.
	 */
	public static final IDDocumentType PASSPORT = new IDDocumentType("passport");
	
	
	/**
	 * Official document permitting an individual to operate motorized
	 * vehicles. In the absence of a formal identity document, a driver's
	 * license may be accepted in many countries for identity verification.
	 */
	public static final IDDocumentType DRIVING_PERMIT = new IDDocumentType("driving_permit");
	
	
	/**
	 * ID Card issued by the German government to foreign nationals.
	 */
	public static final IDDocumentType DE_IDCARD_FOREIGNERS = new IDDocumentType("de_idcard_foreigners");
	
	
	/**
	 * ID Card issued by the German government to foreign nationals as
	 * passports replacement.
	 */
	public static final IDDocumentType DE_EMERGENCY_IDCARD = new IDDocumentType("de_emergency_idcard");
	
	
	/**
	 * Electronic Resident Permit issued by the German government to
	 * foreign nationals.
	 */
	public static final IDDocumentType DE_ERP = new IDDocumentType("de_erp");
	
	
	/**
	 * Electronic Resident Permit issued by the German government to
	 * foreign nationals as replacement for another identity document.
	 */
	public static final IDDocumentType DE_ERP_REPLACEMENT_IDCARD = new IDDocumentType("de_erp_replacement_idcard");
	
	
	/**
	 * ID Card issued by the German government to refugees as passports
	 * replacement.
	 */
	public static final IDDocumentType DE_IDCARD_REFUGEES = new IDDocumentType("de_idcard_refugees");
	
	
	/**
	 * ID Card issued by the German government to apatrids as passports
	 * replacement.
	 */
	public static final IDDocumentType DE_IDCARD_APATRIDS = new IDDocumentType("de_idcard_apatrids");
	
	
	/**
	 * Identity document issued to refugees in case of suspension of
	 * deportation that are marked as "id card replacement".
	 */
	public static final IDDocumentType DE_CERTIFICATE_OF_SUSPENSION_OF_DEPORTATION = new IDDocumentType("de_certificate_of_suspension_of_deportation");
	
	
	/**
	 * Permission to reside issued by the German government to foreign
	 * nationals applying for asylum.
	 */
	public static final IDDocumentType DE_PERMISSION_TO_RESIDE = new IDDocumentType("de_permission_to_reside");
	
	
	/**
	 * ID Card replacement document issued by the German government to
	 * foreign nationals (see Act on the Residence, Economic Activity and
	 * Integration of Foreigners in the Federal Territory, Residence Act,
	 * Appendix D1 ID Card replacement according to § 48 Abs. 2 i.V.m. §
	 * 78a Abs. 4).
	 */
	public static final IDDocumentType DE_REPLACEMENT_IDCARD = new IDDocumentType("de_replacement_idcard");
	
	
	/**
	 * Japanese drivers license.
	 */
	public static final IDDocumentType JP_DRIVERS_LICENSE = new IDDocumentType("jp_drivers_license");
	
	
	/**
	 * Japanese residence card for foreigners.
	 */
	public static final IDDocumentType JP_RESIDENCY_CARD_FOR_FOREIGNER = new IDDocumentType("jp_residency_card_for_foreigner");
	
	
	/**
	 * Japanese national ID card.
	 */
	public static final IDDocumentType JP_INDIVIDUAL_NUMBER_CARD = new IDDocumentType("jp_individual_number_card");
	
	
	/**
	 * Japanese special residency card for foreigners to permit permanent
	 * residence.
	 */
	public static final IDDocumentType JP_PERMANENT_RESIDENCY_CARD_FOR_FOREIGNER = new IDDocumentType("jp_permanent_residency_card_for_foreigner");
	
	
	/**
	 * Japanese health insurance card.
	 */
	public static final IDDocumentType JP_HEALTH_INSURANCE_CARD = new IDDocumentType("jp_health_insurance_card");
	
	
	/**
	 * Japanese residency card.
	 */
	public static final IDDocumentType JP_RESIDENCY_CARD = new IDDocumentType("jp_residency_card");
	
	
	/**
	 * Creates a new identity document type.
	 *
	 * @param value The identity document type value. Must not be
	 *              {@code null}.
	 */
	public IDDocumentType(final String value) {
		super(value);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof IDDocumentType &&
			this.toString().equals(object.toString());
	}
}

