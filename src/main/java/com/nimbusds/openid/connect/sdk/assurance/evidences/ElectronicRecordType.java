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
 * Electronic record type.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 *     <li>https://bitbucket.org/openid/ekyc-ida/wiki/identifiers
 * </ul>
 */
@Immutable
public final class ElectronicRecordType extends Identifier {
	
	
	private static final long serialVersionUID = -3135412141332663342L;
	
	
	/**
	 * A record from an official register of births.
	 */
	public static final ElectronicRecordType BIRTH_REGISTER = new ElectronicRecordType("birth_register");
	
	
	/**
	 * A record from an official population register.
 	 */
	public static final ElectronicRecordType POPULATION_REGISTER = new ElectronicRecordType("population_register");
	
	
	/**
	 * A record from an official register of voters.
 	 */
	public static final ElectronicRecordType VOTER_REGISTER = new ElectronicRecordType("voter_register");
	
	
	/**
	 * A record from an official register of adoptions.
	 */
	public static final ElectronicRecordType ADOPTION_REGISTER = new ElectronicRecordType("adoption_register");
	
	
	/**
	 * A record from an official register of marriages.
 	 */
	public static final ElectronicRecordType MARRIAGE_REGISTER = new ElectronicRecordType("marriage_register");
	
	
	/**
	 * An authoritative record of a person having received specific
	 * education or has passed a test or series of tests.
 	 */
	public static final ElectronicRecordType EDUCATION = new ElectronicRecordType("education");
	
	
	/**
	 * A military personnel record.
	 */
	public static final ElectronicRecordType MILITARY = new ElectronicRecordType("military");
	
	
	/**
	 * A record of a bank account from a recognized banking institution.
	 */
	public static final ElectronicRecordType BANK_ACCOUNT = new ElectronicRecordType("bank_account");
	
	
	/**
	 * A record of an account from a recognised utility provider.
	 */
	public static final ElectronicRecordType UTILITY_ACCOUNT = new ElectronicRecordType("utility_account");
	
	
	/**
	 * A record of a mortgage from a recognized mortgage provider.
	 */
	public static final ElectronicRecordType MORTGAGE_ACCOUNT = new ElectronicRecordType("mortgage_account");
	
	
	/**
	 * A record of a loan from a recognised loan provider.
	 */
	public static final ElectronicRecordType LOAN_ACCOUNT = new ElectronicRecordType("loan_account");
	
	
	/**
	 * A record from a country's tax authority.
	 */
	public static final ElectronicRecordType TAX = new ElectronicRecordType("tax");
	
	
	/**
	 * A record from a country's social security authority.
	 */
	public static final ElectronicRecordType SOCIAL_SECURITY = new ElectronicRecordType("social_security");
	
	
	/**
	 * A record from an institution or authority for the confinement of
	 * persons who have been deprived of their liberty following a criminal
	 * conviction by a judicial process.
	 */
	public static final ElectronicRecordType PRISON_RECORD = new ElectronicRecordType("prison_record");
	
	
	/**
	 * Creates a new electronic record type.
	 *
	 * @param value The electronic record type value. Must not be
	 *              {@code null}.
	 */
	public ElectronicRecordType(final String value) {
		super(value);
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof ElectronicRecordType &&
			this.toString().equals(object.toString());
	}
}
