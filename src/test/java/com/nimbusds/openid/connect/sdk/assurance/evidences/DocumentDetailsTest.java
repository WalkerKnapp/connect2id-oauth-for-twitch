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

package com.nimbusds.openid.connect.sdk.assurance.evidences;


import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.date.SimpleDate;
import com.nimbusds.openid.connect.sdk.assurance.claims.CountryCode;
import com.nimbusds.openid.connect.sdk.assurance.claims.ISO3166_1Alpha2CountryCode;
import com.nimbusds.openid.connect.sdk.claims.Address;


public class DocumentDetailsTest extends TestCase {


	public void testMinimal() throws ParseException {
		
		DocumentDetails details = new DocumentDetails(
			DocumentType.IDCARD,
			null,
			null,
			null,
			null,
			null,
			null
		);
		
		assertEquals(DocumentType.IDCARD, details.getType());
		assertNull(details.getDocumentNumber());
		assertNull(details.getPersonalNumber());
		assertNull(details.getSerialNumber());
		assertNull(details.getDateOfIssuance());
		assertNull(details.getDateOfExpiry());
		assertNull(details.getIssuer());
		
		JSONObject jsonObject = details.toJSONObject();
		
		assertEquals(DocumentType.IDCARD.getValue(), jsonObject.get("type"));
		assertEquals(1, jsonObject.size());
		
		details = DocumentDetails.parse(jsonObject);
		
		assertEquals(DocumentType.IDCARD, details.getType());
		assertNull(details.getDocumentNumber());
		assertNull(details.getPersonalNumber());
		assertNull(details.getSerialNumber());
		assertNull(details.getDateOfIssuance());
		assertNull(details.getDateOfExpiry());
		assertNull(details.getIssuer());
		
		assertEquals(details, DocumentDetails.parse(jsonObject));
		assertEquals(details.hashCode(), DocumentDetails.parse(jsonObject).hashCode());
	}
	
	
	public void testFullySet() throws ParseException {
		
		DocumentNumber documentNumber = new DocumentNumber("123");
		PersonalNumber personalNumber = new PersonalNumber("456");
		SerialNumber serialNumber = new SerialNumber("789");
		SimpleDate issueDate = new SimpleDate(2021, 12, 25);
		SimpleDate expirationDate = new SimpleDate(2031, 12, 25);
		
		Name name = new Name("Wonderland");
		Address address = new Address();
		address.setPostalCode("4000");
		CountryCode countryCode = new ISO3166_1Alpha2CountryCode("WO");
		Jurisdiction jurisdiction = new Jurisdiction("WO-WON");
		DocumentIssuer documentIssuer = new DocumentIssuer(
			name,
			address,
			countryCode,
			jurisdiction
		);
		
		DocumentDetails details = new DocumentDetails(
			DocumentType.IDCARD,
			documentNumber,
			personalNumber,
			serialNumber,
			issueDate,
			expirationDate,
			documentIssuer
		);
		
		assertEquals(DocumentType.IDCARD, details.getType());
		assertEquals(documentNumber, details.getDocumentNumber());
		assertEquals(personalNumber, details.getPersonalNumber());
		assertEquals(serialNumber, details.getSerialNumber());
		assertEquals(issueDate, details.getDateOfIssuance());
		assertEquals(expirationDate, details.getDateOfExpiry());
		assertEquals(documentIssuer, details.getIssuer());
		
		JSONObject jsonObject = details.toJSONObject();
		assertEquals(DocumentType.IDCARD.getValue(), jsonObject.get("type"));
		assertEquals(documentNumber.getValue(), jsonObject.get("document_number"));
		assertEquals(personalNumber.getValue(), jsonObject.get("personal_number"));
		assertEquals(serialNumber.getValue(), jsonObject.get("serial_number"));
		assertEquals(issueDate.toISO8601String(), jsonObject.get("date_of_issuance"));
		assertEquals(expirationDate.toISO8601String(), jsonObject.get("date_of_expiry"));
		
		JSONObject issuerObject = JSONObjectUtils.getJSONObject(jsonObject, "issuer");
		assertEquals(name.getValue(), issuerObject.get("name"));
		assertEquals(address.getPostalCode(), issuerObject.get("postal_code"));
		assertEquals(countryCode.getValue(), issuerObject.get("country_code"));
		assertEquals(jurisdiction.getValue(), issuerObject.get("jurisdiction"));
		assertEquals(4, issuerObject.size());
		
		assertEquals(7, jsonObject.size());
		
		details = DocumentDetails.parse(jsonObject);
		
		assertEquals(DocumentType.IDCARD, details.getType());
		assertEquals(documentNumber, details.getDocumentNumber());
		assertEquals(personalNumber, details.getPersonalNumber());
		assertEquals(serialNumber, details.getSerialNumber());
		assertEquals(issueDate, details.getDateOfIssuance());
		assertEquals(expirationDate, details.getDateOfExpiry());
		assertEquals(documentIssuer, details.getIssuer());
		
		assertEquals(details, DocumentDetails.parse(jsonObject));
		assertEquals(details.hashCode(), DocumentDetails.parse(jsonObject).hashCode());
	}
	
	
	public void testParse_missingRequiredType() {
		
		try {
			DocumentDetails.parse(new JSONObject());
			fail();
		} catch (ParseException e) {
			assertEquals("Missing JSON object member with key type", e.getMessage());
		}
	}
	
	
	public void testParse_requiredTypeEmpty() {
		
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("type", "");
		
		try {
			DocumentDetails.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("Empty or blank JSON object member with key type", e.getMessage());
		}
	}
}
