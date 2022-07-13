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

package com.nimbusds.openid.connect.sdk.assurance.claims;


import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.StringUtils;


/**
 * ISO 3166-3 country code for former countries and territories.
 */
@Immutable
public final class ISO3166_3CountryCode extends CountryCode {
	
	
	private static final long serialVersionUID = 614967184722743546L;
	
	
	/** British Antarctic Territory */
	public static final ISO3166_3CountryCode BQAQ = new ISO3166_3CountryCode("BQAQ");
	
	/** Burma */
	public static final ISO3166_3CountryCode BUMM = new ISO3166_3CountryCode("BUMM");
	
	/** Byelorussian SSR */
	public static final ISO3166_3CountryCode BYAA = new ISO3166_3CountryCode("BYAA");
	
	/** Canton and Enderbury Islands */
	public static final ISO3166_3CountryCode CTKI = new ISO3166_3CountryCode("CTKI");
	
	/** Czechoslovakia */
	public static final ISO3166_3CountryCode CSHH = new ISO3166_3CountryCode("CSHH");
	
	/** Dahomey */
	public static final ISO3166_3CountryCode DYBJ = new ISO3166_3CountryCode("DYBJ");
	
	/** Dronning Maud Land */
	public static final ISO3166_3CountryCode NQAQ = new ISO3166_3CountryCode("NQAQ");
	
	/** East Timor */
	public static final ISO3166_3CountryCode TPTL = new ISO3166_3CountryCode("TPTL");
	
	/** France, Metropolitan */
	public static final ISO3166_3CountryCode FXFR = new ISO3166_3CountryCode("FXFR");
	
	/** French Afars and Issas */
	public static final ISO3166_3CountryCode AIDJ = new ISO3166_3CountryCode("AIDJ");
	
	/** French Southern and Antarctic Territories */
	public static final ISO3166_3CountryCode FQHH = new ISO3166_3CountryCode("FQHH");
	
	/** German Democratic Republic */
	public static final ISO3166_3CountryCode DDDE = new ISO3166_3CountryCode("DDDE");
	
	/** Gilbert Islands */
	public static final ISO3166_3CountryCode GEHH = new ISO3166_3CountryCode("GEHH");
	
	/** Johnston Island */
	public static final ISO3166_3CountryCode JTUM = new ISO3166_3CountryCode("JTUM");
	
	/** Midway Islands */
	public static final ISO3166_3CountryCode MIUM = new ISO3166_3CountryCode("MIUM");
	
	/** Netherlands Antilles */
	public static final ISO3166_3CountryCode ANHH = new ISO3166_3CountryCode("ANHH");
	
	/** Neutral Zone */
	public static final ISO3166_3CountryCode NTHH = new ISO3166_3CountryCode("NTHH");
	
	/** New Hebrides */
	public static final ISO3166_3CountryCode NHVU = new ISO3166_3CountryCode("NHVU");
	
	/** Pacific Islands (Trust Territory) */
	public static final ISO3166_3CountryCode PCHH = new ISO3166_3CountryCode("PCHH");
	
	/** Panama Canal Zone */
	public static final ISO3166_3CountryCode PZPA = new ISO3166_3CountryCode("PZPA");
	
	/** Serbia and Montenegro */
	public static final ISO3166_3CountryCode CSXX = new ISO3166_3CountryCode("CSXX");
	
	/** Sikkim */
	public static final ISO3166_3CountryCode SKIN = new ISO3166_3CountryCode("SKIN");
	
	/** Southern Rhodesia */
	public static final ISO3166_3CountryCode RHZW = new ISO3166_3CountryCode("RHZW");
	
	/** United States Miscellaneous Pacific Islands */
	public static final ISO3166_3CountryCode PUUM = new ISO3166_3CountryCode("PUUM");
	
	/** Upper Volta */
	public static final ISO3166_3CountryCode HVBF = new ISO3166_3CountryCode("HVBF");
	
	/** USSR */
	public static final ISO3166_3CountryCode SUHH = new ISO3166_3CountryCode("SUHH");
	
	/** Viet-Nam, Democratic Republic of */
	public static final ISO3166_3CountryCode VDVN = new ISO3166_3CountryCode("VDVN");
	
	/** Wake Island */
	public static final ISO3166_3CountryCode WKUM = new ISO3166_3CountryCode("WKUM");
	
	/** Yemen, Democratic */
	public static final ISO3166_3CountryCode YDYE = new ISO3166_3CountryCode("YDYE");
	
	/** Yugoslavia */
	public static final ISO3166_3CountryCode YUCS = new ISO3166_3CountryCode("YUCS");
	
	/** Zaire */
	public static final ISO3166_3CountryCode ZRCD  = new ISO3166_3CountryCode("ZRCD");
	
	
	/**
	 * Creates a new ISO 3166-3 country code. Normalises the code to upper
	 * case.
	 *
	 * @param value The country code value, must be four-letter.
	 */
	public ISO3166_3CountryCode(final String value) {
		super(value.toUpperCase());
		if (value.length() != 4 || !StringUtils.isAlpha(value)) {
			throw new IllegalArgumentException("The ISO 3166-3 country code must be 4 letters");
		}
	}
	
	
	/**
	 * Returns the former country code (the first component).
	 *
	 * @return The former country code as an ISO 3166-1 alpha-2
	 *         (two-letter) country code.
	 */
	public ISO3166_1Alpha2CountryCode getFormerCode() {
		
		return new ISO3166_1Alpha2CountryCode(getFirstComponentString());
	}
	
	
	/**
	 * Returns the new country code (the second component), unless the
	 * former country is divided and there is no single successor country
	 * (indicated by an "HH" or "XX" code).
	 *
	 * @return The new country code as an ISO 3166-1 alpha-2 (two-letter)
	 *         country code, {@code null} if the former country is divided.
	 *         and there is no single successor country.
	 */
	public ISO3166_1Alpha2CountryCode getNewCode() {
		
		if ("HH".equals(getSecondComponentString()) || "XX".equals(getSecondComponentString())) {
			return null;
		}
		
		return new ISO3166_1Alpha2CountryCode(getSecondComponentString());
	}
	
	
	/**
	 * Returns the first component (the first two letters) representing the
	 * former country code.
	 *
	 * @return The first component as a string.
	 */
	public String getFirstComponentString() {
		
		return getValue().substring(0, 2);
	}
	
	
	/**
	 * Returns the second component (the last two letters).
	 *
	 * @return The second component as a string.
	 */
	public String getSecondComponentString() {
		
		return getValue().substring(2, 4);
	}
	
	
	/**
	 * The {@code iso3166_3-codes.properties} resource.
	 */
	private static final Properties CODES_RESOURCE = new Properties();
	
	
	/**
	 * Returns the country name if available in the
	 * {@code iso3166_3-codes.properties} resource.
	 *
	 * @return The country name, {@code null} if not available.
	 */
	public String getCountryName() {
		
		if (CODES_RESOURCE.isEmpty()) {
			try (InputStream is = getClass().getClassLoader().getResourceAsStream("iso3166_3-codes.properties")) {
				CODES_RESOURCE.load(is);
			} catch (IOException e) {
				return null;
			}
		}
		
		return CODES_RESOURCE.getProperty(getValue());
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof ISO3166_3CountryCode &&
			this.toString().equals(object.toString());
	}
	
	
	/**
	 * Parses an ISO 3166-3 country code.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The ISO 3166-3 country code.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static ISO3166_3CountryCode parse(final String s)
		throws ParseException {
		
		try {
			return new ISO3166_3CountryCode(s);
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage());
		}
	}
}
