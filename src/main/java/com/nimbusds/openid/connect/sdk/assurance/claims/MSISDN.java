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

package com.nimbusds.openid.connect.sdk.assurance.claims;


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.util.StringUtils;


/**
 * Mobile subscriber ISDN number.
 *
 * <p>Example where 91 is the country code, 8369 is the national destination
 * code and 110173 is the subscriber number:
 *
 * <pre>
 * 919825098250
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 *     <li>ITU-T E.164
 * </ul>
 */
@Immutable
public final class MSISDN extends Identifier {
	
	
	private static final long serialVersionUID = 6919844477369481587L;
	
	
	/**
	 * The maximum length of an MSISDN.
	 */
	public static final int MAX_LENGTH = 15;
	
	
	/**
	 * Creates a new mobile subscriber ISDN number with the specified
	 * value.
	 *
	 * @param value The MSISDN value. Must not be {@code null}.
	 */
	public MSISDN(final String value) {
		super(value);
		if (! StringUtils.isNumeric(value)) {
			throw new IllegalArgumentException("The MSISDN must be a numeric string");
		}
		if (value.length() > MAX_LENGTH) {
			throw new IllegalArgumentException("The MSISDN must not contain more than " + MAX_LENGTH + " digits");
		}
	}
	
	
	@Override
	public boolean equals(final Object object) {
		
		return object instanceof MSISDN &&
			this.toString().equals(object.toString());
	}
	
	
	/**
	 * Parses an mobile subscriber ISDN number.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The mobile subscriber ISDN number.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static MSISDN parse(final String s)
		throws ParseException {
		
		try {
			return new MSISDN(s);
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage());
		}
	}
}
