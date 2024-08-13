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

package com.nimbusds.openid.connect.sdk.assurance.evidences.attachment;


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.StringUtils;


/**
 * Evidence attachment type.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0
 * </ul>
 */
public enum AttachmentType {
	
	
	/**
	 * Embedded attachment.
	 */
	EMBEDDED,
	
	
	/**
	 * External attachment.
	 */
	EXTERNAL;
	
	
	@Override
	public String toString() {
		return name().toLowerCase();
	}
	
	
	/**
	 * Parses an attachment type from the specified string.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The attachment type.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static AttachmentType parse(final String s)
		throws ParseException {
		
		if (StringUtils.isBlank(s)) {
			throw new ParseException("Null or blank attachment type");
		}
		
		if (EMBEDDED.name().equalsIgnoreCase(s)) {
			return EMBEDDED;
		} else if (EXTERNAL.name().equalsIgnoreCase(s)) {
			return EXTERNAL;
		} else {
			throw new ParseException("Invalid attachment type: " + s);
		}
	}
}
