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


import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.StringUtils;


/**
 * Enumeration of the display types for authentication and consent UIs.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 * </ul>
 */
public enum Display {


	/**
	 * Full user-agent page view (default).
	 */
	PAGE,
	
	
	/**
	 * Popup user-agent window. The popup User Agent window should be of an
	 * appropriate size for a login-focused dialog and should not obscure
	 * the entire window that it is popping up over.
	 */
	POPUP,
	
	
	/**
	 * Device that leverages a touch interface. The authorisation server 
	 * may attempt to detect the touch device and further customise the 
	 * interface.
	 */
	TOUCH,
	
	
	/**
	 * Feature phone.
	 */
	WAP;


	/**
	 * Gets the default display type.
	 *
	 * @return The default display type ({@link #PAGE}).
	 */
	public static Display getDefault() {
	
		return PAGE;
	}
	
	
	/**
	 * Returns the string identifier of this display type.
	 *
	 * @return The string identifier.
	 */
	@Override
	public String toString() {
	
		return super.toString().toLowerCase();
	}
	
	
	/**
	 * Parses a display type.
	 *
	 * @param s The string to parse. If the string is {@code null} or empty
	 *          the {@link #getDefault} display type will be returned.
	 *
	 * @return The display type.
	 *
	 * @throws ParseException If the parsed string doesn't match a display 
	 *                        type.
	 */
	public static Display parse(final String s)
		throws ParseException {
	
		if (StringUtils.isBlank(s))
			return getDefault();
		
		if (s.equals("page"))
			return PAGE;
			
		if (s.equals("popup"))
			return POPUP;
			
		if (s.equals("touch"))
			return TOUCH;
			
		if (s.equals("wap"))
			return WAP;
			
		throw new ParseException("Unknown display type");
	}
}
