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

package com.nimbusds.oauth2.sdk.device;


import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import net.jcip.annotations.Immutable;

import java.util.*;


/**
 * Device code grant for the OAuth 2.0 Device Authorization Grant.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Device Authorization Grant (RFC 8628)
 * </ul>
 */
@Immutable
public class DeviceCodeGrant extends AuthorizationGrant {

	
	/**
	 * The grant type.
	 */
	public static final GrantType GRANT_TYPE = GrantType.DEVICE_CODE;


	/**
	 * The device code received from the authorisation server.
	 */
	private final DeviceCode deviceCode;


	/**
	 * Creates a new device code grant.
	 * 
	 * @param deviceCode The device code. Must not be {@code null}.
	 */
	public DeviceCodeGrant(final DeviceCode deviceCode) {

		super(GRANT_TYPE);
		this.deviceCode = Objects.requireNonNull(deviceCode);
	}


	/**
	 * Returns the device code received from the authorisation server.
	 * 
	 * @return The device code received from the authorisation server.
	 */
	public DeviceCode getDeviceCode() {

		return deviceCode;
	}


	@Override
	public Map<String, List<String>> toParameters() {

		Map<String, List<String>> params = new LinkedHashMap<>();
		params.put("grant_type", Collections.singletonList(GRANT_TYPE.getValue()));
		params.put("device_code", Collections.singletonList(deviceCode.getValue()));
		return params;
	}


	/**
	 * Parses a device code grant from the specified request body
	 * parameters.
	 *
	 * <p>Example:
	 *
	 * <pre>
	 * grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code
	 * &amp;device_code=GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS
	 * </pre>
	 *
	 * @param params The parameters.
	 *
	 * @return The device code grant.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static DeviceCodeGrant parse(final Map<String, List<String>> params) throws ParseException {
		
		GrantType.ensure(GRANT_TYPE, params);
		
		String deviceCodeString = MultivaluedMapUtils.getFirstValue(params, "device_code");

		if (deviceCodeString == null || deviceCodeString.trim().isEmpty()) {
			String msg = "Missing or empty device_code parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
		}

		DeviceCode deviceCode = new DeviceCode(deviceCodeString);

		return new DeviceCodeGrant(deviceCode);
	}


	@Override
	public boolean equals(Object o) {

		if (this == o)
			return true;
		if (!(o instanceof DeviceCodeGrant))
			return false;

		DeviceCodeGrant deviceCodeGrant = (DeviceCodeGrant) o;
		return deviceCode.equals(deviceCodeGrant.deviceCode);
	}


	@Override
	public int hashCode() {

		return deviceCode.hashCode();
	}
}
