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


import net.jcip.annotations.Immutable;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Authentication Context Class Reference ({@code acr}). It identifies the 
 * authentication context, i.e. the information that the relying party may 
 * require before it makes an entitlements decision with respect to an 
 * authentication response. Such context may include, but is not limited to, 
 * the actual authentication method used or level of assurance such as 
 * ITU-T X.1254 | ISO/IEC 29115 entity authentication assurance level.
 *
 * <p>The ACR is represented by a string or a URI string.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 *     <li>OpenID Connect Extended Authentication Profile (EAP) ACR Values 1.0
 *     <li>RFC 6711
 *     <li>See ISO/IEC DIS 29115
 * </ul>
 */
@Immutable
public final class ACR extends Identifier {
	
	
	private static final long serialVersionUID = 7234490015365923377L;
	
	
	/**
	 * Phishing-Resistant. An authentication mechanism where a party
	 * potentially under the control of the Relying Party cannot gain
	 * sufficient information to be able to successfully authenticate to
	 * the End User's OpenID Provider as if that party were the End User.
	 * (Note that the potentially malicious Relying Party controls where
	 * the User-Agent is redirected to and thus may not send it to the End
	 * User's actual OpenID Provider). NOTE: These semantics are the same
	 * as those specified in [OpenID.PAPE].
	 */
	public static final ACR PHR = new ACR("phr");
	
	
	/**
	 * Phishing-Resistant Hardware-Protected. An authentication mechanism
	 * meeting the requirements for phishing-resistant {@link #PHR}
	 * authentication in which additionally information needed to be able
	 * to successfully authenticate to the End User's OpenID Provider as if
	 * that party were the End User is held in a hardware-protected device
	 * or component.
	 */
	public static final ACR PHRH = new ACR("phrh");
	
	
	/**
	 * Creates a new Authentication Context Class Reference (ACR) with the
	 * specified value.
	 *
	 * @param value The ACR value. Must not be {@code null}.
	 */
	public ACR(final String value) {
	
		super(value);
	}


	@Override
	public boolean equals(final Object object) {
	
		return object instanceof ACR &&
		       this.toString().equals(object.toString());
	}
}
