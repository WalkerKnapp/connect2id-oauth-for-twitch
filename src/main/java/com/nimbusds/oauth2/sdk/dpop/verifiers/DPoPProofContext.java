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

package com.nimbusds.oauth2.sdk.dpop.verifiers;


import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;

import java.util.Objects;


/**
 * DPoP proof JWT verification context.
 */
class DPoPProofContext implements SecurityContext {
	
	
	/**
	 * The DPoP issuer.
	 */
	private final DPoPIssuer issuer;
	
	
	/**
	 * The "ath" (access token hash) claim, {@code null} if not applicable.
	 */
	private Base64URL ath;
	
	
	/**
	 * Creates a new DPoP proof JWT verification context.
	 *  @param issuer The DPoP proof issuer. Must not be {@code null}.
	 *
	 */
	public DPoPProofContext(final DPoPIssuer issuer) {
		this.issuer = Objects.requireNonNull(issuer);
	}
	
	
	/**
	 * Returns the DPoP proof issuer.
	 *
	 * @return The DPoP proof issuer.
	 */
	public DPoPIssuer getIssuer() {
		return issuer;
	}
	
	
	/**
	 * Sets the "ath" "ath" (access token hash) claim.
	 *
	 * @param ath The "ath" claim, {@code null} if not applicable.
	 */
	public void setAccessTokenHash(final Base64URL ath) {
		this.ath = ath;
	}
	
	
	/**
	 * Gets the "ath" "ath" (access token hash) claim.
	 *
	 * @return The "ath" claim, {@code null} if not applicable.
	 */
	public Base64URL getAccessTokenHash() {
		return ath;
	}
}
