/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.federation.api;


import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.util.DateUtils;


/**
 * Resolve claims verifier.
 *
 * <p>Verifies:
 *
 * <ul>
 *     <li>The presence of the required "iss", "sub", "iat", "exp" and
 *         "metadata" claims.
 *     <li>The current time is within the "iat" and "exp" window.
 * </ul>
 */
@Immutable
public class ResolveClaimsVerifier extends DefaultJWTClaimsVerifier {
	
	
	/**
	 * Creates a new resolve claims verifier.
	 */
	public ResolveClaimsVerifier() {
		super(null, new HashSet<>(Arrays.asList("iss", "sub", "iat", "exp", "metadata")));
	}
	
	
	@Override
	public void verify(final JWTClaimsSet claimsSet, final SecurityContext context) throws BadJWTException {
		
		super.verify(claimsSet, context);
		
		// Add iat check
		Date now = new Date();
		if (! DateUtils.isBefore(claimsSet.getIssueTime(), now, getMaxClockSkew())) {
			throw new BadJWTException("JWT issue time after current time");
		}
	}
}
