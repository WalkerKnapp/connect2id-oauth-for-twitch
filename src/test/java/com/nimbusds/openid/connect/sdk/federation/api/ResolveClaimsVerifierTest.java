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

package com.nimbusds.openid.connect.sdk.federation.api;


import java.util.Arrays;
import java.util.HashSet;

import junit.framework.TestCase;


public class ResolveClaimsVerifierTest  extends TestCase {


	public void testConfig() {
		
		ResolveClaimsVerifier verifier = new ResolveClaimsVerifier();
		assertEquals(new HashSet<>(Arrays.asList("iss", "sub", "iat", "exp", "metadata")), verifier.getRequiredClaims());
		assertTrue(verifier.getExactMatchClaims().toJSONObject().isEmpty());
		assertTrue(verifier.getProhibitedClaims().isEmpty());
		assertNull(verifier.getAcceptedAudienceValues());
	}
}
