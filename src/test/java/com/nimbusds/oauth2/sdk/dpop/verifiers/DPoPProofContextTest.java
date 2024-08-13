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


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.dpop.DPoPUtils;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import junit.framework.TestCase;


public class DPoPProofContextTest extends TestCase {
	
	
	public void testConstructor() {
		
		DPoPIssuer issuer = new DPoPIssuer("123");
		DPoPProofContext context = new DPoPProofContext(issuer);
		assertEquals(issuer, context.getIssuer());
		assertNull(context.getAccessTokenHash());
	}
	
	
	public void testConstructorWithAccessToken() throws JOSEException {
		
		DPoPIssuer issuer = new DPoPIssuer("123");
		AccessToken accessToken = new DPoPAccessToken("iat5luciwooSa8Ogh5eweicahG8soo8a");
		Base64URL ath = DPoPUtils.computeSHA256(accessToken);
		DPoPProofContext context = new DPoPProofContext(issuer);
		assertEquals(issuer, context.getIssuer());
		assertNull(context.getAccessTokenHash());
		context.setAccessTokenHash(ath);
		assertEquals(ath, context.getAccessTokenHash());
	}
	
	
	public void testConstructor_rejectNullIssuer() {
		
		NullPointerException exception = null;
		try {
			new DPoPProofContext(null);
			fail();
		} catch (NullPointerException e) {
			exception = e;
		}
		assertNull(exception.getMessage());
	}
}
