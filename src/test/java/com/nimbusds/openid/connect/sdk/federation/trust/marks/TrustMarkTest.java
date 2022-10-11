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

package com.nimbusds.openid.connect.sdk.federation.trust.marks;


import java.text.ParseException;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;


public class TrustMarkTest extends TestCase {


	// https://openid.net/specs/openid-connect-federation-1_0.html#section-5.3.3
	public void testParseExample() throws ParseException, com.nimbusds.oauth2.sdk.ParseException {
		
		String jwt =
			"\"eyJhbGciOiJSUzI1NiIsImtpZCI6Ing0VnduN0RzRE1ib0dBOHRNV2pleVVjT0\"" +
			"\"RTTVBua1luSVdJN3R6eVVnRmsifQ.eyJpc3MiOiJodHRwczovL3d3dy5hZ2lkL\"" +
			"\"mdvdi5pdCIsInN1YiI6Imh0dHBzOi8vcnAuZXhhbXBsZS5pdC9zcGlkIiwiaWF\"" +
			"\"0IjoxNTc5NjIxMTYwLCJpZCI6Imh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L2Nlc\"" +
			"\"nRpZmljYXRpb24vcnAiLCJsb2dvX3VyaSI6Imh0dHBzOi8vd3d3LmFnaWQuZ29\"" +
			"\"2Lml0L3RoZW1lcy9jdXN0b20vYWdpZC9sb2dvLnN2ZyIsInJlZiI6Imh0dHBzO\"" +
			"\"i8vZG9jcy5pdGFsaWEuaXQvaXRhbGlhL3NwaWQvc3BpZC1yZWdvbGUtdGVjbml\"" +
			"\"jaGUtb2lkYy9pdC9zdGFiaWxlL2luZGV4Lmh0bWwifQ.vkYH4CZou-BhFRlZC3\"" +
			"\"eORbPbXUf9kIcqss5N5cI6GK7JsUzvxwYk5TNm8clSpV0YZtZN4RQwEf85Q_fi\"" +
			"\"FLPCPYimR-FtElWO-4Uxg44WQA1N7RbSmMNRzLfObBunMpuXcA8Trwf2d7FZ7n\"" +
			"\"Zi6mXKR8B1_YDQbLiW9q1paT-RmlrwqYyHzG9yewpIj_EQEX6WOjpWj4-Jk6sT\"" +
			"\"ZdCiu8r4d0Y7bpKt4GiGQTkVGdLyrLyMeX7FFcTI_yztKXbi8mV1-b1l7iOaJb\"" +
			"\"FyGfpHeuFCyI3y1B00LTI5GCzuQU_hyVntTnB7Qw7csLnA6B-wwaxsQa2l9-Q8\"" +
			"\"eAGXhfAlzqSqRQ\"";
		
		SignedJWT trustMark = SignedJWT.parse(jwt);
		assertEquals(JWSAlgorithm.RS256, trustMark.getHeader().getAlgorithm());
		assertEquals(new JOSEObjectType("trust-mark+jwt"), trustMark.getHeader().getType());
		assertEquals("x4Vwn7DsDMboGA8tMWjeyUcODSMPnkYnIWI7tzyUgFk", trustMark.getHeader().getKeyID());
		assertEquals(3, trustMark.getHeader().toJSONObject().size());
		
		TrustMarkClaimsSet trustMarkClaimsSet = new TrustMarkClaimsSet(trustMark.getJWTClaimsSet());
	}
}
