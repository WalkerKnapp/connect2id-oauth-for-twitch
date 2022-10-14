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


import java.net.URI;
import java.text.ParseException;

import junit.framework.TestCase;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;


public class TrustMarkTest extends TestCase {


	// https://openid.net/specs/openid-connect-federation-1_0.html#section-5.3.3
	public void testParseExample() throws ParseException, com.nimbusds.oauth2.sdk.ParseException {
		
		String jwt =
			"eyJraWQiOiJmdWtDdUtTS3hwWWJjN09lZUk3Ynlya3N5a0E1bDhPb2RFSXVyOHJ" +
			"oNFlBIiwidHlwIjoidHJ1c3QtbWFyaytqd3QiLCJhbGciOiJSUzI1NiJ9" +
			".eyJpc3MiOiJodHRwczovL3d3dy5hZ2lkLmdvdi5pdCIsInN1YiI6Imh0dHBzOi8" +
			"vcnAuZXhhbXBsZS5pdC9zcGlkIiwiaWF0IjoxNTc5NjIxMTYwLCJpZCI6Imh0d" +
			"HBzOi8vd3d3LnNwaWQuZ292Lml0L2NlcnRpZmljYXRpb24vcnAiLCJsb2dvX3V" +
			"yaSI6Imh0dHBzOi8vd3d3LmFnaWQuZ292Lml0L3RoZW1lcy9jdXN0b20vYWdpZ" +
			"C9sb2dvLnN2ZyIsInJlZiI6Imh0dHBzOi8vZG9jcy5pdGFsaWEuaXQvZG9jcy9" +
			"zcGlkLWNpZS1vaWRjLWRvY3MvaXQvdmVyc2lvbmUtY29ycmVudGUvIn0.AGf5Y" +
			"4MoJt22rznH4i7Wqpb2EF2LzE6BFEkTzY1dCBMCK-" +
			"8P_vj4Boz7335pUF45XXr2jx5_waDRgDoS5vOO-wfc0NWb4Zb_T1RCwcryrzV0" +
			"z3jJICePMPM_1hZnBZjTNQd4EsFNvKmUo_teR2yzAZjguR2Rid30O5PO8kJtGa" +
			"XDmz-" +
			"rWaHbmfLhlNGJnqcp9Lo1bhkU_4Cjpn2bdX7RN0JyfHVY5IJXwdxUMENxZd-" +
			"VtA5QYiw7kPExT53XcJO89ebe_ik4D0dl-" +
			"vINwYhrIz2RPnqgA1OdbK7jg0vm8Tb3aemRLG7oLntHwqLO-" +
			"gGYr6evM2_SgqwA0lQ9mB9yhw";
		
		SignedJWT trustMark = SignedJWT.parse(jwt);
		
		assertEquals(JWSAlgorithm.RS256, trustMark.getHeader().getAlgorithm());
		assertEquals(new JOSEObjectType("trust-mark+jwt"), trustMark.getHeader().getType());
		assertEquals("fukCuKSKxpYbc7OeeI7byrksykA5l8OodEIur8rh4YA", trustMark.getHeader().getKeyID());
		assertEquals(3, trustMark.getHeader().toJSONObject().size());
		
		TrustMarkClaimsSet trustMarkClaimsSet = new TrustMarkClaimsSet(trustMark.getJWTClaimsSet());
		assertEquals(new Issuer("https://www.agid.gov.it"), trustMarkClaimsSet.getIssuer());
		assertEquals(new Subject("https://rp.example.it/spid"), trustMarkClaimsSet.getSubject());
		assertEquals(new Identifier("https://www.spid.gov.it/certification/rp"), trustMarkClaimsSet.getID());
		assertEquals(DateUtils.fromSecondsSinceEpoch(1579621160), trustMarkClaimsSet.getIssueTime());
		assertEquals(URI.create("https://docs.italia.it/docs/spid-cie-oidc-docs/it/versione-corrente/"), trustMarkClaimsSet.getReference());
		assertEquals(URI.create("https://www.agid.gov.it/themes/custom/agid/logo.svg"), trustMarkClaimsSet.getLogoURI());
		assertEquals(6, trustMarkClaimsSet.toJSONObject().size());
	}
}
