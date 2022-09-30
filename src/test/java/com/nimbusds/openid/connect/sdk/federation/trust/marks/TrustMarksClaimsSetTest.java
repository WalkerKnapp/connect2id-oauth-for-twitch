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

package com.nimbusds.openid.connect.sdk.federation.trust.marks;


import java.net.URI;
import java.util.Date;

import junit.framework.TestCase;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;


public class TrustMarksClaimsSetTest extends TestCase {
	

	public void testExample_selfSignedCertificationMark()
		throws Exception {
		
		String json = "{" +
			"\"iss\": \"https://example.com/op\"," +
			"\"sub\": \"https://example.com/op\"," +
			"\"iat\": 1579621160," +
			"\"id\": \"https://openid.net/certification/op\"," +
			"\"logo_uri\": \"https://openid.net/wordpress-content/uploads/2016/05/oid-l-certification-mark-l-cmyk-150dpi-90mm.jpg\"," +
			"\"ref\": \"https://openid.net/wordpress-content/uploads/2015/09/RolandHedberg-pyoidc-0.7.7-Basic-26-Sept-2015.zip\"" +
			"}";
		
		TrustMarkClaimsSet claimsSet = new TrustMarkClaimsSet(JWTClaimsSet.parse(json));
		
		assertEquals(new Issuer("https://example.com/op"), claimsSet.getIssuer());
		assertEquals(new Subject("https://example.com/op"), claimsSet.getSubject());
		assertEquals(1579621160L, claimsSet.getIssueTime().getTime() / 1000L);
		assertEquals(new Identifier("https://openid.net/certification/op"), claimsSet.getID());
		assertEquals(new URI("https://openid.net/wordpress-content/uploads/2016/05/oid-l-certification-mark-l-cmyk-150dpi-90mm.jpg"), claimsSet.getLogoURI());
		assertEquals(new URI("https://openid.net/wordpress-content/uploads/2015/09/RolandHedberg-pyoidc-0.7.7-Basic-26-Sept-2015.zip"), claimsSet.getReference());
		assertEquals(6, claimsSet.toJSONObject().size());
	}
	

	public void testExample_cieTrustMark()
		throws Exception {
		
		String json = "{" +
			"\"id\":\"https://federation.id/openid_relying_party/public/\"," +
			"\"iss\": \"https://trust-anchor.gov.id\"," +
			"\"sub\": \"https://rp.cie.id\"," +
			"\"iat\": 1579621160," +
			"\"organization_name\": \"Organization name\"," +
			"\"policy_uri\": \"https://rp.cie.id/privacy_policy\"," +
			"\"tos_uri\": \"https://rp.cie.id/info_policy\"," +
			"\"service_documentation\": \"https://rp.cie.id/api/v1/get/services\"," +
			"\"ref\": \"https://rp.cie.id/documentation/manuale_operativo.pdf\"" +
			"}";
		
		TrustMarkClaimsSet claimsSet = new TrustMarkClaimsSet(JWTClaimsSet.parse(json));
		
		assertEquals(new Identifier("https://federation.id/openid_relying_party/public/"), claimsSet.getID());
		assertEquals(new Issuer("https://trust-anchor.gov.id"), claimsSet.getIssuer());
		assertEquals(new Subject("https://rp.cie.id"), claimsSet.getSubject());
		assertEquals(1579621160, claimsSet.getIssueTime().getTime() / 1000L);
		assertEquals("Organization name", claimsSet.getStringClaim("organization_name"));
		assertEquals(new URI("https://rp.cie.id/privacy_policy"), claimsSet.getURIClaim("policy_uri"));
		assertEquals(new URI("https://rp.cie.id/info_policy"), claimsSet.getURIClaim("tos_uri"));
		assertEquals(new URI("https://rp.cie.id/api/v1/get/services"), claimsSet.getURIClaim("service_documentation"));
		assertEquals(new URI("https://rp.cie.id/documentation/manuale_operativo.pdf"), claimsSet.getReference());
		assertEquals(9, claimsSet.toJSONObject().size());
	}
	

	public void testExample_cieUnderAgeTrustMark()
		throws Exception {
		
		String json = "{" +
			"\"id\":\"https://federation.id/openid_relying_party/private/under-age\"," +
			"\"iss\": \"https://trust-anchor.gov.id\"," +
			"\"sub\": \"https://rp.cie.id\"," +
			"\"iat\": 1579621160," +
			"\"organization_name\": \"Organization name\"," +
			"\"policy_uri\": \"https://rp.cie.id/privacy_policy\"," +
			"\"tos_uri\": \"https://rp.cie.id/info_policy\"" +
			"}";
		
		TrustMarkClaimsSet claimsSet = new TrustMarkClaimsSet(JWTClaimsSet.parse(json));
		
		assertEquals(new Identifier("https://federation.id/openid_relying_party/private/under-age"), claimsSet.getID());
		assertEquals(new Issuer("https://trust-anchor.gov.id"), claimsSet.getIssuer());
		assertEquals(new Subject("https://rp.cie.id"), claimsSet.getSubject());
		assertEquals(1579621160, claimsSet.getIssueTime().getTime() / 1000L);
		assertEquals("Organization name", claimsSet.getStringClaim("organization_name"));
		assertEquals(new URI("https://rp.cie.id/privacy_policy"), claimsSet.getURIClaim("policy_uri"));
		assertEquals(new URI("https://rp.cie.id/info_policy"), claimsSet.getURIClaim("tos_uri"));
		assertEquals(7, claimsSet.toJSONObject().size());
	}
	
	
	public void testExample_3rdPartyAccreditation()
		throws Exception {
		
		String json = "{" +
			"\"iss\": \"https://swamid.sunet.se\"," +
			"\"sub\": \"https://umu.se/op\"," +
			"\"iat\": 1577833200," +
			"\"exp\": 1609369200," +
			"\"id\": \"https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf\"" +
			"}";
		
		TrustMarkClaimsSet claimsSet = new TrustMarkClaimsSet(JWTClaimsSet.parse(json));
		
		assertEquals(new Issuer("https://swamid.sunet.se"), claimsSet.getIssuer());
		assertEquals(new Subject("https://umu.se/op"), claimsSet.getSubject());
		assertEquals(1577833200L, claimsSet.getIssueTime().getTime() / 1000);
		assertEquals(1609369200, claimsSet.getExpirationTime().getTime() / 1000);
		assertEquals(new Identifier("https://refeds.org/wp-content/uploads/2016/01/Sirtfi-1.0.pdf"), claimsSet.getID());
		assertEquals(5, claimsSet.toJSONObject().size());
	}
	
	
	public void testMinimal()
		throws Exception {
		
		Issuer iss = new Issuer("https://federation.com");
		Subject sub = new Subject("https://op.c2id.com");
		Identifier id =	new Identifier("https://federation.com/mark.jpg");
		
		long now = DateUtils.toSecondsSinceEpoch(new Date());
		Date iat = DateUtils.fromSecondsSinceEpoch(now);
		
		TrustMarkClaimsSet claimsSet = new TrustMarkClaimsSet(iss, sub, id, iat);
		
		assertEquals(iss, claimsSet.getIssuer());
		assertEquals(sub, claimsSet.getSubject());
		assertEquals(id, claimsSet.getID());
		assertEquals(iat, claimsSet.getIssueTime());
		
		JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
		
		assertEquals(iss.getValue(), jwtClaimsSet.getIssuer());
		assertEquals(sub.getValue(), jwtClaimsSet.getSubject());
		assertEquals(id.getValue(), jwtClaimsSet.getStringClaim("id"));
		assertEquals(iat, jwtClaimsSet.getIssueTime());
		
		assertEquals(4, jwtClaimsSet.getClaims().size());
		
		claimsSet = new TrustMarkClaimsSet(jwtClaimsSet);
		
		assertEquals(iss, claimsSet.getIssuer());
		assertEquals(sub, claimsSet.getSubject());
		assertEquals(id, claimsSet.getID());
		assertEquals(iat, claimsSet.getIssueTime());
	}
	
	
	public void testFullySpecified()
		throws Exception {
		
		Issuer iss = new Issuer("https://federation.com");
		Subject sub = new Subject("https://op.c2id.com");
		Identifier id =	new Identifier("https://federation.com/mark.jpg");
		URI mark = URI.create("https://federation.com/mark.jpg");
		URI ref = URI.create("https://federation/ref/123");
		
		long now = DateUtils.toSecondsSinceEpoch(new Date());
		Date iat = DateUtils.fromSecondsSinceEpoch(now);
		Date exp = DateUtils.fromSecondsSinceEpoch(now + 3600);
		
		TrustMarkClaimsSet claimsSet = new TrustMarkClaimsSet(iss, sub, id, iat);
		claimsSet.setMark(mark);
		claimsSet.setReference(ref);
		claimsSet.setExpirationTime(exp);
		
		assertEquals(iss, claimsSet.getIssuer());
		assertEquals(sub, claimsSet.getSubject());
		assertEquals(id, claimsSet.getID());
		assertEquals(iat, claimsSet.getIssueTime());
		assertEquals(mark, claimsSet.getLogoURI());
		assertEquals(exp, claimsSet.getExpirationTime());
		assertEquals(ref, claimsSet.getReference());
		
		JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
		
		assertEquals(iss.getValue(), jwtClaimsSet.getIssuer());
		assertEquals(sub.getValue(), jwtClaimsSet.getSubject());
		assertEquals(id.getValue(), jwtClaimsSet.getStringClaim("id"));
		assertEquals(iat, jwtClaimsSet.getIssueTime());
		assertEquals(mark, jwtClaimsSet.getURIClaim("logo_uri"));
		assertEquals(exp, jwtClaimsSet.getExpirationTime());
		assertEquals(ref, jwtClaimsSet.getURIClaim("ref"));
		
		assertEquals(7, jwtClaimsSet.getClaims().size());
		
		claimsSet = new TrustMarkClaimsSet(jwtClaimsSet);
		
		assertEquals(iss, claimsSet.getIssuer());
		assertEquals(sub, claimsSet.getSubject());
		assertEquals(id, claimsSet.getID());
		assertEquals(iat, claimsSet.getIssueTime());
		assertEquals(mark, claimsSet.getLogoURI());
		assertEquals(exp, claimsSet.getExpirationTime());
		assertEquals(ref, claimsSet.getReference());
	}
}
