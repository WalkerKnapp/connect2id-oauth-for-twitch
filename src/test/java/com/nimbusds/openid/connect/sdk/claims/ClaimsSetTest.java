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


import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;


public class ClaimsSetTest extends TestCase {
	
	
	public void testAudienceList() throws ParseException {
		
		ClaimsSet claimsSet = new ClaimsSet();
		
		assertNull(claimsSet.getAudience());
		
		List<Audience> audienceList = new Audience("123").toSingleAudienceList();
		claimsSet.setAudience(audienceList);
		assertEquals(audienceList, claimsSet.getAudience());
		
		JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
		assertEquals(Collections.singletonList("123"), jwtClaimsSet.getAudience());
		assertEquals(1, jwtClaimsSet.getClaims().size());
	}
	
	
	public void testDateHandling()
		throws ParseException {
		
		ClaimsSet claimsSet = new ClaimsSet();
		assertNull(claimsSet.getDateClaim("exp"));
		
		Date exp = new Date();
		claimsSet.setDateClaim("exp", exp);
		
		Date expWithSecondPrecision = DateUtils.fromSecondsSinceEpoch(DateUtils.toSecondsSinceEpoch(exp));
		assertEquals(expWithSecondPrecision, claimsSet.getDateClaim("exp"));
		
		JSONObject jsonObject = claimsSet.toJSONObject();
		assertEquals(DateUtils.toSecondsSinceEpoch(exp), JSONObjectUtils.getLong(jsonObject, "exp"));
		
		JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
		assertEquals(expWithSecondPrecision, jwtClaimsSet.getExpirationTime());
		
		ClaimsSet newClaimsSet = new ClaimsSet(jsonObject);
		assertEquals(expWithSecondPrecision, newClaimsSet.getDateClaim("exp"));
	}
	
	
	public void testGetJSONArrayClaim() {
		
		JSONArray jsonArray = new JSONArray();
		jsonArray.add("a");
		jsonArray.add("b");
		jsonArray.add("c");
		
		ClaimsSet claimsSet = new ClaimsSet();
		claimsSet.setClaim("array", jsonArray);
		
		assertEquals(jsonArray, claimsSet.getJSONArrayClaim("array"));
		
		Map<String, Object> o = claimsSet.toJSONObject();
		assertEquals(jsonArray, o.get("array"));
		
		claimsSet = new ClaimsSet(new JSONObject(o));
		assertEquals(jsonArray, claimsSet.getJSONArrayClaim("array"));
	}
	
	
	public void testGetJSONArrayClaim_viaJWTClaimsSet() throws ParseException {
		
		JSONArray jsonArray = new JSONArray();
		jsonArray.add("a");
		jsonArray.add("b");
		jsonArray.add("c");
		
		ClaimsSet claimsSet = new ClaimsSet();
		claimsSet.setClaim("array", jsonArray);
		
		assertEquals(jsonArray, claimsSet.getJSONArrayClaim("array"));
		
		JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
		assertEquals(jsonArray, jwtClaimsSet.getClaim("array"));
		
		claimsSet = new ClaimsSet(new JSONObject(jwtClaimsSet.toJSONObject()));
		assertEquals(jsonArray, claimsSet.getJSONArrayClaim("array"));
	}
	
	
	public void testEquality_empty() {
		
		assertEquals(new ClaimsSet(), new ClaimsSet());
		assertEquals(new ClaimsSet().hashCode(), new ClaimsSet().hashCode());
	}
	
	
	public void testEquality_set() {
		
		ClaimsSet a = new ClaimsSet();
		a.setIssuer(new Issuer("https://c2id.com"));
		a.setClaim("name", "Alice");
		
		ClaimsSet b = new ClaimsSet();
		b.setIssuer(new Issuer("https://c2id.com"));
		b.setClaim("name", "Alice");
		
		assertEquals(a, b);
		assertEquals(a.hashCode(), b.hashCode());
	}
	
	
	public void testInequality() {
		
		ClaimsSet a = new ClaimsSet();
		a.setIssuer(new Issuer("https://c2id.com"));
		a.setClaim("name", "Alice");
		
		ClaimsSet b = new ClaimsSet();
		b.setIssuer(new Issuer("https://idp.example.com"));
		b.setClaim("name", "Bob");
		
		assertNotSame(a, b);
		assertNotSame(a.hashCode(), b.hashCode());
	}
}
