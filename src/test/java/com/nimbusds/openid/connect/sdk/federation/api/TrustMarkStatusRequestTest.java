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


import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.trust.marks.TrustMarkClaimsSet;


public class TrustMarkStatusRequestTest extends TestCase {
	
	private static final URI ENDPOINT = URI.create("https://tm.example.com/status");
	private static final Issuer ISSUER = new Issuer("https://tm.example.com");
	private static final Subject SUBJECT = new Subject("https://op.example.com");
	private static final Identifier ID = new Identifier("123");
	private static final Date IAT = DateUtils.fromSecondsSinceEpoch(new Date().getTime() / 1000);
	
	private static final TrustMarkClaimsSet TRUST_MARK_CLAIMS_SET = new TrustMarkClaimsSet(
		ISSUER,
		SUBJECT,
		ID,
		IAT);

	private static final SignedJWT TRUST_MARK;
	
	static {
		try {
			TRUST_MARK = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.RS256).type(new JOSEObjectType("trust-mark+jwt")).keyID("1").build(),
				TRUST_MARK_CLAIMS_SET.toJWTClaimsSet());
			TRUST_MARK.sign(new RSASSASigner(new RSAKeyGenerator(2048).generate()));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	
	public void testByTrustMarkID() throws ParseException {
	
		TrustMarkStatusRequest request = new TrustMarkStatusRequest(ENDPOINT, SUBJECT, ID, null);
		
		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(SUBJECT, request.getSubject());
		assertEquals(new EntityID(SUBJECT), request.getSubjectEntityID());
		assertEquals(ID, request.getID());
		assertNull(request.getIssueTime());
		assertNull(request.getTrustMark());
		
		Map<String, List<String>> params = request.toParameters();
		assertEquals(Collections.singletonList(SUBJECT.getValue()), params.get("sub"));
		assertEquals(Collections.singletonList(ID.getValue()), params.get("id"));
		assertEquals(2, params.size());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(ENDPOINT, httpRequest.getURI());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_URLENCODED, httpRequest.getEntityContentType());
		params = httpRequest.getQueryParameters();
		assertEquals(Collections.singletonList(SUBJECT.getValue()), params.get("sub"));
		assertEquals(Collections.singletonList(ID.getValue()), params.get("id"));
		assertEquals(2, params.size());
		
		request = TrustMarkStatusRequest.parse(httpRequest);
		assertEquals(SUBJECT, request.getSubject());
		assertEquals(new EntityID(SUBJECT), request.getSubjectEntityID());
		assertEquals(ID, request.getID());
		assertNull(request.getIssueTime());
		assertNull(request.getTrustMark());
	}
	
	
	public void testByTrustMarkID_withOptionalIssueTime() throws ParseException {
	
		TrustMarkStatusRequest request = new TrustMarkStatusRequest(ENDPOINT, SUBJECT, ID, IAT);
		
		assertEquals(ENDPOINT, request.getEndpointURI());
		assertEquals(SUBJECT, request.getSubject());
		assertEquals(new EntityID(SUBJECT), request.getSubjectEntityID());
		assertEquals(ID, request.getID());
		assertEquals(IAT, request.getIssueTime());
		assertNull(request.getTrustMark());
		
		Map<String, List<String>> params = request.toParameters();
		assertEquals(Collections.singletonList(SUBJECT.getValue()), params.get("sub"));
		assertEquals(Collections.singletonList(ID.getValue()), params.get("id"));
		assertEquals(Collections.singletonList(DateUtils.toSecondsSinceEpoch(IAT) + ""), params.get("iat"));
		assertEquals(3, params.size());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(ENDPOINT, httpRequest.getURI());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_URLENCODED, httpRequest.getEntityContentType());
		params = httpRequest.getQueryParameters();
		assertEquals(Collections.singletonList(SUBJECT.getValue()), params.get("sub"));
		assertEquals(Collections.singletonList(ID.getValue()), params.get("id"));
		assertEquals(Collections.singletonList(DateUtils.toSecondsSinceEpoch(IAT) + ""), params.get("iat"));
		assertEquals(3, params.size());
		
		request = TrustMarkStatusRequest.parse(httpRequest);
		assertEquals(SUBJECT, request.getSubject());
		assertEquals(new EntityID(SUBJECT), request.getSubjectEntityID());
		assertEquals(ID, request.getID());
		assertEquals(IAT, request.getIssueTime());
		assertNull(request.getTrustMark());
	}
	
	
	public void testByTrustMarkJWT() throws ParseException {
	
		TrustMarkStatusRequest request = new TrustMarkStatusRequest(ENDPOINT, TRUST_MARK);
		assertEquals(TRUST_MARK, request.getTrustMark());
		assertNull(request.getSubject());
		assertNull(request.getSubjectEntityID());
		assertNull(request.getID());
		assertNull(request.getIssueTime());
		
		Map<String, List<String>> params = request.toParameters();
		assertEquals(Collections.singletonList(TRUST_MARK.serialize()), params.get("trust_mark"));
		assertEquals(1, params.size());
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		assertEquals(ENDPOINT, httpRequest.getURI());
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_URLENCODED, httpRequest.getEntityContentType());
		params = httpRequest.getQueryParameters();
		assertEquals(Collections.singletonList(TRUST_MARK.serialize()), params.get("trust_mark"));
		assertEquals(1, params.size());
		
		request = TrustMarkStatusRequest.parse(httpRequest);
		assertEquals(TRUST_MARK.serialize(), request.getTrustMark().serialize());
		assertNull(request.getSubject());
		assertNull(request.getSubjectEntityID());
		assertNull(request.getID());
		assertNull(request.getIssueTime());
	}
	
	
	public void testSubjectConstructor_nullSubject() {
		
		try {
			new TrustMarkStatusRequest(ENDPOINT, null, ID, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The subject must not be null", e.getMessage());
		}
	}
	
	
	public void testSubjectConstructor_nullID() {
		
		try {
			new TrustMarkStatusRequest(ENDPOINT, SUBJECT, null, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The ID must not be null", e.getMessage());
		}
	}
	
	
	public void testTrustMarkConstructor_nullTrustMark() {
		
		try {
			new TrustMarkStatusRequest(ENDPOINT, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The trust mark must not be null", e.getMessage());
		}
	}
	
	
	public void testParse_notPOST() {
		try {
			TrustMarkStatusRequest.parse(new HTTPRequest(HTTPRequest.Method.GET, ENDPOINT));
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP request method must be POST", e.getMessage());
		}
	}
	
	
	public void testParse_missingContentType() {
		try {
			TrustMarkStatusRequest.parse(new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT));
			fail();
		} catch (ParseException e) {
			assertEquals("Missing HTTP Content-Type header", e.getMessage());
		}
	}
	
	
	public void testParse_invalidContentType() {
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT);
		httpRequest.setEntityContentType(ContentType.APPLICATION_JSON);
		httpRequest.setQuery("{}");
		try {
			TrustMarkStatusRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("The HTTP Content-Type header must be application/x-www-form-urlencoded, received application/json", e.getMessage());
		}
	}
	
	
	public void testParse_emptyQuery() {
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, ENDPOINT);
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		try {
			TrustMarkStatusRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid request: The subject must not be null", e.getMessage());
		}
	}
	
	
	public void testParse_missingID() {
		
		TrustMarkStatusRequest request = new TrustMarkStatusRequest(ENDPOINT, SUBJECT, ID, null);
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		Map<String, List<String>> params = request.toParameters();
		params.remove("id");
		httpRequest.setQuery(URLUtils.serializeParameters(params));
		
		try {
			TrustMarkStatusRequest.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid request: The ID must not be null", e.getMessage());
		}
	}
}
