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

package com.nimbusds.oauth2.sdk;


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.PKITLSClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.SelfSignedTLSClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.TLSClientAuthentication;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.X509CertificateGenerator;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import javax.net.ssl.SSLSocketFactory;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.text.ParseException;


public class RequestObjectPOSTRequestTest extends TestCase {
	
	
	private static JWT createRequestJWT() throws JOSEException {
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048)
			.keyID("s1")
			.generate();
		
		AuthorizationRequest ar = new AuthorizationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new ClientID("123"))
			.redirectionURI(URI.create("https://example.com/cb"))
			.state(new State())
			.build();
		
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), ar.toJWTClaimsSet());
		jwt.sign(new RSASSASigner(rsaJWK));
		return jwt;
	}
	
	
	public void testJWTLifeCycle() throws Exception {
		
		JWT jwt = createRequestJWT();
		
		URI endpoint = URI.create("https://c2id.com/requests");
		RequestObjectPOSTRequest postRequest = new RequestObjectPOSTRequest(endpoint, jwt);
		assertEquals(endpoint, postRequest.getEndpointURI());
		assertNull(postRequest.getClientAuthentication());
		assertNull(postRequest.getTLSClientAuthentication());
		assertEquals(jwt, postRequest.getRequestObject());
		assertNull(postRequest.getRequestJSONObject());
		
		HTTPRequest httpRequest = postRequest.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_JWT.toString(), httpRequest.getEntityContentType().toString());
		assertEquals(jwt.serialize(), httpRequest.getQuery());
		
		postRequest = RequestObjectPOSTRequest.parse(httpRequest);
		assertEquals(endpoint, postRequest.getEndpointURI());
		assertNull(postRequest.getClientAuthentication());
		assertNull(postRequest.getTLSClientAuthentication());
		assertEquals(jwt.serialize(), postRequest.getRequestObject().serialize());
		assertNull(postRequest.getRequestJSONObject());
	}
	
	
	// Plain JSON object with self-signed mTLS
	public void testJSONObjectLifeCycle_selfSignedTLSClientAuth() throws Exception {
		
		X509Certificate clientCert = X509CertificateGenerator.generateSampleClientCertificate();
		
		JSONObject jsonObject = JSONObjectUtils.toJSONObject(createRequestJWT().getJWTClaimsSet());
		
		URI endpoint = URI.create("https://c2id.com/requests");
		TLSClientAuthentication clientAuth = new SelfSignedTLSClientAuthentication(new ClientID("123"), (SSLSocketFactory) null);
		RequestObjectPOSTRequest postRequest = new RequestObjectPOSTRequest(endpoint, clientAuth, jsonObject);
		assertEquals(endpoint, postRequest.getEndpointURI());
		assertEquals(clientAuth, postRequest.getClientAuthentication());
		assertEquals(clientAuth, postRequest.getTLSClientAuthentication());
		assertNull(postRequest.getRequestObject());
		assertEquals(jsonObject, postRequest.getRequestJSONObject());
		
		HTTPRequest httpRequest = postRequest.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_JSON.toString(), httpRequest.getEntityContentType().toString());
		assertNull(httpRequest.getClientX509Certificate());
		assertNull(httpRequest.getClientX509CertificateSubjectDN());
		assertEquals(jsonObject, httpRequest.getQueryAsJSONObject());
		
		httpRequest.setClientX509Certificate(clientCert); // simulate reverse proxy
		httpRequest.setClientX509CertificateRootDN(clientCert.getIssuerDN().getName());
		httpRequest.setClientX509CertificateSubjectDN(clientCert.getSubjectDN().getName());
		postRequest = RequestObjectPOSTRequest.parse(httpRequest);
		
		assertEquals(endpoint, postRequest.getEndpointURI());
		SelfSignedTLSClientAuthentication selfSignedTLSClientAuth = (SelfSignedTLSClientAuthentication) postRequest.getTLSClientAuthentication();
		assertEquals(clientAuth.getClientID(), selfSignedTLSClientAuth.getClientID());
		assertEquals(clientCert, selfSignedTLSClientAuth.getClientX509Certificate());
		assertNull(postRequest.getRequestObject());
		assertEquals(jsonObject, postRequest.getRequestJSONObject());
	}
	
	
	// Plain JSON object with PKI-based mTLS
	public void testJSONObjectLifeCycle_PKITLSClientAuth() throws Exception {
		
		JSONObject jsonObject = JSONObjectUtils.toJSONObject(createRequestJWT().getJWTClaimsSet());
		
		URI endpoint = URI.create("https://c2id.com/requests");
		TLSClientAuthentication clientAuth = new PKITLSClientAuthentication(new ClientID("123"), (SSLSocketFactory) null);
		RequestObjectPOSTRequest postRequest = new RequestObjectPOSTRequest(endpoint, clientAuth, jsonObject);
		assertEquals(endpoint, postRequest.getEndpointURI());
		assertEquals(clientAuth, postRequest.getClientAuthentication());
		assertEquals(clientAuth, postRequest.getTLSClientAuthentication());
		assertNull(postRequest.getRequestObject());
		assertEquals(jsonObject, postRequest.getRequestJSONObject());
		
		HTTPRequest httpRequest = postRequest.toHTTPRequest();
		assertEquals(HTTPRequest.Method.POST, httpRequest.getMethod());
		assertEquals(ContentType.APPLICATION_JSON.toString(), httpRequest.getEntityContentType().toString());
		assertNull(httpRequest.getClientX509Certificate());
		assertNull(httpRequest.getClientX509CertificateSubjectDN());
		assertEquals(jsonObject, httpRequest.getQueryAsJSONObject());
		
		httpRequest.setClientX509Certificate(X509CertificateGenerator.generateSelfSignedNotSelfIssuedCertificate(
				"issuer", "123")); // simulate reverse proxy
		postRequest = RequestObjectPOSTRequest.parse(httpRequest);
		
		assertEquals(endpoint, postRequest.getEndpointURI());
		PKITLSClientAuthentication pkiTLSClientAuth = (PKITLSClientAuthentication) postRequest.getTLSClientAuthentication();
		assertEquals(clientAuth.getClientID(), pkiTLSClientAuth.getClientID());
		assertNull(postRequest.getRequestObject());
		assertEquals(jsonObject, postRequest.getRequestJSONObject());
	}
	
	
	public void testRejectNullJWT() {
		
		try {
			new RequestObjectPOSTRequest(
				URI.create("https://c2id.com/requests"),
				null);
			
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testRejectUnsecuredJWT() throws ParseException, JOSEException {
		
		JWT jwt = createRequestJWT();
		
		try {
			new RequestObjectPOSTRequest(
				URI.create("https://c2id.com/requests"),
				new PlainJWT(jwt.getJWTClaimsSet()));
			
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The request object must not be an unsecured JWT (alg=none)", e.getMessage());
		}
	}
	
	
	public void testRejectJSONObjectWithMissingTLSClientAuth() {
		
		try {
			new RequestObjectPOSTRequest(
				URI.create("https://c2id.com/requests"),
				null,
				new JSONObject());
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
	
	
	public void testRejectNullJSONObject() {
		
		try {
			new RequestObjectPOSTRequest(
				URI.create("https://c2id.com/requests"),
				new SelfSignedTLSClientAuthentication(new ClientID("123"), (SSLSocketFactory)null),
				null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
}
