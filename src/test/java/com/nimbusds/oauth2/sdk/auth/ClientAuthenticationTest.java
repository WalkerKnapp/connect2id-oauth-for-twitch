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

package com.nimbusds.oauth2.sdk.auth;


import java.net.URI;
import java.net.URL;
import java.security.cert.X509Certificate;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.X509CertificateGenerator;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;

import junit.framework.TestCase;


/**
 * Tests the base client authentication class.
 */
public class ClientAuthenticationTest extends TestCase {


	// See issue 141
	public void testParseClientSecretPostNullSecret()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://googleapis.com/oauth2/v3/token"));
		httpRequest.setContentType("application/x-www-form-urlencoded");
		httpRequest.setBody("code=4%2FiLoSjco7cxQJSnXBxaxaKCFGG0Au6Rm4H0ZrFV2-5jg&redirect_uri=https%3A%2F%2Fdevelopers.google.com%2Foauthplayground&client_id=407408718192.apps.googleusercontent.com&client_secret=&scope=&grant_type=authorization_code");

		ClientAuthentication auth = ClientAuthentication.parse(httpRequest);
		assertNull(auth);
	}


	public void testParseClientSecretJWTNull()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://googleapis.com/oauth2/v3/token"));
		httpRequest.setContentType("application/x-www-form-urlencoded");
		httpRequest.setBody("code=4%2FiLoSjco7cxQJSnXBxaxaKCFGG0Au6Rm4H0ZrFV2-5jg&redirect_uri=https%3A%2F%2Fdevelopers.google.com%2Foauthplayground&client_assertion_type=&client_assertion=&scope=&grant_type=authorization_code");

		ClientAuthentication auth = ClientAuthentication.parse(httpRequest);
		assertNull(auth);
	}
	
	
	public void testSelfSignedClientCertificateAuthentication_fromCertOnly()
		throws Exception {
		
		X509Certificate clientCert = X509CertificateGenerator.generateSampleClientCertificate();
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("client_id=123");
		httpRequest.setClientX509Certificate(clientCert);
		
		SelfSignedTLSClientAuthentication clientAuth = (SelfSignedTLSClientAuthentication) ClientAuthentication.parse(httpRequest);
		assertEquals(new ClientID("123"), clientAuth.getClientID());
		assertNull(clientAuth.getSSLSocketFactory());
		assertEquals(clientCert, clientAuth.getClientX509Certificate());
	}
	
	
	public void testSelfSignedClientCertificateAuthentication_withSubjectAndRootParams()
		throws Exception {
		
		X509Certificate clientCert = X509CertificateGenerator.generateSampleClientCertificate();
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("client_id=123");
		httpRequest.setClientX509Certificate(clientCert);
		httpRequest.setClientX509CertificateRootDN(clientCert.getIssuerX500Principal().getName());
		httpRequest.setClientX509CertificateSubjectDN(clientCert.getSubjectX500Principal().getName());
		
		SelfSignedTLSClientAuthentication clientAuth = (SelfSignedTLSClientAuthentication) ClientAuthentication.parse(httpRequest);
		assertEquals(new ClientID("123"), clientAuth.getClientID());
		assertNull(clientAuth.getSSLSocketFactory());
		assertEquals(clientCert, clientAuth.getClientX509Certificate());
	}
	
	
	public void testSelfSignedClientCertificateAuthentication_detectIssuerMismatch()
		throws Exception {
		
		X509Certificate clientCert = X509CertificateGenerator.generateSampleClientCertificate();
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("client_id=123");
		httpRequest.setClientX509Certificate(clientCert);
		httpRequest.setClientX509CertificateRootDN("cn=invalidIssuer");
		httpRequest.setClientX509CertificateSubjectDN(clientCert.getSubjectX500Principal().getName());
		
		try {
			ClientAuthentication.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Client X.509 certificate issuer DN doesn't match HTTP request metadata", e.getMessage());
		}
	}
	
	
	public void testSelfSignedClientCertificateAuthentication_detectSubjectMismatch()
		throws Exception {
		
		X509Certificate clientCert = X509CertificateGenerator.generateSampleClientCertificate();
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("client_id=123");
		httpRequest.setClientX509Certificate(clientCert);
		httpRequest.setClientX509CertificateRootDN(clientCert.getIssuerX500Principal().getName());
		httpRequest.setClientX509CertificateSubjectDN("cn=invalidSubject");
		
		try {
			ClientAuthentication.parse(httpRequest);
			fail();
		} catch (ParseException e) {
			assertEquals("Client X.509 certificate subject DN doesn't match HTTP request metadata", e.getMessage());
		}
	}
	
	
	public void testTLSClientCertificateAuthentication()
		throws Exception {

		X509Certificate clientCert = X509CertificateGenerator.generateSelfSignedNotSelfIssuedCertificate("issuer", "client-123");

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("client_id=123");
		httpRequest.setClientX509Certificate(clientCert);
		httpRequest.setClientX509CertificateSubjectDN(clientCert.getSubjectDN().getName());
		
		PKITLSClientAuthentication clientAuth = (PKITLSClientAuthentication) ClientAuthentication.parse(httpRequest);
		assertEquals(new ClientID("123"), clientAuth.getClientID());
		assertNull(clientAuth.getSSLSocketFactory());
		assertEquals("CN=client-123", clientAuth.getClientX509CertificateSubjectDN());
	}
	
	
	public void testClientAuthenticationNone()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setEntityContentType(ContentType.APPLICATION_URLENCODED);
		httpRequest.setBody("client_id=123");
		
		assertNull(ClientAuthentication.parse(httpRequest));
	}
	
	
	// https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/274/clientauthenticationparse-should-return-no
	public void testClientAuthenticationNone_withClientCertificate()
		throws Exception {
		
		URI endpoint = URI.create("https://c2id.com/token/introspect");
		
		X509Certificate clientCert = X509CertificateGenerator.generateSampleClientCertificate();
		AccessToken clientAuthz = new BearerAccessToken();
		AccessToken introspectedToken = new BearerAccessToken();
		
		TokenIntrospectionRequest request = new TokenIntrospectionRequest(
			endpoint,
			clientAuthz,
			introspectedToken);
		
		HTTPRequest httpRequest = request.toHTTPRequest();
		httpRequest.setClientX509Certificate(clientCert);
		
		assertNull(ClientAuthentication.parse(httpRequest));
	}
}
