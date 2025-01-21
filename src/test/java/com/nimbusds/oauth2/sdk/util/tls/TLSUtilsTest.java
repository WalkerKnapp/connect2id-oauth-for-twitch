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

package com.nimbusds.oauth2.sdk.util.tls;


import java.io.File;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import javax.net.ssl.SSLSocketFactory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.X509CertChainUtils;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils;


public class TLSUtilsTest {
	
	
	@Test
	public void testHTTPSRequestWithCustomTrustStore_CA()
		throws Exception {
		
		List<X509Certificate> certChain = X509CertChainUtils.parse(new File("src/test/resources/c2id-net-chain.pem"));
		
		assertEquals(3, certChain.size());
		
		certChain.remove(0); // remove site cert for c2id.net
		
		for (X509Certificate c: certChain) {
			assertNotNull(c.getSubjectDN());
		}
		
		KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
		trustStore.load(null);
		
		X509CertChainUtils.store(trustStore, certChain);
		
		SSLSocketFactory sslSocketFactory = TLSUtils.createSSLSocketFactory(trustStore);
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://c2id.net/login"));
		httpRequest.setSSLSocketFactory(sslSocketFactory);
		HTTPResponse httpResponse = httpRequest.send();
		assertEquals(200, httpResponse.getStatusCode());
	}
	
	
	@Test
	public void testHTTPSRequestWithCustomTrustStore_siteCertOnly()
		throws Exception {
		
		// PEM cert chain needs to be updated once a year
		List<X509Certificate> certChain = X509CertChainUtils.parse(new File("src/test/resources/c2id-net-chain.pem"));
		
		assertEquals(3, certChain.size());
		
		certChain.remove(1); // remove intermediate cert
		certChain.remove(1); // remove root cert
		
		for (X509Certificate c: certChain) {
			assertNotNull(c.getSubjectDN());
		}
		
		KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
		trustStore.load(null);
		
		X509CertChainUtils.store(trustStore, certChain);
		
		SSLSocketFactory sslSocketFactory = TLSUtils.createSSLSocketFactory(trustStore);
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://c2id.net/login"));
		httpRequest.setSSLSocketFactory(sslSocketFactory);
		HTTPResponse httpResponse = httpRequest.send();
		assertEquals(200, httpResponse.getStatusCode());
	}
	
	
	@Test
	public void testHTTPSRequestWithCustomKeyStore_selfSignedClientCert()
		throws Exception {
		
//		System.setProperty("javax.net.debug", "ssl,handshake");
		
		Date now = new Date();
		Date nbf = new Date(now.getTime() - 1000L);
		Date exp = new Date(now.getTime() + 3600_000L);
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048).generate();
		
		X509Certificate cert = X509CertificateUtils.generateSelfSigned(new Issuer("example.com"), nbf, exp, rsaJWK.toRSAPublicKey(), rsaJWK.toRSAPrivateKey());
		String alias = cert.getSubjectDN().getName();
		assertEquals("CN=example.com", alias);
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null);
		X509CertUtils.store(keyStore, rsaJWK.toRSAPrivateKey(), "keypassword".toCharArray(), cert);
		
		SSLSocketFactory sslSocketFactory = TLSUtils.createSSLSocketFactory(null, keyStore, "keypassword".toCharArray(), TLSVersion.TLS_1_3);
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://demo.c2id.com"));
		httpRequest.setSSLSocketFactory(sslSocketFactory);
		HTTPResponse httpResponse = httpRequest.send();
		assertEquals(200, httpResponse.getStatusCode());
	}
	
	
	@Test
	public void testHTTPSRequestWithCustomKeyStore_selfSignedClientCert_noKeyPassword()
		throws Exception {
		
//		System.setProperty("javax.net.debug", "ssl,handshake");
		
		Date now = new Date();
		Date nbf = new Date(now.getTime() - 1000L);
		Date exp = new Date(now.getTime() + 3600_000L);
		
		RSAKey rsaJWK = new RSAKeyGenerator(2048).generate();
		
		X509Certificate cert = X509CertificateUtils.generateSelfSigned(new Issuer("example.com"), nbf, exp, rsaJWK.toRSAPublicKey(), rsaJWK.toRSAPrivateKey());
		String alias = cert.getSubjectDN().getName();
		assertEquals("CN=example.com", alias);
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null);
		X509CertUtils.store(keyStore, rsaJWK.toRSAPrivateKey(), null, cert);
		
		SSLSocketFactory sslSocketFactory = TLSUtils.createSSLSocketFactory(null, keyStore, null, TLSVersion.TLS_1_3);
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://demo.c2id.com"));
		httpRequest.setSSLSocketFactory(sslSocketFactory);
		HTTPResponse httpResponse = httpRequest.send();
		assertEquals(200, httpResponse.getStatusCode());
	}
	
	
	@Test
	public void testRequest_noTrustStore_noKeyStore()
		throws Exception {
		
		SSLSocketFactory sslSocketFactory = TLSUtils.createSSLSocketFactory(null);
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://c2id.net"));
		httpRequest.setSSLSocketFactory(sslSocketFactory);
		HTTPResponse httpResponse = httpRequest.send();
		assertEquals(200, httpResponse.getStatusCode());
	}
}
