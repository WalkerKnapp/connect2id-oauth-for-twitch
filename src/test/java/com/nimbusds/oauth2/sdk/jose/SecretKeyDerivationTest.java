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

package com.nimbusds.oauth2.sdk.jose;


import java.math.BigInteger;
import javax.crypto.SecretKey;

import static org.junit.Assert.assertArrayEquals;

import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.oauth2.sdk.auth.Secret;


public class SecretKeyDerivationTest extends TestCase {
	
	
	private static final Secret CLIENT_SECRET = new Secret(ByteUtils.byteLength(256));
	
	
	public void testDerive_dir_A128GCM()
		throws Exception {
		
		SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.DIR, EncryptionMethod.A128GCM);
		
		assertEquals("AES", key.getAlgorithm());
		assertArrayEquals(ByteUtils.subArray(CLIENT_SECRET.getSHA256(), 0, 128 / 8), key.getEncoded());
		assertEquals(ByteUtils.byteLength(128), key.getEncoded().length);
		
		JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM), new Payload("Hello, world!"));
		jwe.encrypt(new DirectEncrypter(key));
	}
	
	
	public void testDerive_dir_A192GCM()
		throws Exception {
		
		SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.DIR, EncryptionMethod.A192GCM);
		
		assertEquals("AES", key.getAlgorithm());
		assertArrayEquals(ByteUtils.subArray(CLIENT_SECRET.getSHA256(), 0, 192 / 8), key.getEncoded());
		assertEquals(ByteUtils.byteLength(192), key.getEncoded().length);
		
		JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A192GCM), new Payload("Hello, world!"));
		jwe.encrypt(new DirectEncrypter(key));
	}
	
	
	public void testDerive_dir_A256GCM()
		throws Exception {
		
		SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
		
		assertEquals("AES", key.getAlgorithm());
		assertArrayEquals(ByteUtils.subArray(CLIENT_SECRET.getSHA256(), 0, 256 / 8), key.getEncoded());
		assertEquals(ByteUtils.byteLength(256), key.getEncoded().length);
		
		JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM), new Payload("Hello, world!"));
		jwe.encrypt(new DirectEncrypter(key));
	}
	
	
	public void testDerive_dir_A128CBC_HS256()
		throws Exception {
		
		SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);
		
		assertEquals("AES", key.getAlgorithm());
		assertArrayEquals(ByteUtils.subArray(CLIENT_SECRET.getSHA256(), 0, 256 / 8), key.getEncoded());
		assertEquals(ByteUtils.byteLength(256), key.getEncoded().length);
		
		JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256), new Payload("Hello, world!"));
		jwe.encrypt(new DirectEncrypter(key));
	}
	
	
	public void testDerive_dir_HS384()
		throws Exception {
		
		SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.DIR, EncryptionMethod.A192CBC_HS384);
		
		assertEquals("AES", key.getAlgorithm());
		assertEquals(ByteUtils.byteLength(384), key.getEncoded().length);
		
		JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A192CBC_HS384), new Payload("Hello, world!"));
		jwe.encrypt(new DirectEncrypter(key));
	}
	
	
	public void testDerive_dir_A256CBC_HS512()
		throws Exception {
		
		SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.DIR, EncryptionMethod.A256CBC_HS512);
		
		assertEquals("AES", key.getAlgorithm());
		assertEquals(ByteUtils.byteLength(512), key.getEncoded().length);
		
		JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256CBC_HS512), new Payload("Hello, world!"));
		jwe.encrypt(new DirectEncrypter(key));
	}
	
	
	public void testDerive_A128KW()
		throws Exception {
		
		SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.A128KW, EncryptionMethod.A256CBC_HS512);
		
		assertEquals("AES", key.getAlgorithm());
		assertArrayEquals(ByteUtils.subArray(CLIENT_SECRET.getSHA256(), 0, 128 / 8), key.getEncoded());
		assertEquals(ByteUtils.byteLength(128), key.getEncoded().length);
		
		JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A256CBC_HS512), new Payload("Hello, world!"));
		jwe.encrypt(new AESEncrypter(key));
	}
	
	
	public void testDerive_A192KW()
		throws Exception {
		
		SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.A192KW, EncryptionMethod.A256CBC_HS512);
		
		assertEquals("AES", key.getAlgorithm());
		assertArrayEquals(ByteUtils.subArray(CLIENT_SECRET.getSHA256(), 0, 192 / 8), key.getEncoded());
		assertEquals(ByteUtils.byteLength(192), key.getEncoded().length);
		
		JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.A192KW, EncryptionMethod.A256CBC_HS512), new Payload("Hello, world!"));
		jwe.encrypt(new AESEncrypter(key));
	}
	
	
	public void testDerive_A256KW()
		throws Exception {
		
		SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.A256KW, EncryptionMethod.A256CBC_HS512);
		
		assertEquals("AES", key.getAlgorithm());
		assertArrayEquals(ByteUtils.subArray(CLIENT_SECRET.getSHA256(), 0, 256 / 8), key.getEncoded());
		assertEquals(ByteUtils.byteLength(256), key.getEncoded().length);
		
		JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.A256KW, EncryptionMethod.A256CBC_HS512), new Payload("Hello, world!"));
		jwe.encrypt(new AESEncrypter(key));
	}
	
	
	public void testDerive_A128GCMKW()
		throws Exception {
		
		SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.A128GCMKW, EncryptionMethod.A256CBC_HS512);
		
		assertEquals("AES", key.getAlgorithm());
		assertArrayEquals(ByteUtils.subArray(CLIENT_SECRET.getSHA256(), 0, 128 / 8), key.getEncoded());
		assertEquals(ByteUtils.byteLength(128), key.getEncoded().length);
		
		JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.A128GCMKW, EncryptionMethod.A256CBC_HS512), new Payload("Hello, world!"));
		jwe.encrypt(new AESEncrypter(key));
	}
	
	
	public void testDerive_A192GCMKW()
		throws Exception {
		
		SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.A192GCMKW, EncryptionMethod.A256CBC_HS512);
		
		assertEquals("AES", key.getAlgorithm());
		assertArrayEquals(ByteUtils.subArray(CLIENT_SECRET.getSHA256(), 0, 192 / 8), key.getEncoded());
		assertEquals(ByteUtils.byteLength(192), key.getEncoded().length);
		
		JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.A192GCMKW, EncryptionMethod.A256CBC_HS512), new Payload("Hello, world!"));
		jwe.encrypt(new AESEncrypter(key));
	}
	
	
	public void testDerive_A256GCMKW()
		throws Exception {
		
		SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.A256GCMKW, EncryptionMethod.A256CBC_HS512);
		
		assertEquals("AES", key.getAlgorithm());
		assertArrayEquals(ByteUtils.subArray(CLIENT_SECRET.getSHA256(), 0, 256 / 8), key.getEncoded());
		assertEquals(ByteUtils.byteLength(256), key.getEncoded().length);
		
		JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A256CBC_HS512), new Payload("Hello, world!"));
		jwe.encrypt(new AESEncrypter(key));
	}
	
	
	public void testUnsupportedJWEAlg() {
		
		try {
			SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.RSA1_5, EncryptionMethod.A128GCM);
		} catch (JOSEException e) {
			assertEquals("Unsupported JWE algorithm / method: alg=RSA1_5 enc=A128GCM", e.getMessage());
		}
	}
	
	
	public void testUnsupportedJWEMethod() {
		
		try {
			SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.DIR, new EncryptionMethod("xyz"));
		} catch (JOSEException e) {
			assertEquals("Unsupported JWE method: enc=xyz", e.getMessage());
		}
	}
	
	
	public void testUnsupportedSecretKeyLength() {
		
		try {
			SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, 1024);
		} catch (JOSEException e) {
			assertEquals("Unsupported secret key length: 1024 bits", e.getMessage());
		}
	}
	
	
	public void testMsbTruncate() {
		
		assertEquals(1, new BigInteger(new byte[]{0, 0, 0, 1}).intValue());
		assertEquals(1, new BigInteger(new byte[]{1}).intValue());
	}
}