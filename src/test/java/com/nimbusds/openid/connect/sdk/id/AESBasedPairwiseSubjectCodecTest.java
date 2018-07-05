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

package com.nimbusds.openid.connect.sdk.id;


import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.id.Subject;
import junit.framework.TestCase;


public class AESBasedPairwiseSubjectCodecTest extends TestCase {
	

	public void testEncodeAndDecode()
		throws Exception {

		// Generate salt
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);

		// Generate AES key
		KeyGenerator KeyGen=KeyGenerator.getInstance("AES");
		KeyGen.init(128);
		SecretKey aesKey=KeyGen.generateKey();

		AESBasedPairwiseSubjectCodec codec = new AESBasedPairwiseSubjectCodec(aesKey, salt);

		// Test getters
		assertEquals(salt, codec.getSalt());
		assertEquals(aesKey, codec.getAESKey());
		assertNull(codec.getProvider());

		SectorID sectorID = new SectorID("example.com");
		Subject localSubject = new Subject("alice");

		Subject pairwiseSubject = codec.encode(sectorID, localSubject);
		System.out.println("Pairwise subject: " + pairwiseSubject);

		Map.Entry<SectorID,Subject> out = codec.decode(pairwiseSubject);
		assertEquals(sectorID, out.getKey());
		assertEquals(localSubject, out.getValue());
	}


	public void testEscapeDelimiter()
		throws Exception {

		// Generate salt
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);

		// Generate AES key
		KeyGenerator KeyGen=KeyGenerator.getInstance("AES");
		KeyGen.init(128);
		SecretKey aesKey=KeyGen.generateKey();

		AESBasedPairwiseSubjectCodec codec = new AESBasedPairwiseSubjectCodec(aesKey, salt);

		// Test getters
		assertEquals(salt, codec.getSalt());
		assertEquals(aesKey, codec.getAESKey());
		assertNull(codec.getProvider());

		SectorID sectorID = new SectorID("example|com");
		Subject localSubject = new Subject("alice|adams");

		Subject pairwiseSubject = codec.encode(sectorID, localSubject);
		System.out.println("Pairwise subject: " + pairwiseSubject);

		Map.Entry<SectorID,Subject> out = codec.decode(pairwiseSubject);
		assertEquals(sectorID, out.getKey());
		assertEquals(localSubject, out.getValue());
	}


	public void testEncodeAndDecodeWithProvider()
		throws Exception {

		// Generate salt
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);

		// Generate AES key
		KeyGenerator KeyGen=KeyGenerator.getInstance("AES");
		KeyGen.init(128);
		SecretKey aesKey=KeyGen.generateKey();

		AESBasedPairwiseSubjectCodec codec = new AESBasedPairwiseSubjectCodec(aesKey, salt);

		// Test getters
		assertEquals(salt, codec.getSalt());
		assertEquals(aesKey, codec.getAESKey());
		assertNull(codec.getProvider());

		codec.setProvider(BouncyCastleProviderSingleton.getInstance());
		assertEquals(BouncyCastleProviderSingleton.getInstance(), codec.getProvider());

		SectorID sectorID = new SectorID("example.com");
		Subject localSubject = new Subject("alice");

		Subject pairwiseSubject = codec.encode(sectorID, localSubject);
		System.out.println("Pairwise subject: " + pairwiseSubject);

		Map.Entry<SectorID,Subject> out = codec.decode(pairwiseSubject);
		assertEquals(sectorID, out.getKey());
		assertEquals(localSubject, out.getValue());
	}


	public void testDeterminism()
		throws Exception {

		// Generate salt
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);

		// Generate AES key
		KeyGenerator KeyGen=KeyGenerator.getInstance("AES");
		KeyGen.init(128);
		SecretKey aesKey=KeyGen.generateKey();

		AESBasedPairwiseSubjectCodec codec = new AESBasedPairwiseSubjectCodec(aesKey, salt);

		// Test getters
		assertEquals(salt, codec.getSalt());
		assertEquals(aesKey, codec.getAESKey());
		assertNull(codec.getProvider());

		SectorID sectorID = new SectorID("example.com");
		Subject localSubject = new Subject("alice");

		Subject firstPairwiseSubject = codec.encode(sectorID, localSubject);

		// Repeat
		for (int i=0; i<1000; i++) {
			assertTrue(firstPairwiseSubject.equals(codec.encode(sectorID, localSubject)));
		}
	}


	public void testDecodeInvalidCrypto()
		throws Exception {

		// Generate salt
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);

		// Generate AES key
		KeyGenerator KeyGen=KeyGenerator.getInstance("AES");
		KeyGen.init(128);
		SecretKey aesKey=KeyGen.generateKey();

		AESBasedPairwiseSubjectCodec codec = new AESBasedPairwiseSubjectCodec(aesKey, salt);

		try {
			codec.decode(new Subject("xyz"));
		} catch (InvalidPairwiseSubjectException e) {
			assertEquals("Decryption failed: Input length must be multiple of 16 when decrypting with padded cipher", e.getMessage());
		}
	}


	public void testDecodeInvalidCryptoAlt()
		throws Exception {

		// Generate salt
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);

		// Generate AES key
		KeyGenerator KeyGen=KeyGenerator.getInstance("AES");
		KeyGen.init(128);
		SecretKey aesKey=KeyGen.generateKey();

		AESBasedPairwiseSubjectCodec codec = new AESBasedPairwiseSubjectCodec(aesKey, salt);

		byte[] cipherText = new byte[1024];
		new SecureRandom().nextBytes(cipherText);

		try {
			codec.decode(new Subject(Base64URL.encode(cipherText).toString()));
		} catch (InvalidPairwiseSubjectException e) {
			assertEquals("Decryption failed: Given final block not properly padded. Such issues can arise if a bad key is used during decryption.", e.getMessage());
		}
	}


	public void testRejectNullKey() {

		// Generate salt
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);

		try {
			new AESBasedPairwiseSubjectCodec(null, salt);
		} catch (IllegalArgumentException e) {
			assertEquals("The AES key must not be null", e.getMessage());
		}
	}


	public void testRejectNullSalt()
		throws NoSuchAlgorithmException {

		// Generate salt
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);

		// Generate AES key
		KeyGenerator KeyGen=KeyGenerator.getInstance("AES");
		KeyGen.init(128);
		SecretKey aesKey=KeyGen.generateKey();

		try {
			new AESBasedPairwiseSubjectCodec(aesKey, null);
		} catch (IllegalArgumentException e) {
			assertEquals("The salt must not be null", e.getMessage());
		}
	}
}
