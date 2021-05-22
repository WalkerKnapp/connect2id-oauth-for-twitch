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


import java.security.SecureRandom;

import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Subject;
import junit.framework.TestCase;


public class HashBasedPairwiseSubjectCodecTest extends TestCase {
	

	public void testAlgConstant() {
		assertEquals("SHA-256", HashBasedPairwiseSubjectCodec.HASH_ALGORITHM);
	}


	public void testEncode() {

		// Generate salt
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);

		HashBasedPairwiseSubjectCodec codec = new HashBasedPairwiseSubjectCodec(salt);
		assertEquals(salt, codec.getSalt());
		assertNull(codec.getProvider());

		SectorID sectorID = new SectorID("example.com");
		Subject localSubject = new Subject("alice");

		Subject pairwiseSubject = codec.encode(sectorID, localSubject);
		System.out.println("Pairwise subject: " + pairwiseSubject);
		assertEquals(256, new Base64URL(pairwiseSubject.getValue()).decode().length * 8);
	}


	public void testEncodeWithNonURIAudienceAsSectorID() {

		// Generate salt
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);

		HashBasedPairwiseSubjectCodec codec = new HashBasedPairwiseSubjectCodec(salt);
		assertEquals(salt, codec.getSalt());
		assertNull(codec.getProvider());
		
		Audience audience = new Audience("3f7951a7-0aa4-43cd-835a-1d3f6d024c24");
		SectorID sectorID = new SectorID(audience.getValue());
		Subject localSubject = new Subject("alice");

		Subject pairwiseSubject = codec.encode(sectorID, localSubject);
		System.out.println("Pairwise subject: " + pairwiseSubject);
		assertEquals(256, new Base64URL(pairwiseSubject.getValue()).decode().length * 8);
	}


	public void testConstructorConsistency() {

		// Generate salt
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);

		HashBasedPairwiseSubjectCodec codec = new HashBasedPairwiseSubjectCodec(salt);
		assertEquals(salt, codec.getSalt());
		assertNull(codec.getProvider());

		SectorID sectorID = new SectorID("example.com");
		Subject localSubject = new Subject("alice");

		Subject s1 = codec.encode(sectorID, localSubject);

		codec = new HashBasedPairwiseSubjectCodec(Base64URL.encode(salt));
		Subject s2 = codec.encode(sectorID, localSubject);

		assertEquals(s1, s2);
	}


	public void testEncodeWithProvider() {

		// Generate salt
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);

		HashBasedPairwiseSubjectCodec codec = new HashBasedPairwiseSubjectCodec(salt);
		assertEquals(salt, codec.getSalt());
		assertNull(codec.getProvider());

		codec.setProvider(BouncyCastleProviderSingleton.getInstance());
		assertEquals(BouncyCastleProviderSingleton.getInstance(), codec.getProvider());

		SectorID sectorID = new SectorID("example.com");
		Subject localSubject = new Subject("alice");

		Subject pairwiseSubject = codec.encode(sectorID, localSubject);
		System.out.println("Pairwise subject: " + pairwiseSubject);
		assertEquals(256, new Base64URL(pairwiseSubject.getValue()).decode().length * 8);
	}


	public void testDecode()
		throws InvalidPairwiseSubjectException {

		// Generate salt
		byte[] salt = new byte[16];
		new SecureRandom().nextBytes(salt);

		HashBasedPairwiseSubjectCodec codec = new HashBasedPairwiseSubjectCodec(salt);

		try {
			codec.decode(new Subject("xyz"));
			fail();
		} catch (UnsupportedOperationException e) {
			assertEquals("Pairwise subject decoding is not supported", e.getMessage());
		}
	}
}
