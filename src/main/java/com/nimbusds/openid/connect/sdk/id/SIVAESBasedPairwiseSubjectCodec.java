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


import java.util.AbstractMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.oauth2.sdk.id.Subject;
import net.jcip.annotations.ThreadSafe;
import org.cryptomator.siv.SivMode;


/**
 * SIV AES - based encoder / decoder of pairwise subject identifiers. Requires
 * a 256, 384, or 512-bit secret key. Reversal is supported.
 *
 * <p>The plain text is formatted as follows ('|' as delimiter):
 *
 * <pre>
 * sector_id|local_sub
 * </pre>
 *
 * <p>The encoder can be configured to pad the local subject up to a certain
 * string length, typically the maximum expected length of the local subject
 * identifiers, to ensure the output pairwise subject identifiers are output
 * with a length that is uniform and doesn't vary with the local subject
 * identifier length. This is intended as an additional measure against leaking
 * end-user information and hence correlation. Note that local subjects that
 * are longer than the configured length will appear as proportionally longer
 * pairwise identifiers.
 *
 * <p>Pad local subjects that are shorter than 50 characters in length:
 *
 * <pre>
 * new SIVAESBasedPairwiseSubjectCodec(secretKey, 50);
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Synthetic Initialization Vector (SIV) Authenticated Encryption Using
 *         the Advanced Encryption Standard (AES) (RFC 5297)
 *     <li>OpenID Connect Core 1.0
 * </ul>
 */
@ThreadSafe
public class SIVAESBasedPairwiseSubjectCodec extends PairwiseSubjectCodec {
	
	
	/**
	 * The AES SIV crypto engine.
	 */
	private static final SivMode AES_SIV = new SivMode();
	
	
	/**
	 * The AES CTR key (1st half).
	 */
	private final byte[] aesCtrKey;
	
	
	/**
	 * The MAC key (2nd half).
	 */
	private final byte[] macKey;
	
	
	/**
	 * Pads the local subject to the specified length, -1 for no padding.
	 */
	private final int padSubjectToLength;
	
	
	/**
	 * Creates a new SIV AES - based codec for pairwise subject
	 * identifiers. Local subjects are not padded up to a certain length.
	 *
	 * @param secretKey A 256, 384, or 512-bit secret key. Must not be
	 *                  {@code null}.
	 */
	public SIVAESBasedPairwiseSubjectCodec(final SecretKey secretKey) {
		this(secretKey, -1);
	}
	
	
	/**
	 * Creates a new SIV AES - based codec for pairwise subject
	 * identifiers.
	 *
	 * @param secretKey          A 256, 384, or 512-bit secret key. Must
	 *                           not be {@code null}.
	 * @param padSubjectToLength Pads the local subject to the specified
	 *                           length, -1 (negative integer) for no
	 *                           padding.
	 */
	public SIVAESBasedPairwiseSubjectCodec(final SecretKey secretKey,
					       final int padSubjectToLength) {
		super(null);

		byte[] keyBytes = secretKey.getEncoded();
		
		switch (keyBytes.length) {
			case 32:
				aesCtrKey = ByteUtils.subArray(keyBytes, 0, 16);
				macKey = ByteUtils.subArray(keyBytes, 16, 16);
				break;
			case 48:
				aesCtrKey = ByteUtils.subArray(keyBytes, 0, 24);
				macKey = ByteUtils.subArray(keyBytes, 24, 24);
				break;
			case 64:
				aesCtrKey = ByteUtils.subArray(keyBytes, 0, 32);
				macKey = ByteUtils.subArray(keyBytes, 32, 32);
				break;
			default:
				throw new IllegalArgumentException("The SIV AES secret key length must be 256, 384 or 512 bits");
		}
		
		this.padSubjectToLength = padSubjectToLength;
	}
	
	
	/**
	 * Returns the secret key.
	 *
	 * @return The key.
	 */
	public SecretKey getSecretKey() {
		
		return new SecretKeySpec(ByteUtils.concat(aesCtrKey, macKey), "AES");
	}
	
	
	/**
	 * Returns the optional padded string length of local subjects.
	 *
	 * @return The padding string length, -1 (negative integer) for no
	 *         padding.
	 */
	public int getPadSubjectToLength() {
		
		return padSubjectToLength;
	}
	
	
	private static String escapeSeparator(final String s) {
		
		return s.replace("|", "\\|");
	}
	
	
	@Override
	public Subject encode(final SectorID sectorID, final Subject localSub) {
		
		// Escape separator chars
		final String escapedSectorIDString = escapeSeparator(sectorID.getValue());
		final String escapedLocalSub = escapeSeparator(localSub.getValue());
		
		StringBuilder optionalPadding = new StringBuilder();
		
		if (padSubjectToLength > 0) {
			// Apply padding
			int paddingLength = padSubjectToLength - escapedLocalSub.length();
			
			if (paddingLength == 1) {
				
				optionalPadding = new StringBuilder("|");
				
			} else if (paddingLength > 1) {
				
				optionalPadding = new StringBuilder("|");
				int i = paddingLength;
				while (--i > 0) {
					optionalPadding.append("0"); // pad with 0
				}
			}
		}
		
		// Join parameters, delimited by '|'
		final String plainTextString = (escapedSectorIDString + '|' + escapedLocalSub + optionalPadding);
		
		byte[] plainText = plainTextString.getBytes(CHARSET);
		byte[] cipherText = AES_SIV.encrypt(aesCtrKey, macKey, plainText);
		return new Subject(Base64URL.encode(cipherText).toString());
	}
	
	
	@Override
	public Map.Entry<SectorID, Subject> decode(final Subject pairwiseSubject)
		throws InvalidPairwiseSubjectException {
		
		byte[] cipherText = new Base64URL(pairwiseSubject.getValue()).decode();
		
		byte[] plainText;
		try {
			plainText  = AES_SIV.decrypt(aesCtrKey, macKey, cipherText);
		} catch (Exception e) {
			throw new InvalidPairwiseSubjectException("Decryption failed: " + e.getMessage(), e);
		}
		
		// Split along the '|' delimiter
		String[] parts = new String(plainText, CHARSET).split("(?<!\\\\)\\|");
		
		// Unescape delimiter
		for (int i=0; i<parts.length; i++) {
			parts[i] = parts[i].replace("\\|", "|");
		}
		
		// Check format
		if (parts.length > 3) {
			throw new InvalidPairwiseSubjectException("Invalid format: Unexpected number of tokens: " + parts.length);
		}
		
		return new AbstractMap.SimpleImmutableEntry<>(new SectorID(parts[0]), new Subject(parts[1]));
	}
}
