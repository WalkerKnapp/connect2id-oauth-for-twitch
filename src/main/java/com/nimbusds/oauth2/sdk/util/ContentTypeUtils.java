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

package com.nimbusds.oauth2.sdk.util;


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.ParseException;


/**
 * Content type matching.
 */
public final class ContentTypeUtils {


	/**
	 * Ensures the {@code Content-Type} of an HTTP header matches an
	 * expected value. Note that this method compares only the primary type
	 * and subtype; any content type parameters, such as {@code charset},
	 * are ignored.
	 *
	 * @param expected The expected content type. Must not be {@code null}.
	 * @param found    The found content type. May be {@code null}.
	 *
	 * @throws ParseException If the found content type is {@code null} or
	 *                        doesn't match the expected.
	 */
	public static void ensureContentType(final ContentType expected, final ContentType found)
		throws ParseException {
	
		ensureContentType(expected, null, found);
	}


	/**
	 * Ensures the {@code Content-Type} of an HTTP header matches an
	 * expected value. Note that this method compares only the primary type
	 * and subtype; any content type parameters, such as {@code charset},
	 * are ignored.
	 *
	 * @param expected      The expected content type. Must not be {@code null}.
	 * @param subTypeSuffix Acceptable suffix if the sub type doesn't
	 *                      match exactly, {@code null} if not specified.
	 * @param found         The found content type. May be {@code null}.
	 *
	 * @throws ParseException If the found content type is {@code null} or
	 *                        doesn't match the expected.
	 */
	public static void ensureContentType(final ContentType expected,
					     final String subTypeSuffix,
					     final ContentType found)
		throws ParseException {

		if (found == null) {
			throw new ParseException("Missing HTTP Content-Type header");
		}

		if (expected.matches(found)) {
			// Exact match
			return;
		}

		if (expected.getBaseType().equals(found.getBaseType()) && found.hasSubTypeSuffix(subTypeSuffix)) {
			// Base + suffix match
			return;
		}

		if (subTypeSuffix == null) {

			throw new ParseException("The HTTP Content-Type header must be " +
				expected.getType() +
				", received " + found.getType());

		} else {

			throw new ParseException("The HTTP Content-Type header must be " +
				expected.getType() +
				" or have the +" + subTypeSuffix + " suffix, " +
				"received " + found.getType());
		}
	}
	

	/**
	 * Prevents public instantiation.
	 */
	private ContentTypeUtils() {}
}
