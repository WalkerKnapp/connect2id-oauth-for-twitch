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


import java.util.Arrays;
import java.util.HashSet;
import java.util.StringTokenizer;

import net.jcip.annotations.Immutable;
import net.jcip.annotations.NotThreadSafe;

import org.apache.commons.lang3.StringUtils;

import com.nimbusds.oauth2.sdk.id.Identifier;


/**
 * Authorisation response type. Can be single-valued or multiple-valued.
 *
 * <p>The following helper methods can be used to find out the OAuth 2.0
 * protocol flow that a particular response type implies:
 *
 * <ul>
 *     <li>{@link #impliesImplicitFlow}
 *     <li>{@link #impliesCodeFlow}
 * </ul>
 *
 * <p>Example response type implying an authorisation code flow:
 *
 * <pre>
 * ResponseType() rt = new ResponseType();
 * rt.add(ResponseType.Value.CODE);
 * </pre>
 *
 * <p>Example response type from OpenID Connect specifying an ID token and an 
 * access token (implies implicit flow):
 *
 * <pre>
 * ResponseType() rt = new ResponseType();
 * rt.add(OIDCResponseTypeValue.ID_TOKEN);
 * rt.add(ResponseType.Value.TOKEN);
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 3.1.1 and 4.1.1.
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices.
 * </ul>
 */
@NotThreadSafe
public class ResponseType extends HashSet<ResponseType.Value> {
	
	
	/**
	 * Authorisation response type value.
	 */
	@Immutable
	public static final class Value extends Identifier {

		/**
		 * Authorisation code.
		 */
		public static final Value CODE = new Value("code");

		
		/**
		 * Access token, with optional refresh token.
		 */
		public static final Value TOKEN = new Value("token");

		
		/**
		 * Creates a new response type value.
		 *
		 * @param value The response type value. Must not be
		 *              {@code null} or empty string.
		 */
		public Value(final String value) {

			super(value);
		}
		
		
		@Override
		public boolean equals(final Object object) {

			return object instanceof Value &&
			       this.toString().equals(object.toString());
		}
	}

	
	/**
	 *  Gets the default response type.
	 * 
	 * @return The default response type, consisting of the value
	 *         {@link ResponseType.Value#CODE}.
	 */
	public static ResponseType getDefault() {
		
		ResponseType defaultResponseType = new ResponseType();
		defaultResponseType.add(ResponseType.Value.CODE);
		return defaultResponseType;
	}

	
	/**
	 * Creates a new empty response type.
	 */
	public ResponseType() {
		
	}


	/**
	 * Creates a new response type with the specified string values.
	 *
	 * @param values The string values. Must not be {@code null}.
	 */
	public ResponseType(final String ... values) {

		for (String v: values)
			add(new Value(v));
	}


	/**
	 * Creates a new response type with the specified values.
	 *
	 * @param values The values. Must not be {@code null}.
	 */
	public ResponseType(final Value ... values) {

		addAll(Arrays.asList(values));
	}
	
	
	/**
	 * Parses a set of authorisation response types.
	 *
	 * <p>Example serialised response type sets:
	 *
	 * <pre>
	 * code
	 * token
	 * id_token
	 * id_token token
	 * code token
	 * code id_token
	 * code id_token token
	 * </pre>
	 *
	 * @param s Space-delimited list of one or more authorisation response 
	 *          types.
	 *
	 * @return The authorisation response types set.
	 *
	 * @throws ParseException If the parsed string is {@code null} or 
	 *                        empty.
	 */
	public static ResponseType parse(final String s)
		throws ParseException {
	
		if (StringUtils.isBlank(s))
			throw new ParseException("Null or empty response type string");
	
		ResponseType rt = new ResponseType();
		
		StringTokenizer st = new StringTokenizer(s, " ");

		while (st.hasMoreTokens())
			rt.add(new ResponseType.Value(st.nextToken()));
		
		return rt;
	}
	
	
	/**
	 * Returns {@code true} if this response type implies a code flow.
	 *
	 * @return {@code true} if a code flow is implied, else {@code false}.
	 */
	public boolean impliesCodeFlow() {

		return this.contains(Value.CODE) && this.size() == 1;
	}
	
	
	/**
	 * Returns {@code true} if this response type implies an implicit flow.
	 *
	 * @return {@code true} if an implicit flow is implied, else 
	 *         {@code false}.
	 */
	public boolean impliesImplicitFlow() {
	
		return ! impliesCodeFlow();
	}


	/**
	 * Checks if this response type contains the specified string value.
	 *
	 * @param value The string value. Must not be {@code null}.
	 *
	 * @return {@code true} if the value is contained, else {@code false}.
	 */
	public boolean contains(final String value) {

		return contains(new Value(value));
	}
	
	
	/**
	 * Returns the string representation of this  authorisation response 
	 * type.
	 *
	 * <p>Example serialised response types:
	 *
	 * <pre>
	 * code
	 * token
	 * id_token
	 * id_token token
	 * code token
	 * code id_token
	 * code id_token token
	 * </pre>
	 *
	 * @return Space delimited string representing the authorisation 
	 *         response type.
	 */
	@Override
	public String toString() {
	
		StringBuilder sb = new StringBuilder();

		for (ResponseType.Value v: this) {

			if (sb.length() > 0)
				sb.append(' ');

			sb.append(v.getValue());
		}

		return sb.toString();
	}
}
