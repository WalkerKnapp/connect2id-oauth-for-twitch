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
import java.util.Collection;
import java.util.HashSet;
import java.util.StringTokenizer;

import net.jcip.annotations.Immutable;
import net.jcip.annotations.NotThreadSafe;

import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;


/**
 * Authorisation response type.
 *
 * <p>Example response type implying an authorisation code flow:
 *
 * <pre>
 * ResponseType rt = ResponseType.CODE;
 * </pre>
 *
 * <p>Example response type from OpenID Connect specifying an ID token and an
 * access token (implies implicit flow):
 *
 * <pre>
 * ResponseType rt = ResponseType.IDTOKEN_TOKEN);
 * </pre>
 *
 * <p>The following helper methods can be used to find out the implied OAuth
 * 2.0 protocol flow for a response type:
 *
 * <ul>
 *     <li>{@link #impliesImplicitFlow}
 *     <li>{@link #impliesCodeFlow}
 * </ul>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749)
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices
 * </ul>
 */
@NotThreadSafe
public class ResponseType extends HashSet<ResponseType.Value> {
	
	
	/**
	 * Constant for {@code response_type=code}.
	 */
	public static final ResponseType CODE = new ResponseType(true, Value.CODE);
	
	
	/**
	 * Constant for {@code response_type=token}.
	 */
	public static final ResponseType TOKEN = new ResponseType(true, Value.TOKEN);
	
	
	/**
	 * Constant for {@code response_type=id_token token}.
	 */
	public static final ResponseType IDTOKEN_TOKEN = new ResponseType(true, OIDCResponseTypeValue.ID_TOKEN, Value.TOKEN);
	
	
	/**
	 * Constant for {@code response_type=id_token}.
	 */
	public static final ResponseType IDTOKEN = new ResponseType(true, OIDCResponseTypeValue.ID_TOKEN);
	
	
	/**
	 * Constant for {@code response_type=code id_token}.
	 */
	public static final ResponseType CODE_IDTOKEN = new ResponseType(true, Value.CODE, OIDCResponseTypeValue.ID_TOKEN);
	
	
	/**
	 * Constant for {@code response_type=code token}.
	 */
	public static final ResponseType CODE_TOKEN = new ResponseType(true, Value.CODE, Value.TOKEN);
	
	
	/**
	 * Constant for {@code response_type=code id_token token}.
	 */
	public static final ResponseType CODE_IDTOKEN_TOKEN = new ResponseType(true, Value.CODE, OIDCResponseTypeValue.ID_TOKEN, Value.TOKEN);
	
	
	private static final long serialVersionUID = 1351973244616920112L;
	
	
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
		
		
		private static final long serialVersionUID = 5339971450891463852L;
		
		
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
		
		return ResponseType.CODE;
	}
	
	
	/**
	 * If {@code true} flags the response type as unmodifiable.
	 */
	private final boolean unmodifiable;

	
	/**
	 * Creates a new empty response type.
	 */
	public ResponseType() {
		super();
		unmodifiable = false;
	}


	/**
	 * Creates a new response type with the specified string values.
	 *
	 * @param values The string values. Must not be {@code null}.
	 */
	public ResponseType(final String ... values) {

		for (String v: values) {
			add(new Value(v));
		}
		
		unmodifiable = false;
	}


	/**
	 * Creates a new response type with the specified values.
	 *
	 * @param values The values. Must not be {@code null}.
	 */
	public ResponseType(final Value ... values) {
		this(false, values);
	}


	/**
	 * Creates a new response type with the specified values.
	 *
	 * @param unmodifiable If {@code true} flags the response type as
	 *                     unmodifiable.
	 * @param values       The values. Must not be {@code null}.
	 */
	private ResponseType(final boolean unmodifiable, final Value ... values) {
		super(Arrays.asList(values));
		this.unmodifiable = unmodifiable;
	}
	
	
	/**
	 * Parses a set of authorisation response types.
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
	 * Returns {@code true} if this response type implies an authorisation
	 * code flow.
	 *
	 * <p>Code flow response_type values: code
	 *
	 * @return {@code true} if a code flow is implied, else {@code false}.
	 */
	public boolean impliesCodeFlow() {
		
		return this.equals(new ResponseType(Value.CODE));
	}
	
	
	/**
	 * Returns {@code true} if this response type implies an implicit flow.
	 *
	 * <p>Implicit flow response_type values: token, id_token token,
	 * id_token
	 *
	 * @return {@code true} if an implicit flow is implied, else 
	 *         {@code false}.
	 */
	public boolean impliesImplicitFlow() {
	
		return
			this.equals(new ResponseType(Value.TOKEN)) ||
			this.equals(new ResponseType(OIDCResponseTypeValue.ID_TOKEN, Value.TOKEN)) ||
			this.equals(new ResponseType(OIDCResponseTypeValue.ID_TOKEN));
	}
	
	
	/**
	 * Returns {@code true} if this response type implies an OpenID Connect
	 * hybrid flow.
	 *
	 * <p>Hybrid flow response_type values: code id_token, code token,
	 * code id_token token
	 *
	 * @return {@code true} if a hybrid flow is implied, else
	 *         {@code false}.
	 */
	public boolean impliesHybridFlow() {
	
		return
			this.equals(new ResponseType(Value.CODE, OIDCResponseTypeValue.ID_TOKEN)) ||
			this.equals(new ResponseType(Value.CODE, Value.TOKEN)) ||
			this.equals(new ResponseType(Value.CODE, OIDCResponseTypeValue.ID_TOKEN, Value.TOKEN));
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
	
	
	@Override
	public boolean add(Value value) {
		if (unmodifiable) {
			throw new UnsupportedOperationException();
		}
		return super.add(value);
	}
	
	
	@Override
	public boolean remove(Object o) {
		if (unmodifiable) {
			throw new UnsupportedOperationException();
		}
		return super.remove(o);
	}
	
	
	@Override
	public void clear() {
		if (unmodifiable) {
			throw new UnsupportedOperationException();
		}
		super.clear();
	}
	
	
	@Override
	public boolean removeAll(Collection<?> c) {
		if (unmodifiable) {
			throw new UnsupportedOperationException();
		}
		return super.removeAll(c);
	}
	
	
	@Override
	public boolean addAll(Collection<? extends Value> c) {
		if (unmodifiable) {
			throw new UnsupportedOperationException();
		}
		return super.addAll(c);
	}
	
	
	@Override
	public boolean retainAll(Collection<?> c) {
		if (unmodifiable) {
			throw new UnsupportedOperationException();
		}
		return super.retainAll(c);
	}
}
