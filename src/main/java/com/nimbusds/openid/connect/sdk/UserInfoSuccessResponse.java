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

package com.nimbusds.openid.connect.sdk;


import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.SuccessResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.jcip.annotations.Immutable;

import java.util.Objects;


/**
 * UserInfo success response.
 *
 * <p>The UserInfo claims may be passed as an unprotected JSON object or as a 
 * plain, signed or encrypted JSON Web Token (JWT). Use the appropriate 
 * constructor for that.
 *
 * <p>Example UserInfo HTTP response:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * 
 * {
 *  "sub"         : "248289761001",
 *  "name"        : "Jane Doe"
 *  "given_name"  : "Jane",
 *  "family_name" : "Doe",
 *  "email"       : "janedoe@example.com",
 *  "picture"     : "http://example.com/janedoe/me.jpg"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0
 * </ul>
 */
@Immutable
public class UserInfoSuccessResponse
	extends UserInfoResponse
	implements SuccessResponse {


	/**
	 * The UserInfo claims set, serialisable to a JSON object.
	 */
	private final UserInfo claimsSet;
	
	
	/**
	 * The UserInfo claims set, as plain, signed or encrypted JWT.
	 */
	private final JWT jwt;
	
	
	/**
	 * Creates a new UserInfo success response where the claims are 
	 * specified as an unprotected UserInfo claims set.
	 *
	 * @param claimsSet The UserInfo claims set. Must not be {@code null}.
	 */
	public UserInfoSuccessResponse(final UserInfo claimsSet) {
		this.claimsSet = Objects.requireNonNull(claimsSet);
		this.jwt = null;
	}
	
	
	/**
	 * Creates a new UserInfo success response where the claims are 
	 * specified as a plain, signed or encrypted JSON Web Token (JWT).
	 *
	 * @param jwt The UserInfo claims set. Must not be {@code null}.
	 */
	public UserInfoSuccessResponse(final JWT jwt) {
		this.jwt = Objects.requireNonNull(jwt);
		this.claimsSet = null;
	}


	@Override
	public boolean indicatesSuccess() {
		return true;
	}
	
	
	/**
	 * Gets the content type of this UserInfo response.
	 *
	 * @return The content type, according to the claims format.
	 */
	public ContentType getEntityContentType() {
	
		if (claimsSet != null)
			return ContentType.APPLICATION_JSON;
		else
			return ContentType.APPLICATION_JWT;
	}
	
	
	/**
	 * Gets the UserInfo claims set as an unprotected UserInfo claims set.
	 *
	 * @return The UserInfo claims set, {@code null} if it was specified as
	 *         JSON Web Token (JWT) instead.
	 */
	public UserInfo getUserInfo() {
	
		return claimsSet;
	}
	
	
	/**
	 * Gets the UserInfo claims set as a plain, signed or encrypted JSON
	 * Web Token (JWT).
	 *
	 * @return The UserInfo claims set as a JSON Web Token (JWT), 
	 *         {@code null} if it was specified as an unprotected UserInfo
	 *         claims set instead.
	 */
	public JWT getUserInfoJWT() {
	
		return jwt;
	}
	
	
	@Override
	public HTTPResponse toHTTPResponse() {
	
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		
		httpResponse.setEntityContentType(getEntityContentType());
		
		String content;
		
		if (claimsSet != null) {
		
			content = claimsSet.toJSONObject().toString();

		} else {
			
			try {
				content = jwt.serialize();
				
			} catch (IllegalStateException e) {
			
				throw new SerializeException("Couldn't serialize UserInfo claims JWT: " + 
					                     e.getMessage(), e);
			}
		}
		
		httpResponse.setBody(content);
	
		return httpResponse;
	}
	
	
	/**
	 * Parses a UserInfo response from the specified HTTP response.
	 *
	 * <p>Example HTTP response:
	 *
	 * <pre>
	 * HTTP/1.1 200 OK
	 * Content-Type: application/json
	 * 
	 * {
	 *  "sub"         : "248289761001",
	 *  "name"        : "Jane Doe"
	 *  "given_name"  : "Jane",
	 *  "family_name" : "Doe",
	 *  "email"       : "janedoe@example.com",
	 *  "picture"     : "http://example.com/janedoe/me.jpg"
	 * }
	 * </pre>
	 *
	 * @param httpResponse The HTTP response. Must not be {@code null}.
	 *
	 * @return The UserInfo response.
	 *
	 * @throws ParseException If the HTTP response couldn't be parsed to a 
	 *                        UserInfo response.
	 */
	public static UserInfoSuccessResponse parse(final HTTPResponse httpResponse)
		throws ParseException {
		
		httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
		
		httpResponse.ensureEntityContentType();
		
		ContentType ct = httpResponse.getEntityContentType();
		
		UserInfoSuccessResponse response;
		
		if (ct.matches(ContentType.APPLICATION_JSON)) {
		
			UserInfo claimsSet;
			
			try {
				claimsSet = new UserInfo(httpResponse.getBodyAsJSONObject());
				
			} catch (Exception e) {
				
				throw new ParseException("Couldn't parse UserInfo claims: " + 
					                 e.getMessage(), e);
			}
			
			response = new UserInfoSuccessResponse(claimsSet);
			
		} else if (ct.matches(ContentType.APPLICATION_JWT)) {
		
			JWT jwt;
			
			try {
				jwt = httpResponse.getBodyAsJWT();
				
			} catch (ParseException e) {
			
				throw new ParseException("Couldn't parse UserInfo claims JWT: " + 
					                 e.getMessage(), e);
			}
			
			response = new UserInfoSuccessResponse(jwt);
			
		} else {
			throw new ParseException("Unexpected Content-Type, must be " + 
			                         ContentType.APPLICATION_JSON +
						 " or " +
						 ContentType.APPLICATION_JWT);
		}
		
		return response;
	}
}
