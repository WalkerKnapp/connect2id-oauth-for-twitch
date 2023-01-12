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

package com.nimbusds.openid.connect.sdk.op;


import java.util.List;
import java.util.Map;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;


/**
 * OpenID authentication request detector.
 */
public class AuthenticationRequestDetector {
	
	/**
	 * Returns {@code true} if the specified authorisation request is
	 * likely an OpenID authentication request.
	 *
	 * @param request The authorisation request.
	 *
	 * @return {@code true} for a likely OpenID authentication request,
	 *         else {@code false}.
	 */
	public static boolean isLikelyOpenID(final AuthorizationRequest request) {
		
		return request.getScope() != null && request.getScope().contains(OIDCScopeValue.OPENID);
	}
	
	
	/**
	 * Returns {@code true} if the specified query parameters are likely
	 * for an OpenID authentication request.
	 *
	 * @param queryParams The query parameters.
	 *
	 * @return {@code true} for a likely OpenID authentication request,
	 *         else {@code false}.
	 */
	public static boolean isLikelyOpenID(final Map<String, List<String>> queryParams) {
		
		Scope scope = Scope.parse(MultivaluedMapUtils.getFirstValue(queryParams, ("scope")));
		
		if (scope == null) {
			return false;
		}
		
		return scope.contains(OIDCScopeValue.OPENID);
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private AuthenticationRequestDetector() {}
}
