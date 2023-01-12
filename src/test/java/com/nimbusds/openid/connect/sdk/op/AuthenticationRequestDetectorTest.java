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


import java.net.URI;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;


public class AuthenticationRequestDetectorTest extends TestCase {
	
	
	public void testIsLikelyOpenID_empty() {
		
		assertFalse(AuthenticationRequestDetector.isLikelyOpenID(Collections.<String, List<String>>emptyMap()));
	}
	
	
	public void testIsLikelyOpenID_plainMinimalOAuth() {
		
		AuthorizationRequest request = new AuthorizationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new ClientID("123"))
			.build();
		
		assertFalse(AuthenticationRequestDetector.isLikelyOpenID(request));
		
		assertFalse(AuthenticationRequestDetector.isLikelyOpenID(request.toParameters()));
	}
	
	
	public void testIsLikelyOpenID_plainOAuthWithScope() {
		
		AuthorizationRequest request = new AuthorizationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new ClientID("123"))
			.scope(new Scope("read", "write"))
			.build();
		
		assertFalse(AuthenticationRequestDetector.isLikelyOpenID(request));
		
		assertFalse(AuthenticationRequestDetector.isLikelyOpenID(request.toParameters()));
	}
	
	
	public void testIsLikelyOpenID_minimalOpenID() {
		
		AuthorizationRequest request = new AuthenticationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new Scope("openid"),
			new ClientID("123"),
			URI.create("https://example.com/cb"))
			.build();
		
		assertTrue(AuthenticationRequestDetector.isLikelyOpenID(request));
		
		assertTrue(AuthenticationRequestDetector.isLikelyOpenID(request.toParameters()));
	}
}
