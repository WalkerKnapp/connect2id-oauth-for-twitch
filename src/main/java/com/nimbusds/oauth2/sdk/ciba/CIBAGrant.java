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

package com.nimbusds.oauth2.sdk.ciba;


import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.util.MultivaluedMapUtils;
import net.jcip.annotations.Immutable;

import java.util.*;


/**
 * CIBA grant.
 *
 * <p>Related specifications:
 *
 * <ul>
 *      <li>OpenID Connect CIBA Flow - Core 1.0
 * </ul>
 */
@Immutable
public class CIBAGrant extends AuthorizationGrant {
	
	
	/**
	 * The grant type.
	 */
	public static final GrantType GRANT_TYPE = GrantType.CIBA;
	
	
	/**
	 * The authentication request ID.
	 */
	private final AuthRequestID authRequestID;
	
	
	/**
	 * Creates a new CIBA grant.
	 *
	 * @param authRequestID The authentication request ID. Must not be
	 *                      {@code null}.
	 */
	public CIBAGrant(final AuthRequestID authRequestID) {
		
		super(GRANT_TYPE);
		this.authRequestID = Objects.requireNonNull(authRequestID);
	}
	
	
	/**
	 * Returns the authentication request ID.
	 *
	 * @return The authentication request ID.
	 */
	public AuthRequestID getAuthRequestID() {
		
		return authRequestID;
	}
	
	
	@Override
	public Map<String, List<String>> toParameters() {

		Map<String, List<String>> params = new LinkedHashMap<>();
		params.put("grant_type", Collections.singletonList(GRANT_TYPE.getValue()));
		params.put("auth_req_id", Collections.singletonList(authRequestID.getValue()));
		return params;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (!(o instanceof CIBAGrant))
			return false;
		CIBAGrant cibaGrant = (CIBAGrant) o;
		return getAuthRequestID().equals(cibaGrant.getAuthRequestID());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(getAuthRequestID());
	}
	
	
	/**
	 * Parses a CIBA grant from the specified request body parameters.
	 *
	 * <p>Example:
	 *
	 * <pre>
   	 * scope=openid%20email%20example-scope&amp;
   	 * client_notification_token=8d67dc78-7faa-4d41-aabd-67707b374255&amp;
   	 * binding_message=W4SCT&amp;
   	 * login_hint_token=eyJraWQiOiJsdGFjZXNidyIsImFsZyI6IkVTMjU2In0.eyJ
   	 * zdWJfaWQiOnsic3ViamVjdF90eXBlIjoicGhvbmUiLCJwaG9uZSI6IisxMzMwMjg
   	 * xODAwNCJ9fQ.Kk8jcUbHjJAQkRSHyDuFQr3NMEOSJEZc85VfER74tX6J9CuUllr8
   	 * 9WKUHUR7MA0-mWlptMRRhdgW1ZDt7g1uwQ&amp;
   	 * client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3A&amp;
   	 * client-assertion-type%3Ajwt-bearer&amp;
   	 * client_assertion=eyJraWQiOiJsdGFjZXNidyIsImFsZyI6IkVTMjU2In0.eyJ
   	 * pc3MiOiJzNkJoZFJrcXQzIiwic3ViIjoiczZCaGRSa3F0MyIsImF1ZCI6Imh0dHB
   	 * zOi8vc2VydmVyLmV4YW1wbGUuY29tIiwianRpIjoiYmRjLVhzX3NmLTNZTW80RlN
   	 * 6SUoyUSIsImlhdCI6MTUzNzgxOTQ4NiwiZXhwIjoxNTM3ODE5Nzc3fQ.Ybr8mg_3
   	 * E2OptOSsA8rnelYO_y1L-yFaF_j1iemM3ntB61_GN3APe5cl_-5a6cvGlP154XAK
   	 * 7fL-GaZSdnd9kg
	 * </pre>
	 *
	 * @param params The parameters.
	 *
	 * @return The CIBA grant.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static CIBAGrant parse(final Map<String, List<String>> params) throws ParseException {
		
		GrantType.ensure(GRANT_TYPE, params);
		
		String authReqIDString = MultivaluedMapUtils.getFirstValue(params, "auth_req_id");
		
		if (authReqIDString == null || authReqIDString.trim().isEmpty()) {
			String msg = "Missing or empty auth_req_id parameter";
			throw new ParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
		}
		
		AuthRequestID authRequestID = AuthRequestID.parse(authReqIDString);
		
		return new CIBAGrant(authRequestID);
	}
}
