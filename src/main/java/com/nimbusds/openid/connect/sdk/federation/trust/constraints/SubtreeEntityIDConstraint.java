/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2020, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.federation.trust.constraints;


import java.util.Objects;

import net.jcip.annotations.Immutable;

import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;


/**
 * Subtree entity ID constraint.
 *
 * <p>Example: {@code https://.example.com} matches
 * {@code https://my.example.com}, {@code https://my.host.example.com}, etc.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Federation 1.0, section 5.2.2.
 *     <li>RFC 5280, section 4.2.1.10.
 * </ul>
 */
@Immutable
public final class SubtreeEntityIDConstraint extends EntityIDConstraint {
	
	
	private final String scheme;
	
	
	private final String hostNameAndRemainderPattern;
	
	
	/**
	 * Creates a new subtree entity ID constraint.
	 *
	 * @param entityIDPattern The entity ID pattern to match. Must not be
	 *                        {@code null}.
	 */
	public SubtreeEntityIDConstraint(final String entityIDPattern) {
		
		if (entityIDPattern.startsWith("https://")) {
			scheme = "https://";
		} else if (entityIDPattern.startsWith("http://")) {
			scheme = "http://";
		} else {
			throw new IllegalArgumentException("The entity ID pattern must be an URI with https or http scheme");
		}
		
		hostNameAndRemainderPattern = entityIDPattern.substring(scheme.length());
		
		if (! hostNameAndRemainderPattern.startsWith(".")) {
			throw new IllegalArgumentException("The host part of the entity ID pattern must start with dot (.)");
		}
	}
	
	
	@Override
	public boolean matches(final EntityID entityID) {
		
		String schemeIN;
		
		if (entityID.getValue().startsWith("https://")) {
			schemeIN = "https://";
		} else if (entityID.getValue().startsWith("http://")) {
			schemeIN = "http://";
		} else {
			return false;
		}
		
		if (! schemeIN.equals(scheme)) {
			return false;
		}
		
		String patternIN = entityID.getValue().substring(schemeIN.length());
		
		return patternIN.endsWith(hostNameAndRemainderPattern);
	}
	
	
	@Override
	public String toString() {
		return scheme + hostNameAndRemainderPattern;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof SubtreeEntityIDConstraint)) return false;
		SubtreeEntityIDConstraint that = (SubtreeEntityIDConstraint) o;
		return scheme.equals(that.scheme) &&
			hostNameAndRemainderPattern.equals(that.hostNameAndRemainderPattern);
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(scheme, hostNameAndRemainderPattern);
	}
}
