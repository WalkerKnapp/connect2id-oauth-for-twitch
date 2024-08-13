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

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Identifier;
import net.jcip.annotations.Immutable;


/**
 * CIBA token delivery mode.
 *
 * <ul>
 *      <li>OpenID Connect CIBA Flow - Core 1.0
 * </ul>
 */
@Immutable
public final class BackChannelTokenDeliveryMode extends Identifier {
	
	
	private static final long serialVersionUID = -7661605920720830935L;
	
	
	/**
	 * Push delivery mode. The OP / AS the tokens to a client callback URI.
	 */
	public static final BackChannelTokenDeliveryMode PUSH = new BackChannelTokenDeliveryMode("push");
	
	
	/**
	 * Poll delivery mode. The client polls the OP / AS token endpoint to
	 * obtain the tokens.
	 */
	public static final BackChannelTokenDeliveryMode POLL = new BackChannelTokenDeliveryMode("poll");

	
	/**
	 * Ping delivery mode. The OP / AS sends a notification to a client
	 * endpoint that the tokens are available at the token endpoint.
	 */
	public static final BackChannelTokenDeliveryMode PING = new BackChannelTokenDeliveryMode("ping");

	
	/**
	 * Creates a new CIBA token delivery mode with the specified value.
	 *
	 * @param value The CIBA token delivery mode value. Must not be
	 *              {@code null}.
	 */
	public BackChannelTokenDeliveryMode(final String value) {
		super(value);
	}
	

	@Override
	public boolean equals(final Object object) {

		return object instanceof BackChannelTokenDeliveryMode && this.toString().equals(object.toString());
	}
	

	/**
	 * Parses a CIBA token delivery mode from the specified string.
	 * 
	 * @param value The string value.
	 *
	 * @return The CIBA token delivery mode.
	 *
	 * @throws ParseException On a illegal CIBA token delivery mode.
	 */
	public static BackChannelTokenDeliveryMode parse(final String value)
		throws ParseException  {
		
		if (PING.getValue().equals(value)) {
			return PING;
		} else if (POLL.getValue().equals(value)) {
			return POLL;
		} else if (PUSH.getValue().equals(value)) {
			return PUSH;
		} else {
			throw new ParseException("Invalid CIBA token delivery mode: " + value);
		}
	}
}
