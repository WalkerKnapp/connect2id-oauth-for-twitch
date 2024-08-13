/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2024, Connect2id Ltd and contributors.
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

package com.nimbusds.openid.connect.sdk.nativesso;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.oauth2.sdk.token.TypelessToken;
import com.nimbusds.oauth2.sdk.tokenexchange.TokenExchangeGrant;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.net.URI;


public class ExampleTest {


        @Ignore
        @Test
        public void testExampleFlow() throws IOException, ParseException {

                ClientID nativeClient_1 = new ClientID("zae1Do9f");
                URI nativeClient_1_redirectURI = URI.create("https://app.example.com/cb");

                State state = new State();
                AuthenticationRequest authRequest = new AuthenticationRequest.Builder(
                        ResponseType.CODE,
                        new Scope("openid", "device_sso"),
                        nativeClient_1,
                        nativeClient_1_redirectURI)
                        .state(state)
                        .endpointURI(URI.create("https://c2id.com/login"))
                        .build();

                URI loginURI = authRequest.toURI();

                URI callback = null;

                AuthenticationResponse authResponse = AuthenticationResponseParser.parse(callback);

                if (! authResponse.indicatesSuccess()) {
                        System.err.println("Login failed: " + authResponse.toErrorResponse().getErrorObject());
                        return;
                }

                AuthenticationSuccessResponse authSuccess = authResponse.toSuccessResponse();

                if (! state.equals(authSuccess.getState())) {
                        System.err.println("State mismatch");
                        return;
                }

                TokenRequest tokenRequest = new TokenRequest.Builder(
                        URI.create("https://c2id.com/token"),
                        nativeClient_1,
                        new AuthorizationCodeGrant(authSuccess.getAuthorizationCode(), nativeClient_1_redirectURI))
                        .build();

                HTTPResponse httpResponse = tokenRequest.toHTTPRequest().send();

                OIDCTokenResponse tokenResponse = OIDCTokenResponse.parse(httpResponse);

                if (! tokenResponse.indicatesSuccess()) {
                        System.err.println(tokenResponse.toErrorResponse().getErrorObject());
                        return;
                }

                OIDCTokens oidcTokens = tokenResponse.toSuccessResponse().getOIDCTokens();

                JWT idToken = oidcTokens.getIDToken();
                DeviceSecret deviceSecret = oidcTokens.getDeviceSecret();

                if (deviceSecret == null) {
                        System.out.println("Native SSO not supported");
                        return;
                }

                // Native client 2
                ClientID nativeClient_2 = new ClientID("Thai8cha");

                tokenRequest = new TokenRequest.Builder(
                        URI.create("https://c2id.com/token"),
                        nativeClient_2,
                        new TokenExchangeGrant(
                                new TypelessToken(idToken.serialize()),
                                TokenTypeURI.ID_TOKEN,
                                new TypelessToken(deviceSecret.getValue()),
                                TokenTypeURI.DEVICE_SECRET,
                                null,
                                new Audience("https://c2id.com").toSingleAudienceList()))
                        .scope(new Scope("openid"))
                        .build();

                httpResponse = tokenRequest.toHTTPRequest().send();

                tokenResponse = OIDCTokenResponse.parse(httpResponse);

                if (! tokenResponse.indicatesSuccess()) {
                        System.err.println(tokenResponse.toErrorResponse().getErrorObject());
                        return;
                }

                oidcTokens = tokenResponse.toSuccessResponse().getOIDCTokens();

                idToken = oidcTokens.getIDToken();
                deviceSecret = oidcTokens.getDeviceSecret();

                if (deviceSecret == null) {
                        System.out.println("Native SSO error");
                        return;
                }


        }
}
