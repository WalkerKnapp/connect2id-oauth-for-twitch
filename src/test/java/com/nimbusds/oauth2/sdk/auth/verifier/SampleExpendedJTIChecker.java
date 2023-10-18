/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2023, Connect2id Ltd and contributors.
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

package com.nimbusds.oauth2.sdk.auth.verifier;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.verifier.Context;
import com.nimbusds.oauth2.sdk.auth.verifier.ExpendedJTIChecker;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertNotNull;


public class SampleExpendedJTIChecker implements ExpendedJTIChecker {


        private static String createKey(final JWTID jti, final ClientID clientID, final ClientAuthenticationMethod method) {

                MessageDigest md;
                try {
                        md = MessageDigest.getInstance("SHA-256");
                } catch (NoSuchAlgorithmException e) {
                        throw new RuntimeException(e);
                }

                md.update(jti.getValue().getBytes(StandardCharsets.UTF_8));
                md.update(clientID.getValue().getBytes(StandardCharsets.UTF_8));
                md.update(method.getValue().getBytes(StandardCharsets.UTF_8));

                return Base64URL.encode(md.digest()).toString();
        }


        private final Map<String, Date> map = new HashMap<>();


        @Override
        public boolean isExpended(JWTID jti, ClientID clientID, ClientAuthenticationMethod method, Context context) {

                assertNotNull(jti);
                assertNotNull(clientID);
                assertNotNull(method);

                String key = createKey(jti, clientID, method);

                Date exp = map.get(key);

                if (exp == null) {
                        return false;
                }

                return new Date().before(exp);
        }


        @Override
        public void markExpended(JWTID jti, Date exp, ClientID clientID, ClientAuthenticationMethod method, Context context) {

                assertNotNull(jti);
                assertNotNull(clientID);
                assertNotNull(method);

                map.put(createKey(jti, clientID, method), exp);
        }
}
