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

import com.nimbusds.oauth2.sdk.ParseException;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;

import java.util.Collections;
import java.util.Set;
import java.util.UUID;


public class DeviceSecretTokenTest extends TestCase {


        private static final DeviceSecret DEVICE_SECRET = new DeviceSecret("WYqFXK7Q4HFnJv0hiT3Fgw.-oVkvSXgalUuMQDfEsh1lw");


        public void testLifeCycle() throws Exception {

                DeviceSecretToken token = new DeviceSecretToken(DEVICE_SECRET);
                assertEquals(DEVICE_SECRET, token.getDeviceSecret());
                assertEquals(DEVICE_SECRET.getValue(), token.getValue());
                assertEquals(DEVICE_SECRET.toString(), token.toString());

                Set<String> parameterNames = token.getParameterNames();
                assertEquals(Collections.singleton("device_secret"), parameterNames);

                JSONObject jsonObject = token.toJSONObject();
                assertEquals(DEVICE_SECRET.getValue(), jsonObject.get("device_secret"));
                assertEquals(1, jsonObject.size());

                assertEquals(DEVICE_SECRET, DeviceSecretToken.parse(jsonObject).getDeviceSecret());

                assertEquals(token, DeviceSecretToken.parse(jsonObject));
                assertEquals(token.hashCode(), DeviceSecretToken.parse(jsonObject).hashCode());
        }


        public void testInequality() {

                DeviceSecretToken t1 = new DeviceSecretToken(DEVICE_SECRET);
                DeviceSecretToken t2 = new DeviceSecretToken(new DeviceSecret(UUID.randomUUID().toString()));

                assertNotSame(t1, t2);
                assertNotSame(t1.hashCode(), t2.hashCode());
        }


        public void testParseNotFound() throws ParseException {

                assertNull(DeviceSecretToken.parse(new JSONObject()));
        }


        public void testParseEmptyDeviceSecretString() {

                JSONObject jsonObject = new JSONObject();
                jsonObject.put("device_secret", "");

                try {
                        DeviceSecretToken.parse(jsonObject);
                } catch (ParseException e) {
                        assertEquals("Illegal device secret", e.getMessage());
                }
        }
}