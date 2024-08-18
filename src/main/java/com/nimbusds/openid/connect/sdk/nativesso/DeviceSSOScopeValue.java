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

import com.nimbusds.oauth2.sdk.Scope;
import net.jcip.annotations.Immutable;


/**
 * Device SSO scope value.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Native SSO for Mobile Apps 1.0
 * </ul>
 */
@Immutable
public class DeviceSSOScopeValue extends Scope.Value {


        /**
         * Informs the authorisation server that the client is making an OpenID
         * Connect Native SSO request.
         */
        public static final DeviceSSOScopeValue DEVICE_SSO = new DeviceSSOScopeValue("device_sso");


        private DeviceSSOScopeValue(String value) {
                super(value);
        }

}
