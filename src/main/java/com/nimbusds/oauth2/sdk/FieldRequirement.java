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

package com.nimbusds.oauth2.sdk;


/**
 * Enumeration representing the requirement level for a field..
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 1.1.
 * </ul>
 */
public enum FieldRequirement {

	/**
	 * Indicates that the field is required.
	 */
	REQUIRED,

	/**
	 * Indicates that the field is optional.
	 */
	OPTIONAL,

	/**
	 * Indicates that the field is not allowed.
	 */
	NOT_ALLOWED;
}