/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.organization.management.organization.user.sharing.constant;

/**
 * Enum representing sharing policies with corresponding codes and types.
 */
public enum SharingPolicyEnum {

    ALL_EXISTING_ORGS_AND_FUTURE_ORGS("GE-POL-001", "General",
            "All existing organizations and future organizations"),
    ONLY_EXISTING_IMMEDIATE_ORGS_AND_FUTURE_IMMEDIATE_ORGS("GE-POL-002", "General",
            "Only existing immediate organizations and future immediate organizations"),
    THIS_ORG_AND_ALL_EXISTING_AND_FUTURE_CHILDREN("SE-POL-001", "Selective",
            "This organization and all existing and future children");

    private final String code;
    private final String type;
    private final String description;

    /**
     * Constructor to initialize the sharing policy enum.
     *
     * @param code        Code representing the sharing policy.
     * @param type        Type of the sharing policy (General/Selective).
     * @param description Description of the sharing policy.
     */
    SharingPolicyEnum(String code, String type, String description) {
        this.code = code;
        this.type = type;
        this.description = description;
    }

    /**
     * Get the code of the sharing policy.
     *
     * @return Code of the sharing policy.
     */
    public String getCode() {
        return code;
    }

    /**
     * Get the type of the sharing policy.
     *
     * @return Type of the sharing policy (General/Selective).
     */
    public String getType() {
        return type;
    }

    /**
     * Get the description of the sharing policy.
     *
     * @return Description of the sharing policy.
     */
    public String getDescription() {
        return description;
    }

    /**
     * Get the SharingPolicyEnum based on the given code.
     *
     * @param code Code of the sharing policy.
     * @return Corresponding SharingPolicyEnum, or null if not found.
     */
    public static SharingPolicyEnum getByCode(String code) {
        for (SharingPolicyEnum policy : SharingPolicyEnum.values()) {
            if (policy.code.equals(code)) {
                return policy;
            }
        }
        return null;
    }

    /**
     * Get the SharingPolicyEnum based on the given type.
     *
     * @param type Type of the sharing policy (General/Selective).
     * @return Corresponding SharingPolicyEnum, or null if not found.
     */
    public static SharingPolicyEnum getByType(String type) {
        for (SharingPolicyEnum policy : SharingPolicyEnum.values()) {
            if (policy.type.equalsIgnoreCase(type)) {
                return policy;
            }
        }
        return null;
    }
}

