/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.organization.management.organization.user.sharing.constant;

import java.util.Optional;

/**
 * Enum representing user sharing policies with additional fields for code, name, applicable resources, and details.
 */
public enum PolicyEnum {

    ALL_EXISTING_ORGS_ONLY(
            "GEN-001",
            "AllExistingOrgsOnly",
            "ALL_EXISTING_ORGS_ONLY",
            "User",
            "All existing organizations",
            "This policy applies when the resource needs to be shared with all existing organizations. " +
                    "Newly created organizations will not be included under this policy."),
    ALL_EXISTING_AND_FUTURE_ORGS(
            "GEN-002",
            "AllExistingAndFutureOrgs",
            "ALL_EXISTING_AND_FUTURE_ORGS",
            "User",
            "All existing organizations and future organizations",
            "This policy applies when the resource needs to be shared with all existing and future " +
                    "organizations."),
    IMMEDIATE_EXISTING_ORGS_ONLY(
            "GEN-003",
            "ImmediateExistingOrgsOnly",
            "IMMEDIATE_EXISTING_ORGS_ONLY",
            "Users",
            "Only existing immediate organizations",
            "This policy applies when the resource needs to be shared with all existing immediate child " +
                    "organizations. Newly created immediate child organizations will not be included under this " +
                    "policy."),
    IMMEDIATE_EXISTING_AND_FUTURE_ORGS(
            "GEN-004",
            "ImmediateExistingAndFutureOrgs",
            "IMMEDIATE_EXISTING_AND_FUTURE_ORGS",
            "Users",
            "Only existing immediate organizations and future immediate organizations",
            "This policy applies when the resource needs to be shared with all immediate child " +
                    "organizations, including future additions to the immediate child level."),
    SELECTED_ORG_ONLY(
            "SEL-001",
            "SelectedOrgOnly",
            "SELECTED_ORG_ONLY",
            "User",
            "Only the selected organization",
            "This policy applies when the resource needs to be shared with only the selected " +
                    "organization. Newly created child organizations of this organization will not be included " +
                    "under this policy."),
    SELECTED_ORG_WITH_ALL_EXISTING_CHILDREN_ONLY(
            "SEL-002",
            "SelectedOrgWithAllExistingChildrenOnly",
            "SELECTED_ORG_WITH_ALL_EXISTING_CHILDREN_ONLY",
            "User",
            "The selected organization and all existing children",
            "This policy applies when the resource needs to be shared with the selected organization and " +
                    "all of its existing children. Newly created child organizations of this organization will not " +
                    "be included under this policy."),
    SELECTED_ORG_WITH_ALL_EXISTING_AND_FUTURE_CHILDREN(
            "SEL-003",
            "SelectedOrgWithAllExistingAndFutureChildren",
            "SELECTED_ORG_WITH_ALL_EXISTING_AND_FUTURE_CHILDREN",
            "User",
            "This organization and all existing and future children",
            "This policy applies when the resource needs to be shared with the selected organization and " +
                    "all of its children, existing and future."),
    SELECTED_ORG_WITH_EXISTING_IMMEDIATE_CHILDREN_ONLY(
            "SEL-004",
            "SelectedOrgWithExistingImmediateChildrenOnly",
            "SELECTED_ORG_WITH_EXISTING_IMMEDIATE_CHILDREN_ONLY",
            "User",
            "The selected organization and all existing immediate children",
            "This policy applies when the resource needs to be shared with the selected organization and " +
                    "all of its existing immediate children. Newly created immediate children will not be included " +
                    "under this policy."),
    SELECTED_ORG_WITH_EXISTING_IMMEDIATE_AND_FUTURE_CHILDREN(
            "SEL-005",
            "SelectedOrgWithExistingImmediateAndFutureChildren",
            "SELECTED_ORG_WITH_EXISTING_IMMEDIATE_AND_FUTURE_CHILDREN",
            "User",
            "This organization and all existing and future immediate children",
            "This policy applies when the resource needs to be shared with the selected organization and " +
                    "all of its immediate children, including future additions.");

    private final String policyCode;
    private final String policyName;
    private final String value;
    private final String applicableResources;
    private final String policyDetails;
    private final String description;

    /**
     * Constructor to initialize the user sharing policy enum.
     *
     * @param policyCode          Unique code representing the sharing policy.
     * @param policyName          Name of the sharing policy (e.g., All_Orgs, Immediate_Children).
     * @param applicableResources Type of resources to which the policy applies (General/Selective).
     * @param description         Short description of the sharing policy.
     * @param policyDetails       Additional details of the sharing policy.
     */
    PolicyEnum(String policyCode, String policyName, String value, String applicableResources, String description,
               String policyDetails) {

        this.policyCode = policyCode;
        this.policyName = policyName;
        this.value = value;
        this.applicableResources = applicableResources;
        this.description = description;
        this.policyDetails = policyDetails;
    }

    /**
     * Get the unique code of the sharing policy.
     *
     * @return Unique code of the sharing policy.
     */
    public String getPolicyCode() {

        return policyCode;
    }

    /**
     * Get the name of the sharing policy.
     *
     * @return Name of the sharing policy.
     */
    public String getPolicyName() {

        return policyName;
    }

    /**
     * Get the value of the sharing policy.
     *
     * @return Value of the sharing policy.
     */
    public String getValue() {

        return value;
    }

    /**
     * Get the applicable resource type for the sharing policy.
     *
     * @return Type of the applicable resource.
     */
    public String getApplicableResources() {

        return applicableResources;
    }

    /**
     * Get the short description of the sharing policy.
     *
     * @return Description of the sharing policy.
     */
    public String getDescription() {

        return description;
    }

    /**
     * Get additional details for the sharing policy.
     *
     * @return Details of the sharing policy.
     */
    public String getPolicyDetails() {

        return policyDetails;
    }

    /**
     * Get the PolicyEnum based on the given policy code.
     *
     * @param policyCode Code of the sharing policy.
     * @return Corresponding PolicyEnum, wrapped in Optional.
     */
    public static Optional<PolicyEnum> getByPolicyCode(String policyCode) {

        for (PolicyEnum policy : PolicyEnum.values()) {
            if (policy.policyCode.equals(policyCode)) {
                return Optional.of(policy);
            }
        }
        return Optional.empty();
    }

    /**
     * Get the PolicyEnum based on the given policy value.
     *
     * @param value Code of the sharing policy.
     * @return Corresponding PolicyEnum, wrapped in Optional.
     */
    public static Optional<PolicyEnum> getByValue(String value) {

        for (PolicyEnum policy : PolicyEnum.values()) {
            if (policy.value.equals(value)) {
                return Optional.of(policy);
            }
        }
        return Optional.empty();
    }

    /**
     * Validate and get the PolicyEnum based on the given requested policy.
     *
     * @param requestedPolicy Requested policy as an Object (should be an instance of String).
     * @return Corresponding PolicyEnum.
     * @throws IllegalArgumentException if the requested policy is invalid or not found.
     */
    public static PolicyEnum validateAndGetPolicy(Object requestedPolicy) {

        if (requestedPolicy instanceof String) {
            String policyStr = (String) requestedPolicy;
            for (PolicyEnum policy : PolicyEnum.values()) {
                if (policy.value.equalsIgnoreCase(policyStr) || policy.policyCode.equalsIgnoreCase(policyStr) ||
                        policy.policyName.equalsIgnoreCase(policyStr)) {
                    return policy;
                }
            }
        }
        throw new IllegalArgumentException("Invalid requested policy: " + requestedPolicy);
    }
}
