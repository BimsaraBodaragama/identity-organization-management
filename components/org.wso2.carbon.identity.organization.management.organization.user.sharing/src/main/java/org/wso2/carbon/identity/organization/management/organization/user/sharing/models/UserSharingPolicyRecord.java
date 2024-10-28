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

package org.wso2.carbon.identity.organization.management.organization.user.sharing.models;

import org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SharingPolicyEnum;

import java.util.List;
import java.util.UUID;

/**
 * Model representing the user organization sharing policy record.
 * This record keeps track of user sharing details based on policy,
 * initiated organization, and roles shared under the specific policy.
 */
public class UserSharingPolicyRecord {

    private UUID sharingRecordId;
    private String userId;
    private String sharingInitiatedOrgId;
    private String policyBearingOrgId;
    private SharingPolicyEnum sharingPolicy;
    private List<SharedRole> roles;

    /**
     * Get the sharing record ID.
     *
     * @return Sharing record ID.
     */
    public UUID getSharingRecordId() {
        return sharingRecordId;
    }

    /**
     * Set the sharing record ID.
     *
     * @param sharingRecordId Sharing record ID.
     */
    public void setSharingRecordId(UUID sharingRecordId) {
        this.sharingRecordId = sharingRecordId;
    }

    /**
     * Get the user ID.
     *
     * @return User ID.
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Set the user ID.
     *
     * @param userId User ID.
     */
    public void setUserId(String userId) {
        this.userId = userId;
    }

    /**
     * Get the organization ID where sharing was initiated.
     *
     * @return Sharing initiated organization ID.
     */
    public String getSharingInitiatedOrgId() {
        return sharingInitiatedOrgId;
    }

    /**
     * Set the organization ID where sharing was initiated.
     *
     * @param sharingInitiatedOrgId Sharing initiated organization ID.
     */
    public void setSharingInitiatedOrgId(String sharingInitiatedOrgId) {
        this.sharingInitiatedOrgId = sharingInitiatedOrgId;
    }

    /**
     * Get the policy-bearing organization ID.
     *
     * @return Policy-bearing organization ID.
     */
    public String getPolicyBearingOrgId() {
        return policyBearingOrgId;
    }

    /**
     * Set the policy-bearing organization ID.
     *
     * @param policyBearingOrgId Policy-bearing organization ID.
     */
    public void setPolicyBearingOrgId(String policyBearingOrgId) {
        this.policyBearingOrgId = policyBearingOrgId;
    }

    /**
     * Get the sharing policy.
     *
     * @return Sharing policy.
     */
    public SharingPolicyEnum getSharingPolicy() {
        return sharingPolicy;
    }

    /**
     * Set the sharing policy.
     *
     * @param sharingPolicy Sharing policy.
     */
    public void setSharingPolicy(SharingPolicyEnum sharingPolicy) {
        this.sharingPolicy = sharingPolicy;
    }

    /**
     * Get the roles shared under this policy.
     *
     * @return List of roles.
     */
    public List<SharedRole> getRoles() {
        return roles;
    }

    /**
     * Set the roles shared under this policy.
     *
     * @param roles List of roles.
     */
    public void setRoles(List<SharedRole> roles) {
        this.roles = roles;
    }
}
