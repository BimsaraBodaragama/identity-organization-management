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

import java.util.List;

/**
 * Model representing an organization with a specific policy for user sharing.
 */
public class PolicyBearingOrganization {

    private String orgId;
    private String policy;
    private List<SharedRole> roles;

    /**
     * Get the organization ID.
     *
     * @return Organization ID.
     */
    public String getOrgId() {

        return orgId;
    }

    /**
     * Set the organization ID.
     *
     * @param orgId Organization ID.
     */
    public void setOrgId(String orgId) {

        this.orgId = orgId;
    }

    /**
     * Get the sharing policy for the organization.
     *
     * @return Sharing policy.
     */
    public String getPolicy() {

        return policy;
    }

    /**
     * Set the sharing policy for the organization.
     *
     * @param policy Sharing policy.
     */
    public void setPolicy(String policy) {

        this.policy = policy;
    }

    /**
     * Get the list of role assignments for the organization.
     *
     * @return List of SharedRole.
     */
    public List<SharedRole> getRoles() {

        return roles;
    }

    /**
     * Set the list of role assignments for the organization.
     *
     * @param roles List of SharedRole.
     */
    public void setRoles(List<SharedRole> roles) {

        this.roles = roles;
    }
}
