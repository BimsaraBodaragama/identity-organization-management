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

package org.wso2.carbon.identity.organization.management.organization.user.sharing.models;

import org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.PolicyEnum;

import java.util.List;

/**
 * Model that contains the user share selective data object.
 */
public class UserShareSelective extends UserShareBase {

    private String organizationId;

    public String getOrganizationId() {

        return organizationId;
    }

    public void setOrganizationId(String organizationId) {

        this.organizationId = organizationId;
    }

    // Chaining method
    public UserShareSelective withOrganizationId(String organizationId) {
        this.organizationId = organizationId;
        return this;
    }

    @Override
    public UserShareSelective withUserId(String userId) {
        super.withUserId(userId);
        return this;
    }

    @Override
    public UserShareSelective withPolicy(PolicyEnum policy) {
        super.withPolicy(policy);
        return this;
    }

    @Override
    public UserShareSelective withRoles(List<String> roles) {
        super.withRoles(roles);
        return this;
    }
}
