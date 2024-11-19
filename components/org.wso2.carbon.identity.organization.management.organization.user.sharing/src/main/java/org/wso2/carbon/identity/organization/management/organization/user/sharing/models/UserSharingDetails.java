/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.organization.management.organization.user.sharing.models;

import org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.PolicyEnum;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Model that contains the user sharing details data object.
 */
public class UserSharingDetails {

    private String sharingUserId;
    private String sharingInitiatedOrgId;
    private String targetOrgId;
    private String originalUserId;
    private String originalUserName;
    private String originalOrgId;
    private String sharingType;
    private List<String> roleIds;
    private PolicyEnum policy;

    private UserSharingDetails(Builder builder) {

        this.sharingUserId = builder.sharingUserId;
        this.sharingInitiatedOrgId = builder.sharingInitiatedOrgId;
        this.targetOrgId = builder.targetOrgId;
        this.originalUserId = builder.originalUserId;
        this.originalUserName = builder.originalUserName;
        this.originalOrgId = builder.originalOrgId;
        this.sharingType = builder.sharingType;
        this.roleIds = builder.roleIds;
        this.policy = builder.policy;
    }

    public String getSharingUserId() {

        return sharingUserId;
    }

    public String getSharingInitiatedOrgId() {

        return sharingInitiatedOrgId;
    }

    public String getTargetOrgId() {

        return targetOrgId;
    }

    public String getOriginalUserId() {

        return originalUserId;
    }

    public String getOriginalUserName() {

        return originalUserName;
    }

    public String getOriginalOrgId() {

        return originalOrgId;
    }

    public String getSharingType() {

        return sharingType;
    }

    public List<String> getRoleIds() {

        return roleIds;
    }

    public PolicyEnum getPolicy() {

        return policy;
    }

    public void setSharingUserId(String sharingUserId) {

        this.sharingUserId = sharingUserId;
    }

    public void setSharingInitiatedOrgId(String sharingInitiatedOrgId) {

        this.sharingInitiatedOrgId = sharingInitiatedOrgId;
    }

    public void setTargetOrgId(String targetOrgId) {

        this.targetOrgId = targetOrgId;
    }

    public void setOriginalUserId(String originalUserId) {

        this.originalUserId = originalUserId;
    }

    public void setOriginalUserName(String originalUserName) {

        this.originalUserName = originalUserName;
    }

    public void setOriginalOrgId(String originalOrgId) {

        this.originalOrgId = originalOrgId;
    }

    public void setSharingType(String sharingType) {

        this.sharingType = sharingType;
    }

    public void setRoleIds(List<String> roleIds) {

        this.roleIds = roleIds;
    }

    public void setPolicy(PolicyEnum policy) {

        this.policy = policy;
    }

    /**
     * Builder class for UserSharingDetails.
     */
    public static class Builder {

        private String sharingUserId = "";
        private String sharingInitiatedOrgId = "";
        private String targetOrgId = "";
        private String originalUserId = "";
        private String originalUserName = "";
        private String originalOrgId = "";
        private String sharingType = "";
        private List<String> roleIds = Collections.emptyList();
        private PolicyEnum policy = PolicyEnum.NO_SHARING;

        public Builder withSharingUserId(String sharingUserId) {

            this.sharingUserId = sharingUserId != null ? sharingUserId : "";
            return this;
        }

        public Builder withSharingInitiatedOrgId(String sharingInitiatedOrgId) {

            this.sharingInitiatedOrgId = sharingInitiatedOrgId != null ? sharingInitiatedOrgId : "";
            return this;
        }

        public Builder withTargetOrgId(String targetOrgId) {

            this.targetOrgId = targetOrgId != null ? targetOrgId : "";
            return this;
        }

        public Builder withOriginalUserId(String originalUserId) {

            this.originalUserId = originalUserId != null ? originalUserId : "";
            return this;
        }

        public Builder withOriginalUserName(String originalUserName) {

            this.originalUserName = originalUserName != null ? originalUserName : "";
            return this;
        }

        public Builder withOriginalOrgId(String originalOrgId) {

            this.originalOrgId = originalOrgId != null ? originalOrgId : "";
            return this;
        }

        public Builder withSharingType(String sharingType) {

            this.sharingType = sharingType != null ? sharingType : "Not Specified";
            return this;
        }

        public Builder withRoleIds(List<String> roleIds) {
            this.roleIds = roleIds != null ? new ArrayList<>(roleIds) : Collections.emptyList();
            return this;
        }

        public Builder withPolicy(PolicyEnum appliedSharingPolicy) {

            this.policy =
                    appliedSharingPolicy != null ? appliedSharingPolicy : PolicyEnum.NO_SHARING; // Assumed default
            return this;
        }

        public UserSharingDetails build() {

            return new UserSharingDetails(this);
        }
    }

    public UserSharingDetails copy() {
        return new UserSharingDetails.Builder()
                .withSharingUserId(this.sharingUserId)
                .withSharingInitiatedOrgId(this.sharingInitiatedOrgId)
                .withTargetOrgId(this.targetOrgId)
                .withOriginalUserId(this.originalUserId)
                .withOriginalUserName(this.originalUserName)
                .withOriginalOrgId(this.originalOrgId)
                .withSharingType(this.sharingType)
                .withRoleIds(this.roleIds != null ? new ArrayList<>(this.roleIds) : null)
                .withPolicy(this.policy)
                .build();
    }
}
