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

import org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.PolicyEnum;

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
    private PolicyEnum appliedSharingPolicy;

    // Getters and Setters
    public String getSharingUserId() {
        return sharingUserId;
    }

    public void setSharingUserId(String sharingUserId) {
        this.sharingUserId = sharingUserId;
    }

    public String getSharingInitiatedOrgId() {
        return sharingInitiatedOrgId;
    }

    public void setSharingInitiatedOrgId(String sharingInitiatedOrg) {
        this.sharingInitiatedOrgId = sharingInitiatedOrg;
    }

    public String getTargetOrgId() {
        return targetOrgId;
    }

    public void setTargetOrgId(String targetOrgId) {
        this.targetOrgId = targetOrgId;
    }

    public String getOriginalUserId() {
        return originalUserId;
    }

    public void setOriginalUserId(String originalUserId) {
        this.originalUserId = originalUserId;
    }

    public String getOriginalUserName() {
        return originalUserName;
    }

    public void setOriginalUserName(String originalUserName) {
        this.originalUserName = originalUserName;
    }

    public String getOriginalOrgId() {
        return originalOrgId;
    }

    public void setOriginalOrgId(String originalOrgId) {
        this.originalOrgId = originalOrgId;
    }

    public String getSharingType() {
        return sharingType;
    }

    public void setSharingType(String sharingType) {
        this.sharingType = sharingType;
    }

    public List<String> getRoleIds() {
        return roleIds;
    }

    public void setRoleIds(List<String> roleIds) {
        this.roleIds = roleIds;
    }

    public PolicyEnum getAppliedSharingPolicy() {
        return appliedSharingPolicy;
    }

    public void setAppliedSharingPolicy(PolicyEnum appliedSharingPolicy) {
        this.appliedSharingPolicy = appliedSharingPolicy;
    }

    // Chaining methods
    public UserSharingDetails withSharingUserId(String sharingUserId) {
        this.sharingUserId = sharingUserId;
        return this;
    }

    public UserSharingDetails withSharingInitiatedOrgId(String sharingInitiatedOrg) {
        this.sharingInitiatedOrgId = sharingInitiatedOrg;
        return this;
    }

    public UserSharingDetails withTargetOrgId(String targetOrgId) {
        this.targetOrgId = targetOrgId;
        return this;
    }

    public UserSharingDetails withOriginalUserId(String originalUserId) {
        this.originalUserId = originalUserId;
        return this;
    }

    public UserSharingDetails withOriginalUserName(String originalUserName) {
        this.originalUserName = originalUserName;
        return this;
    }

    public UserSharingDetails withOriginalOrgId(String originalOrgId) {
        this.originalOrgId = originalOrgId;
        return this;
    }

    public UserSharingDetails withSharingType(String sharingType) {
        this.sharingType = sharingType;
        return this;
    }

    public UserSharingDetails withRoleIds(List<String> roleIds) {
        this.roleIds = roleIds;
        return this;
    }

    public UserSharingDetails withAppliedSharingPolicy(PolicyEnum appliedSharingPolicy) {
        this.appliedSharingPolicy = appliedSharingPolicy;
        return this;
    }
}
