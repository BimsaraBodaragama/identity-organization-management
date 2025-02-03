/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.RoleWithAudienceDO;

/**
 * Model that represent each shared result with shared status.
 */
public class SharedResult {

    private int id;
    private UserAssociation userAssociation;
    private SharingType sharingType;
    private RoleWithAudienceDO role;
    private SharedStatus status;
    private String statusDetail;
    private Throwable error;

    private SharedResult(Builder builder) {

        this.id = builder.id;
        this.userAssociation = builder.userAssociation;
        this.sharingType = builder.sharingType;
        this.role = builder.role;
        this.status = builder.status;
        this.statusDetail = builder.statusDetail;
        this.error = builder.error;
    }

    /**
     * Converts the current instance into a Builder for modification.
     */
    public Builder toBuilder() {

        return new Builder()
                .id(this.id)
                .userAssociation(this.userAssociation)
                .sharingType(this.sharingType)
                .role(this.role)
                .status(this.status)
                .statusDetail(this.statusDetail)
                .error(this.error);
    }

    public int getId() {

        return id;
    }

    public void setId(int id) {

        this.id = id;
    }

    public UserAssociation getUserAssociation() {

        return userAssociation;
    }

    public void setUserAssociation(
            UserAssociation userAssociation) {

        this.userAssociation = userAssociation;
    }

    public SharingType getSharingType() {

        return sharingType;
    }

    public void setSharingType(SharingType sharingType) {

        this.sharingType = sharingType;
    }

    public RoleWithAudienceDO getRole() {

        return role;
    }

    public void setRole(RoleWithAudienceDO role) {

        this.role = role;
    }

    public SharedStatus getStatus() {

        return status;
    }

    public void setStatus(SharedStatus status) {

        this.status = status;
    }

    public String getStatusDetail() {

        return statusDetail;
    }

    public void setStatusDetail(String statusDetail) {

        this.statusDetail = statusDetail;
    }

    public Throwable getError() {

        return error;
    }

    public void setError(Throwable error) {

        this.error = error;
    }

    /**
     * Builder class for SharedResult.
     */
    public static class Builder {

        private int id;
        private UserAssociation userAssociation;
        private SharingType sharingType;
        private RoleWithAudienceDO role;
        private SharedStatus status;
        private String statusDetail;
        private Throwable error;

        public Builder id(int id) {

            this.id = id;
            return this;
        }

        public Builder userAssociation(UserAssociation userAssociation) {

            this.userAssociation = userAssociation;
            return this;
        }

        public Builder sharingType(SharingType sharingType) {

            this.sharingType = sharingType;
            return this;
        }

        public Builder role(RoleWithAudienceDO role) {

            this.role = role;
            return this;
        }

        public Builder status(SharedStatus status) {

            this.status = status;
            return this;
        }

        public Builder statusDetail(String statusDetail) {

            this.statusDetail = statusDetail;
            return this;
        }

        public Builder error(Throwable error) {

            this.error = error;
            return this;
        }

        public SharedResult build() {

            return new SharedResult(this);
        }
    }

    /**
     * Enum representing the possible statuses of a shared result.
     */
    public enum SharedStatus {

        SUCCESSFUL,
        FAILED
    }

    /**
     * Enum representing the result is from either sharing or unsharing.
     */
    public enum SharingType {

        SHARE,
        UNSHARE
    }
}
