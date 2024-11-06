/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
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

/**
 * SQL constants for organization user sharing.
 */
public class SQLConstants {

    public static final String CREATE_ORGANIZATION_USER_ASSOCIATION = "INSERT INTO UM_ORG_USER_ASSOCIATION(" +
            "UM_USER_ID, UM_ORG_ID, UM_ASSOCIATED_USER_ID, UM_ASSOCIATED_ORG_ID) VALUES(?, ?, ?, ?)";
    public static final String CREATE_ORGANIZATION_USER_ASSOCIATION_EXTENDED = "INSERT INTO UM_ORG_USER_ASSOCIATION(" +
            "UM_USER_ID, UM_ORG_ID, UM_ASSOCIATED_USER_ID, UM_ASSOCIATED_ORG_ID, " +
            "UM_ASSOCIATION_INITIATED_ORG_ID, UM_ASSOCIATION_TYPE) VALUES(?, ?, ?, ?, ?, ?)";
    public static final String DELETE_ORGANIZATION_USER_ASSOCIATION_FOR_SHARED_USER = "DELETE FROM " +
            "UM_ORG_USER_ASSOCIATION WHERE UM_USER_ID = ? AND UM_ASSOCIATED_ORG_ID = ?";
    public static final String DELETE_ORGANIZATION_USER_ASSOCIATIONS_FOR_ROOT_USER = "DELETE FROM " +
            "UM_ORG_USER_ASSOCIATION WHERE UM_ASSOCIATED_USER_ID = ? AND UM_ASSOCIATED_ORG_ID = ?";
    public static final String GET_ORGANIZATION_USER_ASSOCIATIONS_FOR_USER = "SELECT UM_USER_ID, UM_ORG_ID, " +
            "UM_ASSOCIATED_USER_ID, UM_ASSOCIATED_ORG_ID " +
            "FROM UM_ORG_USER_ASSOCIATION WHERE UM_ASSOCIATED_USER_ID = ? AND UM_ASSOCIATED_ORG_ID = ?";
    public static final String GET_ORGANIZATION_USER_ASSOCIATION_FOR_ROOT_USER_IN_ORG = "SELECT UM_USER_ID, " +
            "UM_ORG_ID, UM_ASSOCIATED_USER_ID, UM_ASSOCIATED_ORG_ID FROM UM_ORG_USER_ASSOCIATION " +
            "WHERE UM_ASSOCIATED_USER_ID = ? AND UM_ORG_ID = ?";
    public static final String GET_ORGANIZATION_USER_ASSOCIATIONS_FOR_SHARED_USER = "SELECT UM_USER_ID, UM_ORG_ID, " +
            "UM_ASSOCIATED_USER_ID, UM_ASSOCIATED_ORG_ID FROM UM_ORG_USER_ASSOCIATION " +
            "WHERE UM_USER_ID = ? AND UM_ORG_ID = ?";
    public static final String GET_ORGANIZATION_USER_ASSOCIATIONS_FOR_SHARED_USER_BY_USER_ID =
            "SELECT UM_USER_ID, UM_ASSOCIATED_USER_ID, UM_ASSOCIATED_ORG_ID " +
                    "FROM UM_ORG_USER_ASSOCIATION WHERE UM_USER_ID = ?";
    public static final String CHECK_COLUMN_EXISTENCE_IN_TABLE =
            "SELECT COUNT(*) AS count FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ? AND COLUMN_NAME = ?";
    public static final String ADD_COLUMN_TO_TABLE = "ALTER TABLE %s ADD %s VARCHAR(255) DEFAULT '%s'";

    public static final String DEFAULT_VALUE_NOT_SPECIFIED = "NOT_SPECIFIED";

    /**
     * SQL placeholders related to organization user sharing SQL operations.
     */
    public static final class SQLPlaceholders {

        public static final String COLUMN_NAME_USER_ID = "UM_USER_ID";
        public static final String COLUMN_NAME_ORG_ID = "UM_ORG_ID";
        public static final String COLUMN_NAME_ASSOCIATED_USER_ID = "UM_ASSOCIATED_USER_ID";
        public static final String COLUMN_NAME_ASSOCIATED_ORG_ID = "UM_ASSOCIATED_ORG_ID";
        public static final String COLUMN_NAME_ASSOCIATION_INITIATED_ORG_ID = "UM_ASSOCIATION_INITIATED_ORG_ID";
        public static final String COLUMN_NAME_ASSOCIATION_TYPE = "UM_ASSOCIATION_TYPE";
        public static final String COUNT_ALIAS = "count";
    }

}
