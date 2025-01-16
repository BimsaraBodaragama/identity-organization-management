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

package org.wso2.carbon.identity.organization.management.organization.user.sharing.dao;

import org.wso2.carbon.database.utils.jdbc.NamedJdbcTemplate;
import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.database.utils.jdbc.exceptions.TransactionException;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserAssociation;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementServerException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.CHECK_COLUMN_EXISTENCE_IN_TABLE;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.CREATE_ORGANIZATION_USER_ASSOCIATION;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.CREATE_ORGANIZATION_USER_ASSOCIATION_EXTENDED;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.DELETE_ORGANIZATION_USER_ASSOCIATIONS_FOR_ROOT_USER;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.DELETE_ORGANIZATION_USER_ASSOCIATION_FOR_SHARED_USER;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.GET_ORGANIZATION_USER_ASSOCIATIONS_FOR_SHARED_USER;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.GET_ORGANIZATION_USER_ASSOCIATIONS_FOR_SHARED_USER_BY_USER_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.GET_ORGANIZATION_USER_ASSOCIATIONS_FOR_USER;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.GET_ORGANIZATION_USER_ASSOCIATION_FOR_ROOT_USER_IN_ORG;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.SQLPlaceholders.COLUMN_NAME_ASSOCIATED_ORG_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.SQLPlaceholders.COLUMN_NAME_ASSOCIATED_USER_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.SQLPlaceholders.COLUMN_NAME_ORG_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.SQLPlaceholders.COLUMN_NAME_USER_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.SQLPlaceholders.COUNT_ALIAS;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ORG_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.USER_ID;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_CREATE_ORGANIZATION_USER_ASSOCIATION;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_DELETE_ORGANIZATION_USER_ASSOCIATIONS;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_DELETE_ORGANIZATION_USER_ASSOCIATION_FOR_SHARED_USER;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_GET_ORGANIZATION_USER_ASSOCIATIONS;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_GET_ORGANIZATION_USER_ASSOCIATION_FOR_USER_AT_SHARED_ORG;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_GET_ORGANIZATION_USER_ASSOCIATION_OF_SHARED_USER;
import static org.wso2.carbon.identity.organization.management.service.util.Utils.getNewTemplate;
import static org.wso2.carbon.identity.organization.management.service.util.Utils.getOrganizationId;
import static org.wso2.carbon.identity.organization.management.service.util.Utils.handleServerException;

/**
 * DAO implementation for managing organization user associations.
 */
public class OrganizationUserSharingDAOImpl implements OrganizationUserSharingDAO {

    @Override
    public void createOrganizationUserAssociation(String userId, String orgId, String associatedUserId,
                                                  String associatedOrgId) throws OrganizationManagementServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            namedJdbcTemplate.withTransaction(template -> {
                template.executeInsert(CREATE_ORGANIZATION_USER_ASSOCIATION, namedPreparedStatement -> {
                    namedPreparedStatement.setString(1, userId);
                    namedPreparedStatement.setString(2, orgId);
                    namedPreparedStatement.setString(3, associatedUserId);
                    namedPreparedStatement.setString(4, associatedOrgId);
                }, null, false);
                return null;
            });
        } catch (TransactionException e) {
            throw handleServerException(ERROR_CODE_ERROR_CREATE_ORGANIZATION_USER_ASSOCIATION, e, associatedUserId);
        }
    }

    @Override
    public void createOrganizationUserAssociation(String userId, String orgId, String associatedUserId,
                                                  String associatedOrgId, String associationInitiatedOrgId,
                                                  String associationType) throws OrganizationManagementServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            namedJdbcTemplate.withTransaction(template -> {
                template.executeInsert(CREATE_ORGANIZATION_USER_ASSOCIATION_EXTENDED, namedPreparedStatement -> {
                    namedPreparedStatement.setString(1, userId);
                    namedPreparedStatement.setString(2, orgId);
                    namedPreparedStatement.setString(3, associatedUserId);
                    namedPreparedStatement.setString(4, associatedOrgId);
                    namedPreparedStatement.setString(5, associationInitiatedOrgId);
                    namedPreparedStatement.setString(6, associationType);
                }, null, false);
                return null;
            });
        } catch (TransactionException e) {
            throw handleServerException(ERROR_CODE_ERROR_CREATE_ORGANIZATION_USER_ASSOCIATION, e, associatedUserId);
        }
    }

    public boolean deleteUserAssociationOfUserByAssociatedOrg(String userId, String associatedOrgId)
            throws OrganizationManagementServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            namedJdbcTemplate.executeUpdate(DELETE_ORGANIZATION_USER_ASSOCIATION_FOR_SHARED_USER,
                    namedPreparedStatement -> {
                        namedPreparedStatement.setString(1, userId);
                        namedPreparedStatement.setString(2, associatedOrgId);
                    });
            return true;
        } catch (DataAccessException e) {
            throw handleServerException(ERROR_CODE_ERROR_DELETE_ORGANIZATION_USER_ASSOCIATION_FOR_SHARED_USER, e,
                    userId);
        }
    }

    @Override
    public boolean deleteUserAssociationsOfAssociatedUser(String associatedUserId, String associatedOrgId)
            throws OrganizationManagementServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            namedJdbcTemplate.executeUpdate(DELETE_ORGANIZATION_USER_ASSOCIATIONS_FOR_ROOT_USER,
                    namedPreparedStatement -> {
                        namedPreparedStatement.setString(1, associatedUserId);
                        namedPreparedStatement.setString(2, associatedOrgId);
                    });
            return true;
        } catch (DataAccessException e) {
            throw handleServerException(ERROR_CODE_ERROR_DELETE_ORGANIZATION_USER_ASSOCIATIONS, e);
        }
    }

    @Override
    public List<UserAssociation> getUserAssociationsOfAssociatedUser(String associatedUserId, String associatedOrgId)
            throws OrganizationManagementServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            return namedJdbcTemplate.executeQuery(GET_ORGANIZATION_USER_ASSOCIATIONS_FOR_USER,
                    (resultSet, rowNumber) -> {
                        UserAssociation userAssociation = new UserAssociation();
                        userAssociation.setUserId(resultSet.getString(COLUMN_NAME_USER_ID));
                        userAssociation.setOrganizationId(resultSet.getString(COLUMN_NAME_ORG_ID));
                        userAssociation.setAssociatedUserId(resultSet.getString(COLUMN_NAME_ASSOCIATED_USER_ID));
                        userAssociation.setUserResidentOrganizationId(
                                resultSet.getString(COLUMN_NAME_ASSOCIATED_ORG_ID));
                        return userAssociation;
                    },
                    namedPreparedStatement -> {
                        namedPreparedStatement.setString(1, associatedUserId);
                        namedPreparedStatement.setString(2, associatedOrgId);
                    });
        } catch (DataAccessException e) {
            throw handleServerException(ERROR_CODE_ERROR_GET_ORGANIZATION_USER_ASSOCIATIONS, e);
        }
    }

    @Override
    public UserAssociation getUserAssociationOfAssociatedUserByOrgId(String associatedUserId, String orgId)
            throws OrganizationManagementServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            return namedJdbcTemplate.fetchSingleRecord(GET_ORGANIZATION_USER_ASSOCIATION_FOR_ROOT_USER_IN_ORG,
                    (resultSet, rowNumber) -> {
                        UserAssociation userAssociation = new UserAssociation();
                        userAssociation.setUserId(resultSet.getString(COLUMN_NAME_USER_ID));
                        userAssociation.setOrganizationId(resultSet.getString(COLUMN_NAME_ORG_ID));
                        userAssociation.setAssociatedUserId(resultSet.getString(COLUMN_NAME_ASSOCIATED_USER_ID));
                        userAssociation.setUserResidentOrganizationId(
                                resultSet.getString(COLUMN_NAME_ASSOCIATED_ORG_ID));
                        return userAssociation;
                    },
                    namedPreparedStatement -> {
                        namedPreparedStatement.setString(1, associatedUserId);
                        namedPreparedStatement.setString(2, orgId);
                    });
        } catch (DataAccessException e) {
            throw handleServerException(ERROR_CODE_ERROR_GET_ORGANIZATION_USER_ASSOCIATION_FOR_USER_AT_SHARED_ORG, e,
                    orgId);
        }
    }

    @Override
    public UserAssociation getUserAssociation(String userId, String organizationId)
            throws OrganizationManagementServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            return namedJdbcTemplate.fetchSingleRecord(GET_ORGANIZATION_USER_ASSOCIATIONS_FOR_SHARED_USER,
                    (resultSet, rowNumber) -> {
                        UserAssociation userAssociation = new UserAssociation();
                        userAssociation.setUserId(resultSet.getString(COLUMN_NAME_USER_ID));
                        userAssociation.setOrganizationId(resultSet.getString(COLUMN_NAME_ORG_ID));
                        userAssociation.setAssociatedUserId(resultSet.getString(COLUMN_NAME_ASSOCIATED_USER_ID));
                        userAssociation.setUserResidentOrganizationId(
                                resultSet.getString(COLUMN_NAME_ASSOCIATED_ORG_ID));
                        return userAssociation;
                    },
                    namedPreparedStatement -> {
                        namedPreparedStatement.setString(1, userId);
                        namedPreparedStatement.setString(2, organizationId);
                    });
        } catch (DataAccessException e) {
            throw handleServerException(ERROR_CODE_ERROR_GET_ORGANIZATION_USER_ASSOCIATION_OF_SHARED_USER, e,
                    userId, organizationId);
        }
    }

    @Override
    public boolean areRequiredColumnsPresent(String tableName, String... columnNames)
            throws OrganizationManagementServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();

        try {
            for (String columnName : columnNames) {
                // Check if the specified column exists in the table
                boolean columnExists = namedJdbcTemplate.executeQuery(
                        CHECK_COLUMN_EXISTENCE_IN_TABLE,
                        (resultSet, rowNumber) -> resultSet.getInt(COUNT_ALIAS) > 0,
                        namedPreparedStatement -> {
                            namedPreparedStatement.setString(1, tableName);
                            namedPreparedStatement.setString(2, columnName);
                        }).get(0);

                if (!columnExists) {
                    return false; // Return false if any required column is missing
                }
            }
            return true; // All specified columns are present
        } catch (DataAccessException e) {
            throw handleServerException(ERROR_CODE_ERROR_GET_ORGANIZATION_USER_ASSOCIATIONS, e, tableName);
        }
    }

    @Override
    public Map<String, String> getUserAssociationDetailsByUserId(String userId)
            throws OrganizationManagementServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();

        Map<String, String> resultMap = new HashMap<>();
        try {
            List<UserAssociation> userAssociations = namedJdbcTemplate.executeQuery(
                    GET_ORGANIZATION_USER_ASSOCIATIONS_FOR_SHARED_USER_BY_USER_ID,
                    (resultSet, rowNumber) -> {
                        UserAssociation userAssociation = new UserAssociation();
                        userAssociation.setUserId(resultSet.getString(COLUMN_NAME_USER_ID));
                        userAssociation.setAssociatedUserId(resultSet.getString(COLUMN_NAME_ASSOCIATED_USER_ID));
                        userAssociation.setUserResidentOrganizationId(
                                resultSet.getString(COLUMN_NAME_ASSOCIATED_ORG_ID));
                        return userAssociation;
                    },
                    namedPreparedStatement -> namedPreparedStatement.setString(1, userId));

            if (userAssociations.isEmpty()) {
                // No records found; return the input userId and default resident org value
                resultMap.put(USER_ID, userId);
                resultMap.put(ORG_ID, getOrganizationId());
            } else {
                // Get the first record
                UserAssociation firstAssociation = userAssociations.get(0);
                resultMap.put(USER_ID, firstAssociation.getAssociatedUserId());
                resultMap.put(ORG_ID, firstAssociation.getUserResidentOrganizationId());
            }

            return resultMap;
        } catch (DataAccessException e) {
            throw handleServerException(ERROR_CODE_ERROR_GET_ORGANIZATION_USER_ASSOCIATIONS, e, userId);
        }
    }

}
