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
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserAssociation;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementServerException;

import java.util.List;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.CREATE_ORGANIZATION_USER_ASSOCIATION;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.CREATE_ORGANIZATION_USER_ASSOCIATION_EXTENDED;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.DELETE_ORGANIZATION_USER_ASSOCIATIONS_FOR_ROOT_USER;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.DELETE_ORGANIZATION_USER_ASSOCIATION_FOR_SHARED_USER;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.GET_ORGANIZATION_USER_ASSOCIATIONS_FOR_SHARED_USER;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.GET_ORGANIZATION_USER_ASSOCIATIONS_FOR_USER;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.GET_ORGANIZATION_USER_ASSOCIATION_FOR_ROOT_USER_IN_ORG;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.SQLPlaceholders.COLUMN_NAME_ASSOCIATED_ORG_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.SQLPlaceholders.COLUMN_NAME_ASSOCIATED_USER_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.SQLPlaceholders.COLUMN_NAME_ORG_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SQLConstants.SQLPlaceholders.COLUMN_NAME_USER_ID;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_CREATE_ORGANIZATION_USER_ASSOCIATION;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_DELETE_ORGANIZATION_USER_ASSOCIATIONS;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_DELETE_ORGANIZATION_USER_ASSOCIATION_FOR_SHARED_USER;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_GET_ORGANIZATION_USER_ASSOCIATIONS;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_GET_ORGANIZATION_USER_ASSOCIATION_FOR_USER_AT_SHARED_ORG;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_GET_ORGANIZATION_USER_ASSOCIATION_OF_SHARED_USER;
import static org.wso2.carbon.identity.organization.management.service.util.Utils.getNewTemplate;
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

//    @Override
//    public boolean areRequiredAssociationColumnsPresent() throws OrganizationManagementServerException {
//        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
//        String tableName = "UM_ORG_USER_ASSOCIATION";
//
//        try {
//            // Check if the 'UM_ASSOCIATION_INITIATED_ORG_ID' column exists
//            boolean associationInitiatedOrgIdExists = namedJdbcTemplate.executeQuery(
//                    "SELECT COUNT(*) AS count FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ? AND COLUMN_NAME = 'UM_ASSOCIATION_INITIATED_ORG_ID'",
//                    (resultSet, rowNumber) -> resultSet.getInt("count") > 0,
//                    namedPreparedStatement -> namedPreparedStatement.setString(1, tableName)
//                                                                                    ).get(0);
//
//            // Check if the 'UM_ASSOCIATION_TYPE' column exists
//            boolean associationTypeExists = namedJdbcTemplate.executeQuery(
//                    "SELECT COUNT(*) AS count FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ? AND COLUMN_NAME = 'UM_ASSOCIATION_TYPE'",
//                    (resultSet, rowNumber) -> resultSet.getInt("count") > 0,
//                    namedPreparedStatement -> namedPreparedStatement.setString(1, tableName)
//                                                                          ).get(0);
//            return associationInitiatedOrgIdExists && associationTypeExists;
//        } catch (DataAccessException e) {
//            throw handleServerException(ERROR_CODE_ERROR_GET_ORGANIZATION_USER_ASSOCIATIONS, e, tableName);
//        }
//    }
//

    @Override
    public boolean areRequiredColumnsPresent(String tableName, String... columnNames)
            throws OrganizationManagementServerException {
        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();

        try {
            for (String columnName : columnNames) {
                // Check if the specified column exists in the table
                boolean columnExists = namedJdbcTemplate.executeQuery(
                        "SELECT COUNT(*) AS count FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ? AND COLUMN_NAME = ?",
                        (resultSet, rowNumber) -> resultSet.getInt("count") > 0,
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



    /*@Override
    public boolean ensureColumnsExist() throws OrganizationManagementServerException {
        try (Connection connection = getConnection()) {  // Assuming getConnection() gives a JDBC connection
            // Check if columns exist
            boolean associationInitiatedOrgIdExists = checkColumnExists(connection, "UM_ORG_USER_ASSOCIATION", "associationInitiatedOrgId");
            boolean associationTypeExists = checkColumnExists(connection, "UM_ORG_USER_ASSOCIATION", "associationType");

            // Add missing columns if needed
            if (!associationInitiatedOrgIdExists) {
                addColumn(connection, "ALTER TABLE UM_ORG_USER_ASSOCIATION ADD associationInitiatedOrgId VARCHAR(255) DEFAULT 'NOT_SPECIFIED'");
            }
            if (!associationTypeExists) {
                addColumn(connection, "ALTER TABLE UM_ORG_USER_ASSOCIATION ADD associationType VARCHAR(255) DEFAULT 'NOT_SPECIFIED'");
            }

            // Re-check to ensure columns now exist
            associationInitiatedOrgIdExists = checkColumnExists(connection, "UM_ORG_USER_ASSOCIATION", "associationInitiatedOrgId");
            associationTypeExists = checkColumnExists(connection, "UM_ORG_USER_ASSOCIATION", "associationType");

            return associationInitiatedOrgIdExists && associationTypeExists;
        } catch (SQLException e) {
            throw new OrganizationManagementServerException("Error while ensuring columns exist", e.getMessage());
        }
    }

    // Helper method to check if a column exists using DatabaseMetaData
    private boolean checkColumnExists(Connection connection, String tableName, String columnName) throws SQLException {
        DatabaseMetaData metaData = connection.getMetaData();
        try (ResultSet resultSet = metaData.getColumns(null, null, tableName, columnName)) {
            return resultSet.next(); // Returns true if the column exists
        }
    }

    // Helper method to add a new column
    private void addColumn(Connection connection, String alterTableSQL) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(alterTableSQL)) {
            statement.executeUpdate();
        }
    }

    // Utility method to get a JDBC connection
    private Connection getConnection() throws SQLException {
        // Replace with your method of getting a JDBC connection
        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        return connection;
        //return DataSource.getConnection(); // Example, replace with actual connection retrieval
    }*/



//    @Override
//    public boolean createMissingColumns(String tableName, String columnName1, String columnName2) throws OrganizationManagementServerException {
//
//        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
//
//        try {
//            // Check if the 'UM_ASSOCIATION_INITIATED_ORG_ID' column exists
//            boolean associationInitiatedOrgIdExists = namedJdbcTemplate.executeQuery(
//                    "SELECT COUNT(*) AS count FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ? AND COLUMN_NAME = 'UM_ASSOCIATION_INITIATED_ORG_ID'",
//                    (resultSet, rowNumber) -> resultSet.getInt("count") > 0,
//                    namedPreparedStatement -> namedPreparedStatement.setString(1, tableName)
//                                                                                    ).get(0);
//
//            // Check if the 'UM_ASSOCIATION_TYPE' column exists
//            boolean associationTypeExists = namedJdbcTemplate.executeQuery(
//                    "SELECT COUNT(*) AS count FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ? AND COLUMN_NAME = 'UM_ASSOCIATION_TYPE'",
//                    (resultSet, rowNumber) -> resultSet.getInt("count") > 0,
//                    namedPreparedStatement -> namedPreparedStatement.setString(1, tableName)
//                                                                          ).get(0);
//
//            // Add the missing columns if they don't exist
//            if (!associationInitiatedOrgIdExists) {
//                namedJdbcTemplate.executeUpdate(
//                        "ALTER TABLE UM_ORG_USER_ASSOCIATION ADD UM_ASSOCIATION_INITIATED_ORG_ID VARCHAR(255) DEFAULT 'NOT_SPECIFIED'"
//                                               );
//            }
//            if (!associationTypeExists) {
//                namedJdbcTemplate.executeUpdate(
//                        "ALTER TABLE UM_ORG_USER_ASSOCIATION ADD UM_ASSOCIATION_TYPE VARCHAR(255) DEFAULT 'NOT_SPECIFIED'"
//                                               );
//            }
//
//            // Re-check to ensure columns now exist
//            associationInitiatedOrgIdExists = namedJdbcTemplate.executeQuery(
//                    "SELECT COUNT(*) AS count FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ? AND COLUMN_NAME = 'UM_ASSOCIATION_INITIATED_ORG_ID'",
//                    (resultSet, rowNumber) -> resultSet.getInt("count") > 0,
//                    namedPreparedStatement -> namedPreparedStatement.setString(1, tableName)
//                                                                            ).get(0);
//
//            associationTypeExists = namedJdbcTemplate.executeQuery(
//                    "SELECT COUNT(*) AS count FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ? AND COLUMN_NAME = 'UM_ASSOCIATION_TYPE'",
//                    (resultSet, rowNumber) -> resultSet.getInt("count") > 0,
//                    namedPreparedStatement -> namedPreparedStatement.setString(1, tableName)
//                                                                  ).get(0);
//
//            return associationInitiatedOrgIdExists && associationTypeExists;
//        } catch (DataAccessException e) {
//            throw handleServerException(ERROR_CODE_ERROR_GET_ORGANIZATION_USER_ASSOCIATIONS, e, tableName);
//        }
//    }

    @Override
    public void createMissingColumns(String tableName, String defaultValue, String... columnNames)
            throws OrganizationManagementServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();

        try {
            for (String columnName : columnNames) {
                //TODO: Check for each column name before altering -> Alter only if the column name does't exists
                //Dynamically generate the SQL statement to add each column with the specified default value if it doesn't already exist
                String sql = String.format("ALTER TABLE %s ADD %s VARCHAR(255) DEFAULT '%s'", tableName, columnName, defaultValue);
                namedJdbcTemplate.executeUpdate(sql);
            }
        } catch (DataAccessException e) {
            throw handleServerException(ERROR_CODE_ERROR_GET_ORGANIZATION_USER_ASSOCIATIONS, e, tableName);
        }
    }






}
