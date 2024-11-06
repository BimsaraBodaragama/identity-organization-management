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

import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserAssociation;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementServerException;
import org.wso2.carbon.user.core.UserStoreException;

import java.util.List;
import java.util.Map;

/**
 * DAO interface for organization user sharing.
 */
public interface OrganizationUserSharingDAO {

    /**
     * Creates the association between the shared user and the actual user in the shared organization.
     *
     * @param userId           ID of the user who gets created in the organization.
     * @param orgId            Organization ID of the user shared organization.
     * @param associatedUserId Actual user ID of the associated user.
     * @param associatedOrgId  The organization ID where the associated user is managed.
     * @throws OrganizationManagementServerException If an error occurs while creating the organization user
     *                                               association.
     */
    void createOrganizationUserAssociation(String userId, String orgId, String associatedUserId, String associatedOrgId)
            throws OrganizationManagementServerException;

    /**
     * Creates the association between the shared user and the actual user in the shared organization.
     *
     * @param userId                    ID of the user who gets created in the organization.
     * @param orgId                     Organization ID of the user shared organization.
     * @param associatedUserId          Actual user ID of the associated user.
     * @param associatedOrgId           The organization ID where the associated user is managed.
     * @param associationInitiatedOrgId The organization ID where the association was initiated.
     * @param associationType           The type of association.
     * @throws OrganizationManagementServerException If an error occurs while creating the organization user
     *                                               association.
     */
    void createOrganizationUserAssociation(String userId, String orgId, String associatedUserId, String associatedOrgId,
                                           String associationInitiatedOrgId, String associationType)
            throws OrganizationManagementServerException;

    /**
     * Delete the organization user association for a shared user in a shared organization.
     *
     * @param userId          The ID of the user.
     * @param associatedOrgId The organization ID where the associated user's identity is managed.
     * @return True if the user association is deleted successfully.
     * @throws OrganizationManagementServerException If an error occurs while deleting the user association.
     */
    boolean deleteUserAssociationOfUserByAssociatedOrg(String userId, String associatedOrgId)
            throws OrganizationManagementServerException;

    /**
     * Delete all the organization user associations for a given user.
     *
     * @param associatedUserId Actual user ID of the user.
     * @param associatedOrgId  The organization ID where the user's identity is managed.
     * @return True if all the user associations are deleted successfully.
     * @throws OrganizationManagementServerException If an error occurs while deleting the user associations.
     */
    boolean deleteUserAssociationsOfAssociatedUser(String associatedUserId, String associatedOrgId)
            throws OrganizationManagementServerException;

    /**
     * Get all the user associations for a given user.
     *
     * @param associatedUserId Actual user ID of the user.
     * @param associatedOrgId  The organization ID where is the user is managed.
     * @return the list of {@link UserAssociation}s.
     * @throws OrganizationManagementServerException If an error occurs while fetching user associations.
     */
    List<UserAssociation> getUserAssociationsOfAssociatedUser(String associatedUserId, String associatedOrgId)
            throws OrganizationManagementServerException;

    /**
     * Get the organization user association of a given user in a given organization.
     *
     * @param associatedUserId ID of the associated user.
     * @param orgId            Organization ID where the user is shared.
     * @return The organization users association details.
     * @throws OrganizationManagementServerException If an error occurs while retrieving the user association.
     */
    UserAssociation getUserAssociationOfAssociatedUserByOrgId(String associatedUserId, String orgId)
            throws OrganizationManagementServerException;

    /**
     * Get the shared user association of a shared user.
     *
     * @param userId         The user ID of the shared user.
     * @param organizationId The organization ID of the user.
     * @return The user association of the user.
     * @throws OrganizationManagementServerException If an error occurs while retrieving the user association.
     */
    UserAssociation getUserAssociation(String userId, String organizationId)
            throws OrganizationManagementServerException;

    /**
     * Creates specified columns in the given database table if they do not already exist, with a defined default value.
     *
     * This method checks for the presence of each specified column in the given table. If any column is missing,
     * it will be created with the specified default value.
     *
     * @param tableName    The name of the table in which to check and potentially create columns.
     * @param defaultValue The default value to assign to each column if it needs to be created.
     * @param columns      The names of the columns to ensure exist in the table.
     * @throws UserStoreException                   If an error occurs while accessing the user store.
     * @throws InterruptedException                 If the operation is interrupted while creating the columns.
     * @throws OrganizationManagementServerException If an error occurs while creating columns in the table.
     */
    void createMissingColumns(String tableName, String defaultValue, String... columns)
            throws UserStoreException, OrganizationManagementServerException;

    /**
     * Checks if the specified columns are present in the given table in the database.
     *
     * This method verifies the presence of each of the specified columns in the specified table.
     * It returns true if all required columns exist, and false if any are missing.
     *
     * @param tableName   The name of the table to check for the presence of required columns.
     * @param columnNames The names of the columns that are required to exist in the table.
     * @return true if all specified columns are present in the table, false otherwise.
     * @throws UserStoreException If an error occurs while accessing the user store.
     * @throws InterruptedException If the operation is interrupted.
     */
    boolean areRequiredColumnsPresent(String tableName, String... columnNames)
            throws UserStoreException, OrganizationManagementServerException;

    /**
     * Retrieves the user association details for the given user ID.
     *
     * This method queries the UM_ORG_USER_ASSOCIATION table to fetch records based on the given user ID.
     * It returns a map containing the original user and organization details:
     * - If no records are found, the returned map contains the original user as the given user ID, and
     *   "originalOrg" as "Resident org of the input".
     * - If a single record is found, the map contains "originalUser" as the associated user ID, and
     *   "originalOrg" as the associated organization ID from the record.
     * - If multiple records are found, the map contains "originalUser" and "originalOrg" from the first record.
     *
     * @param userId The ID of the user for whom to fetch the association details.
     * @return A map with keys "originalUser" and "originalOrg", containing the corresponding user and organization details.
     * @throws OrganizationManagementServerException If an error occurs while retrieving the user association details.
     */
    Map<String, String> getUserAssociationDetailsByUserId(String userId) throws OrganizationManagementServerException;

}
