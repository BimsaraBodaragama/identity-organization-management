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
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementServerException;

import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.ResourceSharingSQLConstants.CREATE_RESOURCE_SHARING_POLICY;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.ResourceSharingSQLConstants.DELETE_RESOURCE_SHARING_POLICY;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_CREATE_ORGANIZATION_USER_ASSOCIATION;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_DELETE_ORGANIZATION_USER_ASSOCIATION_FOR_SHARED_USER;
import static org.wso2.carbon.identity.organization.management.service.util.Utils.getNewTemplate;
import static org.wso2.carbon.identity.organization.management.service.util.Utils.handleServerException;
/**
 * DAO implementation for handling user sharing policies.
 */
public class ResourceSharingPolicyHandlerDAOImpl implements ResourceSharingPolicyHandlerDAO {

    @Override
    public void createResourceSharingPolicyRecord(String resource, String resourceType, String initiatedOrganization,
                                                  String policyHoldingOrganization, String policy)
            throws OrganizationManagementServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        //TODO: Concern with mssql
        try {//TODO: Go with placeholder names rather than 1,2,3,4,5
            namedJdbcTemplate.withTransaction(template -> {
                template.executeInsert(CREATE_RESOURCE_SHARING_POLICY, namedPreparedStatement -> {
                    namedPreparedStatement.setString(1, resource);
                    namedPreparedStatement.setString(2, resourceType);
                    namedPreparedStatement.setString(3, initiatedOrganization);
                    namedPreparedStatement.setString(4, policyHoldingOrganization);
                    namedPreparedStatement.setString(5, policy);
                }, null, false);
                return null;
            });
        } catch (TransactionException e) {
            //TODO: RENAME THE ERROR
            throw handleServerException(ERROR_CODE_ERROR_CREATE_ORGANIZATION_USER_ASSOCIATION, e, resource);
        }
    }

    @Override
    public boolean deleteResourceSharingPolicyRecord(String resource, String resourceType, String initiatedOrganization,
                                                     String policyHoldingOrganization)
            throws OrganizationManagementServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            namedJdbcTemplate.executeUpdate(DELETE_RESOURCE_SHARING_POLICY, namedPreparedStatement -> {
                namedPreparedStatement.setString(1, resource);
                namedPreparedStatement.setString(2, resourceType);
                namedPreparedStatement.setString(3, initiatedOrganization);
                namedPreparedStatement.setString(4, policyHoldingOrganization);
            });
            return true;
        } catch (DataAccessException e) {
            //TODO: RENAME THE ERROR
            throw handleServerException(ERROR_CODE_ERROR_DELETE_ORGANIZATION_USER_ASSOCIATION_FOR_SHARED_USER, e,
                    resource);
        }
    }
}
