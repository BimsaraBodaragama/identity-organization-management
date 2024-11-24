/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.organization.resource.sharing.policy.management.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.database.utils.jdbc.NamedJdbcTemplate;
import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.database.utils.jdbc.exceptions.TransactionException;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.SharedAttributeType;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.exception.ResourceSharingPolicyMgtException;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.exception.ResourceSharingPolicyMgtServerException;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.models.ResourceSharingPolicy;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.models.SharedResourceAttribute;

import java.util.ArrayList;
import java.util.List;

import static org.wso2.carbon.identity.organization.management.service.util.Utils.getNewTemplate;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingConstants.ErrorMessage.ERROR_CODE_CREATION_OF_SHARED_RESOURCE_ATTRIBUTE_BUILDER_FAILED;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingConstants.ErrorMessage.ERROR_CODE_RESOURCE_SHARED_RESOURCE_ATTRIBUTE_CREATION_FAILED;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingConstants.ErrorMessage.ERROR_CODE_RESOURCE_SHARED_RESOURCE_ATTRIBUTE_DELETION_FAILED;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingConstants.ErrorMessage.ERROR_CODE_RESOURCE_SHARING_POLICY_CREATION_FAILED;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingConstants.ErrorMessage.ERROR_CODE_RESOURCE_SHARING_POLICY_DELETION_FAILED;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingConstants.ErrorMessage.ERROR_CODE_RETRIEVING_SHARED_RESOURCE_ATTRIBUTES_FAILED;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingSQLConstants.CREATE_RESOURCE_SHARING_POLICY;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingSQLConstants.DELETE_RESOURCE_SHARING_POLICY;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingSQLConstants.DELETE_SHARED_RESOURCE_ATTRIBUTE;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingSQLConstants.GET_SHARED_RESOURCE_ATTRIBUTES;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingSQLConstants.INSERT_SHARED_RESOURCE_ATTRIBUTE;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingSQLConstants.SQLPlaceholders.DB_SCHEMA_COLUMN_NAME_INITIATING_ORG_ID;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingSQLConstants.SQLPlaceholders.DB_SCHEMA_COLUMN_NAME_POLICY_HOLDING_ORG_ID;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingSQLConstants.SQLPlaceholders.DB_SCHEMA_COLUMN_NAME_RESOURCE_ID;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingSQLConstants.SQLPlaceholders.DB_SCHEMA_COLUMN_NAME_RESOURCE_SHARING_POLICY_ID;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingSQLConstants.SQLPlaceholders.DB_SCHEMA_COLUMN_NAME_RESOURCE_TYPE;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingSQLConstants.SQLPlaceholders.DB_SCHEMA_COLUMN_NAME_SHARED_ATTRIBUTE_ID;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingSQLConstants.SQLPlaceholders.DB_SCHEMA_COLUMN_NAME_SHARED_ATTRIBUTE_TYPE;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingSQLConstants.SQLPlaceholders.DB_SCHEMA_COLUMN_NAME_SHARING_POLICY;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingSQLConstants.SQLPlaceholders.DB_SCHEMA_COLUMN_NAME_UM_ID;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.util.ResourceSharingUtils.handleServerException;

/**
 * DAO implementation for handling user sharing policies.
 */
public class ResourceSharingPolicyHandlerDAOImpl implements ResourceSharingPolicyHandlerDAO {

    private static final Log LOG = LogFactory.getLog(ResourceSharingPolicyHandlerDAOImpl.class);

    @Override
    public int addResourceSharingPolicyRecord(ResourceSharingPolicy resourceSharingPolicy)
            throws ResourceSharingPolicyMgtServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            return namedJdbcTemplate.executeInsert(CREATE_RESOURCE_SHARING_POLICY, namedPreparedStatement -> {
                namedPreparedStatement.setString(DB_SCHEMA_COLUMN_NAME_RESOURCE_ID,
                        resourceSharingPolicy.getResourceId());
                namedPreparedStatement.setString(DB_SCHEMA_COLUMN_NAME_RESOURCE_TYPE,
                        resourceSharingPolicy.getResourceType().name());
                namedPreparedStatement.setString(DB_SCHEMA_COLUMN_NAME_INITIATING_ORG_ID,
                        resourceSharingPolicy.getInitiatingOrgId());
                namedPreparedStatement.setString(DB_SCHEMA_COLUMN_NAME_POLICY_HOLDING_ORG_ID,
                        resourceSharingPolicy.getPolicyHoldingOrgId());
                namedPreparedStatement.setString(DB_SCHEMA_COLUMN_NAME_SHARING_POLICY,
                        resourceSharingPolicy.getSharingPolicy().getPolicyCode());
            }, null, true, DB_SCHEMA_COLUMN_NAME_UM_ID);
        } catch (DataAccessException e) {
            throw handleServerException(ERROR_CODE_RESOURCE_SHARING_POLICY_CREATION_FAILED, e,
                    resourceSharingPolicy.getResourceType(), resourceSharingPolicy.getResourceId());
        }
    }

    @Override
    public void addSharedResourceAttributes(List<SharedResourceAttribute> sharedResourceAttributes)
            throws ResourceSharingPolicyMgtServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();

        try {
            namedJdbcTemplate.withTransaction(template -> {
                template.executeBatchInsert(INSERT_SHARED_RESOURCE_ATTRIBUTE, (namedPreparedStatement -> {
                    for (SharedResourceAttribute sharedResourceAttribute : sharedResourceAttributes) {
                        namedPreparedStatement.setInt(DB_SCHEMA_COLUMN_NAME_RESOURCE_SHARING_POLICY_ID,
                                sharedResourceAttribute.getResourceSharingPolicyId());
                        namedPreparedStatement.setString(DB_SCHEMA_COLUMN_NAME_SHARED_ATTRIBUTE_TYPE,
                                sharedResourceAttribute.getSharedAttributeType().name());
                        namedPreparedStatement.setString(DB_SCHEMA_COLUMN_NAME_SHARED_ATTRIBUTE_ID,
                                sharedResourceAttribute.getSharedAttributeId());
                        namedPreparedStatement.addBatch();
                    }
                }), null);
                return null;
            });
        } catch (TransactionException e) {
            throw handleServerException(ERROR_CODE_RESOURCE_SHARED_RESOURCE_ATTRIBUTE_CREATION_FAILED);
        }
    }

    @Override
    public boolean deleteResourceSharingPolicyRecordById(int resourceSharingPolicyId)
            throws ResourceSharingPolicyMgtServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            namedJdbcTemplate.executeUpdate(DELETE_RESOURCE_SHARING_POLICY,
                    namedPreparedStatement -> namedPreparedStatement.setInt(
                            DB_SCHEMA_COLUMN_NAME_RESOURCE_SHARING_POLICY_ID,
                            resourceSharingPolicyId));
            return true;
        } catch (DataAccessException e) {
            throw handleServerException(ERROR_CODE_RESOURCE_SHARING_POLICY_DELETION_FAILED);
        }
    }

    @Override
    public boolean deleteSharedResourceAttributesByResourceSharingPolicyId(int resourceSharingPolicyId,
                                                                           SharedAttributeType sharedAttributeType)
            throws ResourceSharingPolicyMgtServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            namedJdbcTemplate.executeUpdate(DELETE_SHARED_RESOURCE_ATTRIBUTE, namedPreparedStatement -> {
                namedPreparedStatement.setInt(DB_SCHEMA_COLUMN_NAME_RESOURCE_SHARING_POLICY_ID,
                        resourceSharingPolicyId);
                namedPreparedStatement.setString(DB_SCHEMA_COLUMN_NAME_SHARED_ATTRIBUTE_TYPE,
                        sharedAttributeType.name());
            });
            return true;
        } catch (DataAccessException e) {
            throw handleServerException(ERROR_CODE_RESOURCE_SHARED_RESOURCE_ATTRIBUTE_DELETION_FAILED);
        }
    }

    @Override
    public List<SharedResourceAttribute> getSharedResourceAttributesBySharingPolicyId(int resourceSharingPolicyId)
            throws ResourceSharingPolicyMgtServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        List<SharedResourceAttribute> sharedResourceAttributes = new ArrayList<>();

        try {
            namedJdbcTemplate.executeQuery(GET_SHARED_RESOURCE_ATTRIBUTES, (resultSet, rowNumber) -> {

                SharedResourceAttribute.Builder attributesBuilder = SharedResourceAttribute.builder()
                        .withResourceSharingPolicyId(
                                resultSet.getInt(DB_SCHEMA_COLUMN_NAME_RESOURCE_SHARING_POLICY_ID))
                        .withSharedAttributeType(SharedAttributeType.valueOf(
                                resultSet.getString(DB_SCHEMA_COLUMN_NAME_SHARED_ATTRIBUTE_TYPE)))
                        .withSharedAttributeId(
                                resultSet.getString(DB_SCHEMA_COLUMN_NAME_SHARED_ATTRIBUTE_ID));
                try {
                    SharedResourceAttribute sharedResourceAttribute = attributesBuilder.build();
                    sharedResourceAttribute.setSharedResourceAttributeId(resultSet.getInt(DB_SCHEMA_COLUMN_NAME_UM_ID));
                    sharedResourceAttributes.add(sharedResourceAttribute);
                } catch (ResourceSharingPolicyMgtException e) {
                    LOG.debug(ERROR_CODE_CREATION_OF_SHARED_RESOURCE_ATTRIBUTE_BUILDER_FAILED.toString());
                }

                return null;
            }, namedPreparedStatement -> namedPreparedStatement.setInt(
                    DB_SCHEMA_COLUMN_NAME_RESOURCE_SHARING_POLICY_ID,
                    resourceSharingPolicyId));

        } catch (DataAccessException e) {
            throw handleServerException(ERROR_CODE_RETRIEVING_SHARED_RESOURCE_ATTRIBUTES_FAILED);
        }

        return sharedResourceAttributes;
    }

    @Override
    public List<ResourceSharingPolicy> getResourceSharingPoliciesByOrgIds(List<String> orgIds)
            throws ResourceSharingPolicyMgtServerException {

        return new ArrayList<>();
    }



   /* //@Override
    public List<ResourceSharingPolicy> getResourceSharingPoliciesByOrgIds2(List<String> orgIds)
            throws ResourceSharingPolicyMgtServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        List<ResourceSharingPolicy> resourceSharingPolicies = new ArrayList<>();

        try {
            namedJdbcTemplate.executeQuery(GET_RESOURCE_SHARING_POLICIES_BY_ORG_IDS, (resultSet, rowNumber) -> {
                ResourceSharingPolicy policy = new ResourceSharingPolicy();
                policy.setResourceSharingPolicyId(resultSet.getInt(DB_SCHEMA_COLUMN_NAME_UM_ID));
                policy.setResourceId(resultSet.getString(DB_SCHEMA_COLUMN_NAME_RESOURCE_ID));
                policy.setResourceType(ResourceType.valueOf(resultSet.getString(DB_SCHEMA_COLUMN_NAME_RESOURCE_TYPE)));
                policy.setInitiatingOrgId(resultSet.getString(DB_SCHEMA_COLUMN_NAME_INITIATING_ORG_ID));
                policy.setPolicyHoldingOrgId(resultSet.getString(DB_SCHEMA_COLUMN_NAME_POLICY_HOLDING_ORG_ID));
                policy.setSharingPolicy(
                        PolicyEnum.getPolicyByPolicyCode(resultSet.getString(DB_SCHEMA_COLUMN_NAME_SHARING_POLICY)));

                resourceSharingPolicies.add(policy);
                return null;
            }, namedPreparedStatement -> namedPreparedStatement.setString("orgIds", String.join(",", orgIds)));

        } catch (DataAccessException e) {
            throw handleServerException(ERROR_CODE_RETRIEVING_RESOURCE_SHARING_POLICY_FAILED);
        }

        return resourceSharingPolicies;
    }

    @Override
    public List<ResourceSharingPolicy> getResourceSharingPoliciesByOrgIds(List<String> orgIds)
            throws ResourceSharingPolicyMgtServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        List<ResourceSharingPolicy> policies = new ArrayList<>();

        // Create dynamic placeholders for the orgIds
        StringJoiner joiner = new StringJoiner(", ", "(", ")");
        for (int i = 0; i < orgIds.size(); i++) {
            joiner.add("?");
        }
        String query = GET_RESOURCE_SHARING_POLICIES_BY_ORG_IDS.replace(":orgIds", joiner.toString());

        try {
            namedJdbcTemplate.executeQuery(query, (resultSet, rowNumber) -> {
                ResourceSharingPolicy policy = new ResourceSharingPolicy();
                policy.setResourceSharingPolicyId(resultSet.getInt(DB_SCHEMA_COLUMN_NAME_UM_ID));
                policy.setResourceId(resultSet.getString(DB_SCHEMA_COLUMN_NAME_RESOURCE_ID));
                policy.setResourceType(ResourceType.valueOf(resultSet.getString(DB_SCHEMA_COLUMN_NAME_RESOURCE_TYPE)));
                policy.setInitiatingOrgId(resultSet.getString(DB_SCHEMA_COLUMN_NAME_INITIATING_ORG_ID));
                policy.setPolicyHoldingOrgId(resultSet.getString(DB_SCHEMA_COLUMN_NAME_POLICY_HOLDING_ORG_ID));
                policy.setSharingPolicy(
                        PolicyEnum.getPolicyByPolicyCode(resultSet.getString(DB_SCHEMA_COLUMN_NAME_SHARING_POLICY)));
                policies.add(policy);
                return null;
            }, namedPreparedStatement -> {
                for (int i = 0; i < orgIds.size(); i++) {
                    namedPreparedStatement.setString(i + 1, orgIds.get(i));
                }
            });
        } catch (DataAccessException e) {
            throw handleServerException(ERROR_CODE_RETRIEVING_RESOURCE_SHARING_POLICY_FAILED);
        }
        return policies;
    }*/

}
