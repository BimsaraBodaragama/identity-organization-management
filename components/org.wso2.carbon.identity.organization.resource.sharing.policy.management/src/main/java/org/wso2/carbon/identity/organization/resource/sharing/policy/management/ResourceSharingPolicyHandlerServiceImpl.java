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

package org.wso2.carbon.identity.organization.resource.sharing.policy.management;

import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceType;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.SharedAttributeType;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.dao.ResourceSharingPolicyHandlerDAO;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.dao.ResourceSharingPolicyHandlerDAOImpl;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.exception.ResourceSharingPolicyMgtClientException;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.exception.ResourceSharingPolicyMgtException;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.model.ResourceSharingPolicy;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.model.SharedResourceAttribute;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingConstants.ErrorMessage.ERROR_CODE_INAPPLICABLE_RESOURCE_TYPE_TO_POLICY;
import static org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceSharingConstants.ErrorMessage.ERROR_CODE_NULL_OR_EMPTY_INPUTS;

/**
 * Implementation of the core service for managing resource sharing policies.
 */
public class ResourceSharingPolicyHandlerServiceImpl implements ResourceSharingPolicyHandlerService {

    private static final ResourceSharingPolicyHandlerDAO RESOURCE_SHARING_POLICY_HANDLER_DAO =
            new ResourceSharingPolicyHandlerDAOImpl();

    @Override
    public int addResourceSharingPolicy(ResourceSharingPolicy resourceSharingPolicy)
            throws ResourceSharingPolicyMgtException {

        validateInputs(resourceSharingPolicy);

        List<ResourceType> applicableResources = resourceSharingPolicy.getSharingPolicy().getApplicableResources();
        if (applicableResources.contains(resourceSharingPolicy.getResourceType())) {

            return RESOURCE_SHARING_POLICY_HANDLER_DAO.addResourceSharingPolicy(resourceSharingPolicy);
        }
        throw new ResourceSharingPolicyMgtClientException(ERROR_CODE_INAPPLICABLE_RESOURCE_TYPE_TO_POLICY.getCode(),
                ERROR_CODE_INAPPLICABLE_RESOURCE_TYPE_TO_POLICY.getMessage());
    }

    @Override
    public ResourceSharingPolicy getResourceSharingPolicyById(int resourceSharingPolicyId)
            throws ResourceSharingPolicyMgtException {

        validateInputs(resourceSharingPolicyId);

        return RESOURCE_SHARING_POLICY_HANDLER_DAO.getResourceSharingPolicyById(resourceSharingPolicyId);
    }

    @Override
    public List<ResourceSharingPolicy> getResourceSharingPolicies(List<String> policyHoldingOrganizationIds)
            throws ResourceSharingPolicyMgtException {

        validateInputs(policyHoldingOrganizationIds);

        return RESOURCE_SHARING_POLICY_HANDLER_DAO.getResourceSharingPolicies(policyHoldingOrganizationIds);
    }

    @Override
    public Map<ResourceType, List<ResourceSharingPolicy>> getResourceSharingPoliciesGroupedByResourceType(
            List<String> policyHoldingOrganizationIds) throws ResourceSharingPolicyMgtException {

        validateInputs(policyHoldingOrganizationIds);

        return RESOURCE_SHARING_POLICY_HANDLER_DAO.getResourceSharingPoliciesGroupedByResourceType(
                policyHoldingOrganizationIds);
    }

    @Override
    public Map<String, List<ResourceSharingPolicy>> getResourceSharingPoliciesGroupedByPolicyHoldingOrgId(
            List<String> policyHoldingOrganizationIds) throws ResourceSharingPolicyMgtException {

        validateInputs(policyHoldingOrganizationIds);

        return RESOURCE_SHARING_POLICY_HANDLER_DAO.getResourceSharingPoliciesGroupedByPolicyHoldingOrgId(
                policyHoldingOrganizationIds);
    }

    @Override
    public boolean deleteResourceSharingPolicyRecordById(int resourceSharingPolicyId,
                                                         String deleteRequestInitiatedOrgId)
            throws ResourceSharingPolicyMgtException {

        validateInputs(deleteRequestInitiatedOrgId);

        return RESOURCE_SHARING_POLICY_HANDLER_DAO.deleteResourceSharingPolicyRecordById(resourceSharingPolicyId,
                deleteRequestInitiatedOrgId);
    }

    @Override
    public boolean deleteResourceSharingPolicyByResourceTypeAndId(ResourceType resourceType, String resourceId,
                                                                  String deleteRequestInitiatedOrgId)
            throws ResourceSharingPolicyMgtException {

        validateInputs(resourceType, resourceId, deleteRequestInitiatedOrgId);

        return RESOURCE_SHARING_POLICY_HANDLER_DAO.deleteResourceSharingPolicyByResourceTypeAndId(resourceType,
                resourceId, deleteRequestInitiatedOrgId);
    }

    @Override
    public boolean addSharedResourceAttributes(List<SharedResourceAttribute> sharedResourceAttributes)
            throws ResourceSharingPolicyMgtException {

        validateInputs(sharedResourceAttributes);

        List<SharedResourceAttribute> addableSharedResourceAttributes = new ArrayList<>();
        for (SharedResourceAttribute sharedResourceAttribute : sharedResourceAttributes) {

            ResourceSharingPolicy resourceSharingPolicy =
                    getResourceSharingPolicyById(sharedResourceAttribute.getResourceSharingPolicyId());

            if (isValidAttributeForTheResource(resourceSharingPolicy, sharedResourceAttribute)) {

                addableSharedResourceAttributes.add(sharedResourceAttribute);
            }
        }

        return RESOURCE_SHARING_POLICY_HANDLER_DAO.addSharedResourceAttributes(addableSharedResourceAttributes);
    }

    @Override
    public List<SharedResourceAttribute> getSharedResourceAttributesBySharingPolicyId(int resourceSharingPolicyId)
            throws ResourceSharingPolicyMgtException, DataAccessException {

        return RESOURCE_SHARING_POLICY_HANDLER_DAO.getSharedResourceAttributesBySharingPolicyId(
                resourceSharingPolicyId);
    }

    @Override
    public List<SharedResourceAttribute> getSharedResourceAttributesByType(SharedAttributeType attributeType)
            throws ResourceSharingPolicyMgtException {

        validateInputs(attributeType);

        return RESOURCE_SHARING_POLICY_HANDLER_DAO.getSharedResourceAttributesByType(attributeType);
    }

    @Override
    public List<SharedResourceAttribute> getSharedResourceAttributesById(String attributeId)
            throws ResourceSharingPolicyMgtException {

        validateInputs(attributeId);

        return RESOURCE_SHARING_POLICY_HANDLER_DAO.getSharedResourceAttributesById(attributeId);
    }

    @Override
    public List<SharedResourceAttribute> getSharedResourceAttributesByTypeAndId(SharedAttributeType attributeType,
                                                                                String attributeId)
            throws ResourceSharingPolicyMgtException {

        validateInputs(attributeType, attributeId);

        return RESOURCE_SHARING_POLICY_HANDLER_DAO.getSharedResourceAttributesByTypeAndId(attributeType, attributeId);
    }

    @Override
    public boolean deleteSharedResourceAttributesByResourceSharingPolicyId(int resourceSharingPolicyId,
                                                                           SharedAttributeType sharedAttributeType,
                                                                           String deleteRequestInitiatedOrgId)
            throws ResourceSharingPolicyMgtException {

        validateInputs(sharedAttributeType, deleteRequestInitiatedOrgId);

        return RESOURCE_SHARING_POLICY_HANDLER_DAO.deleteSharedResourceAttributesByResourceSharingPolicyId(
                resourceSharingPolicyId, sharedAttributeType, deleteRequestInitiatedOrgId);
    }

    @Override
    public boolean deleteSharedResourceAttributeByAttributeTypeAndId(SharedAttributeType attributeType,
                                                                     String attributeId,
                                                                     String deleteRequestInitiatedOrgId)
            throws ResourceSharingPolicyMgtException {

        validateInputs(attributeType, attributeId, deleteRequestInitiatedOrgId);

        return RESOURCE_SHARING_POLICY_HANDLER_DAO.deleteSharedResourceAttributeByAttributeTypeAndId(attributeType,
                attributeId, deleteRequestInitiatedOrgId);
    }

    private boolean isValidAttributeForTheResource(ResourceSharingPolicy resourceSharingPolicy,
                                                   SharedResourceAttribute sharedResourceAttribute) {

        return resourceSharingPolicy != null && resourceSharingPolicy.getResourceType()
                .isApplicableAttributeType(sharedResourceAttribute.getSharedAttributeType());
    }

    private void validateInputs(Object... inputs) throws ResourceSharingPolicyMgtClientException {

        for (Object input : inputs) {
            if (input == null) {
                throw new ResourceSharingPolicyMgtClientException(ERROR_CODE_NULL_OR_EMPTY_INPUTS.getCode(),
                        ERROR_CODE_NULL_OR_EMPTY_INPUTS.getMessage());
            }

            if (input instanceof List<?>) {
                for (Object o : (List<?>) input) {
                    if (o == null) {
                        throw new ResourceSharingPolicyMgtClientException(ERROR_CODE_NULL_OR_EMPTY_INPUTS.getCode(),
                                ERROR_CODE_NULL_OR_EMPTY_INPUTS.getMessage());
                    }
                }
            }
        }
    }
}
