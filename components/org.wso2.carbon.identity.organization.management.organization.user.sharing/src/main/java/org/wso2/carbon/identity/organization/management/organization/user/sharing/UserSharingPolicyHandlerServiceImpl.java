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

package org.wso2.carbon.identity.organization.management.organization.user.sharing;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.PolicyEnum;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.dao.OrganizationUserSharingDAO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.dao.OrganizationUserSharingDAOImpl;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.dao.ResourceSharingPolicyHandlerDAO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.dao.ResourceSharingPolicyHandlerDAOImpl;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.exception.UserShareMgtException;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.exception.UserShareMgtServerException;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.internal.OrganizationUserSharingDataHolder;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.RoleWithAudienceDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareBaseDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareGeneralDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareSelective;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareSelectiveDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareSelectiveOrgDetailsDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserUnshareGeneralDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserUnshareSelectiveDO;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementServerException;
import org.wso2.carbon.identity.organization.management.service.model.BasicOrganization;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.PolicyEnum.getPolicyByValue;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.APPLICATION;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.LOG_INFO_SELECTIVE_SHARE_COMPLETED;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.NULL_INPUT_MESSAGE_SUFFIX;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ORGANIZATION;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ORG_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.POLICY_CODE_FOR_EXISTING_AND_FUTURE;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.POLICY_CODE_FOR_FUTURE_ONLY;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.USER_GROUPS;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.USER_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.USER_IDS;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.VALIDATION_CONTEXT_USER_SHARE_GENERAL_DO;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.VALIDATION_CONTEXT_USER_SHARE_SELECTIVE_DO;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.*;
import static org.wso2.carbon.identity.organization.management.service.util.Utils.getOrganizationId;
import static org.wso2.carbon.identity.organization.management.service.util.Utils.getUserStoreManager;

/**
 * Service implementation for handling user sharing policies.
 */
public class UserSharingPolicyHandlerServiceImpl implements UserSharingPolicyHandlerService {

    private static final Log LOG = LogFactory.getLog(UserSharingPolicyHandlerService2Impl.class);
    private static final ResourceSharingPolicyHandlerDAO resourceSharingPolicyHandlerDAO =
            new ResourceSharingPolicyHandlerDAOImpl();
    private static ConcurrentLinkedQueue<String> errorMessages;

    //SELECTIVE SHARE

    /**
     * Propagates the selective share of a user to specific organizations.
     *
     * @param userShareSelectiveDO Contains details for selective sharing.
     */
    @Override
    public void propagateUserSelectiveShare(UserShareSelectiveDO userShareSelectiveDO)
            throws UserShareMgtServerException, OrganizationManagementException, IdentityRoleManagementException,
            UserStoreException, IdentityApplicationManagementException {

        validateInput(userShareSelectiveDO, VALIDATION_CONTEXT_USER_SHARE_SELECTIVE_DO);
        List<UserShareSelectiveOrgDetailsDO> organizations = userShareSelectiveDO.getOrganizations();
        Map<String, List<String>> userCriteria = userShareSelectiveDO.getUserCriteria();

        for (UserShareSelectiveOrgDetailsDO organization : organizations) {
            propagateUserSelectiveShareWithOrganizationByUserCriteria(organization, userCriteria);
        }

        LOG.info(LOG_INFO_SELECTIVE_SHARE_COMPLETED);

        // After parallel processing, check for errors and handle them
        if (!errorMessages.isEmpty()) {
            throw new OrganizationManagementException(
                    "Failed to share user with some organizations: " + String.join(", ", errorMessages));
        }

    }

    private void propagateUserSelectiveShareWithOrganizationByUserCriteria(UserShareSelectiveOrgDetailsDO organization,
                                             Map<String, List<String>> userCriteria)
            throws OrganizationManagementException, IdentityApplicationManagementException,
            IdentityRoleManagementException, UserStoreException {

        for (Map.Entry<String, List<String>> criterion : userCriteria.entrySet()) {
            String criterionKey = criterion.getKey();
            List<String> criterionValues = criterion.getValue();

            switch (criterionKey) {
                case USER_IDS:
                    propagateUserSelectiveShareBasedOnUserIds(criterionValues, organization);
                    break;
                case USER_GROUPS:
                    // Placeholder for future user criteria.
                    break;
                default:
                    throw new OrganizationManagementException("Invalid user criterion provided: " + criterionKey);
            }
        }
    }

    private void propagateUserSelectiveShareBasedOnUserIds(List<String> userIds,
                                                           UserShareSelectiveOrgDetailsDO organization)
            throws IdentityApplicationManagementException, OrganizationManagementException, UserStoreException,
            IdentityRoleManagementException {

        for (String userId : userIds) {
            propagateUserSelectiveShare(userId, organization);
        }
    }

    private void propagateUserSelectiveShare(String userId, UserShareSelectiveOrgDetailsDO organization)
            throws IdentityApplicationManagementException, OrganizationManagementException,
            IdentityRoleManagementException, UserStoreException {

        OrganizationUserSharingService sharingService = getOrganizationUserSharingService();

        UserShareSelective userShareSelective = createUserShareSelective(userId, organization);
        String organizationId = organization.getOrganizationId();
        PolicyEnum policy = getPolicyByValue(organization.getPolicy());

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        AbstractUserStoreManager userStoreManager = getUserStoreManager(tenantId);
        String sharingUserId = userShareSelective.getUserId();
        Map<String, String> originalUserDetails = sharingService.getOriginalUserDetailsFromSharingUser(sharingUserId);
        String originalUserId = originalUserDetails.get(USER_ID);
        String originalUserResidenceOrgId = originalUserDetails.get(ORG_ID);
        String originalUserName = userStoreManager.getUserNameFromUserID(sharingUserId);

        String sharingInitiatedOrgId = getOrganizationId();

        List<String> targetOrganizations = getOrgsToShareUserWithPerPolicy(organizationId, policy);

        for (String targetOrg : targetOrganizations) {
            LOG.info("Processing sharing for target organization: " + targetOrg);
            processUserSelectiveSharing(
                    sharingService, originalUserId, originalUserName, originalUserResidenceOrgId, targetOrg,
                    userShareSelective, policy, sharingInitiatedOrgId);
           LOG.info("Completed sharing for target organization: " + targetOrg);
        }
    }

    // TODO: Validate policy broad or narrow

    private void processUserSelectiveSharing(
            OrganizationUserSharingService sharingService, String originalUserId, String originalUserName,
            String originalUserResidenceOrgId, String targetOrg, UserShareSelective userShareSelective,
            PolicyEnum policy, String sharingInitiatedOrgId) {
        String sharedUserId = null;
        try {
            if (isExistingUserInTargetOrg(originalUserName, targetOrg)) {
                errorMessages.add("User already shared with organization: " + targetOrg);
                return;
            }

            sharingService.shareOrganizationUser(targetOrg, originalUserId, originalUserResidenceOrgId,
                    sharingInitiatedOrgId, "Shared");
            sharedUserId = sharingService.getUserAssociationOfAssociatedUserByOrgId(originalUserId, targetOrg)
                    .getUserId();

            assignRolesIfPresent(userShareSelective, sharedUserId, targetOrg);
            handleFuturePropagationIfRequired(originalUserId, originalUserResidenceOrgId, targetOrg, policy);

        } catch (OrganizationManagementException | IdentityRoleManagementException | UserStoreException e) {
            errorMessages.add("Error while sharing user with organization: " + targetOrg + " - " + e.getMessage());
            if (sharedUserId != null) {
                try {
                    sharingService.unshareOrganizationUsers(sharedUserId, targetOrg);
                } catch (OrganizationManagementException rollbackException) {
                    errorMessages.add("Failed to rollback sharing for user: " + sharedUserId + " from organization: " + targetOrg + " - " + rollbackException.getMessage());
                }
            }
        }
    }

    private void assignRolesIfPresent(UserShareSelective userShareSelective, String sharedUserId, String targetOrg)
            throws IdentityRoleManagementException, OrganizationManagementException {
        if (!userShareSelective.getRoles().isEmpty()) {
            assignRolesToTheSharedUser(sharedUserId, targetOrg, userShareSelective.getRoles());
        }
    }

    private void handleFuturePropagationIfRequired(String originalUserId, String originalUserResidenceOrgId,
                                                   String targetOrg, PolicyEnum policy)
            throws OrganizationManagementServerException {
        if (getPoliciesForFuturePropagation().contains(policy.getPolicyCode())) {
            saveForFuturePropagations(originalUserId, originalUserResidenceOrgId, targetOrg, policy);
        }
    }


    private UserShareSelective createUserShareSelective(String userId, UserShareSelectiveOrgDetailsDO orgDetails)
            throws OrganizationManagementException, IdentityApplicationManagementException,
            IdentityRoleManagementException {

        return new UserShareSelective()
                .withUserId(userId)
                .withOrganizationId(orgDetails.getOrganizationId())
                .withPolicy(getPolicyByValue(orgDetails.getPolicy()))
                .withRoles(getRoleIdsFromRoleNameAndAudience(orgDetails.getRoles()));
    }


    ///////////

    private List<String> getPoliciesForFuturePropagation() {

        List<String> policiesForFuturePropagation = new ArrayList<>();

        for (PolicyEnum policy : PolicyEnum.values()) {
            if (policy.getPolicyCode().contains(POLICY_CODE_FOR_EXISTING_AND_FUTURE) ||
                    policy.getPolicyCode().contains(POLICY_CODE_FOR_FUTURE_ONLY)) {
                policiesForFuturePropagation.add(policy.getPolicyCode());
            }
        }

        return policiesForFuturePropagation;
    }

    private void saveForFuturePropagations(String originalUser, String initiatedOrg, String policyHoldingOrg,
                                           PolicyEnum policy) throws OrganizationManagementServerException {

        resourceSharingPolicyHandlerDAO.createResourceSharingPolicyRecord(originalUser, "User", initiatedOrg,
                policyHoldingOrg, policy.getPolicyCode());

    }


    private void assignRolesToTheSharedUser(String sharedUser, String sharedOrganization, List<String> roles)
            throws IdentityRoleManagementException, OrganizationManagementException {

        String sharedOrgTenantDomain = getOrganizationManager().resolveTenantDomain(sharedOrganization);

        Map<String, String> mainRoleToSharedRoleMappingsBySubOrg =
                getRoleManagementService().getMainRoleToSharedRoleMappingsBySubOrg(roles, sharedOrgTenantDomain);

        for (String role : mainRoleToSharedRoleMappingsBySubOrg.values()) {
            getRoleManagementService().updateUserListOfRole(role, Collections.singletonList(sharedUser),
                    Collections.emptyList(), sharedOrgTenantDomain);
        }

    }

    private boolean isExistingUserInTargetOrg(String userName, String organizationId)
            throws OrganizationManagementException, UserStoreException {
        //Need to decide how the usher share is handled in the duplicate user issue.
        //TODO: Secondary user stores

        String tenantDomain = getOrganizationManager().resolveTenantDomain(organizationId);
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        AbstractUserStoreManager userStoreManager = getUserStoreManager(tenantId);

        return userStoreManager.isExistingUser(userName);
    }

    private List<String> getRoleIdsFromRoleNameAndAudience(List<RoleWithAudienceDO> rolesWithAudience)
            throws OrganizationManagementException, IdentityApplicationManagementException,
            IdentityRoleManagementException {

        String originalOrgId = getOrganizationId();
        String originalTenantDomain = getOrganizationManager().resolveTenantDomain(originalOrgId);

        List<String> list = new ArrayList<>();
        for (RoleWithAudienceDO roleWithAudienceDO : rolesWithAudience) {
            String audienceId = getAudienceId(roleWithAudienceDO, originalOrgId, originalTenantDomain);
            String roleId = getRoleIdFromAudience(
                    roleWithAudienceDO.getRoleName(),
                    roleWithAudienceDO.getAudienceType(),
                    audienceId,
                    originalTenantDomain);
            list.add(roleId);
        }
        return list;

    }

    private String getRoleIdFromAudience(String roleName, String audienceType, String audienceId, String tenantDomain)
            throws IdentityRoleManagementException {

        return getRoleManagementService().getRoleIdByName(roleName, audienceType, audienceId, tenantDomain);
    }

    private String getAudienceId(RoleWithAudienceDO role, String originalOrgId, String tenantDomain)
            throws IdentityApplicationManagementException, OrganizationManagementException {

        switch (role.getAudienceType()) {
            case ORGANIZATION:
                return originalOrgId;
            case APPLICATION:
                return getApplicationManagementService()
                        .getApplicationBasicInfoByName(role.getAudienceName(), tenantDomain)
                        .getApplicationResourceId();
            default:
                throw new OrganizationManagementException("Invalid audience type: " + role.getAudienceType());
        }
    }

    private List<String> getOrgsToShareUserWithPerPolicy(String policyHoldingOrgId, PolicyEnum policy)
            throws OrganizationManagementException {
        Set<String> organizationsToShareWithPerPolicy = new HashSet<>();

        // Retrieve the list of organizations according to the policy

        switch (policy) {
            case ALL_EXISTING_ORGS_ONLY:
            case ALL_EXISTING_AND_FUTURE_ORGS:
                // Share with all existing organizations (entire hierarchy)
                getOrganizationManager().getChildOrganizations(policyHoldingOrgId, true).stream()
                        .map(BasicOrganization::getId)
                        .forEach(organizationsToShareWithPerPolicy::add);
                break;

            case IMMEDIATE_EXISTING_ORGS_ONLY:
            case IMMEDIATE_EXISTING_AND_FUTURE_ORGS:
                // Share with only the immediate existing child organizations
                getOrganizationManager().getChildOrganizations(policyHoldingOrgId, false).stream()
                        .map(BasicOrganization::getId)
                        .forEach(organizationsToShareWithPerPolicy::add);
                break;

            case SELECTED_ORG_ONLY:
                organizationsToShareWithPerPolicy.add(policyHoldingOrgId);
                break;

            case SELECTED_ORG_WITH_ALL_EXISTING_CHILDREN_ONLY:
            case SELECTED_ORG_WITH_ALL_EXISTING_AND_FUTURE_CHILDREN:
                organizationsToShareWithPerPolicy.add(policyHoldingOrgId);
                getOrganizationManager().getChildOrganizations(policyHoldingOrgId, true).stream()
                        .map(BasicOrganization::getId)
                        .forEach(organizationsToShareWithPerPolicy::add);
                break;

            case SELECTED_ORG_WITH_EXISTING_IMMEDIATE_CHILDREN_ONLY:
            case SELECTED_ORG_WITH_EXISTING_IMMEDIATE_AND_FUTURE_CHILDREN:
                organizationsToShareWithPerPolicy.add(policyHoldingOrgId);
                getOrganizationManager().getChildOrganizations(policyHoldingOrgId, false).stream()
                        .map(BasicOrganization::getId)
                        .forEach(organizationsToShareWithPerPolicy::add);
                break;

            default:
                throw new OrganizationManagementException("Invalid policy provided: " + policy.getPolicyName());
        }

        // Convert to a List only at the end
        return new ArrayList<>(organizationsToShareWithPerPolicy);
    }

    //Get Services

    private OrganizationManager getOrganizationManager() {

        return OrganizationUserSharingDataHolder.getInstance().getOrganizationManager();
    }

    private OrganizationUserSharingService getOrganizationUserSharingService() {

        return OrganizationUserSharingDataHolder.getInstance().getOrganizationUserSharingService();
    }

    private RoleManagementService getRoleManagementService() {

        return OrganizationUserSharingDataHolder.getInstance().getRoleManagementService();
    }

    private ApplicationManagementService getApplicationManagementService() {
        return OrganizationUserSharingDataHolder.getInstance().getApplicationManagementService();
    }


    //Validation methods

    private void validateInput(UserShareBaseDO userShareDO, String context) throws UserShareMgtServerException {

        if (userShareDO == null) {
            throwValidationException(context + NULL_INPUT_MESSAGE_SUFFIX,
                    UserSharingConstants.ErrorMessage.ERROR_CODE_NULL_INPUT.getCode(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_NULL_INPUT.getDescription());
        }

        if (userShareDO instanceof UserShareSelectiveDO) {
            validateSelectiveDO((UserShareSelectiveDO) userShareDO);
        } else if (userShareDO instanceof UserShareGeneralDO) {
            validateGeneralDO((UserShareGeneralDO) userShareDO);
        }
    }

    private void validateSelectiveDO(UserShareSelectiveDO selectiveDO) throws UserShareMgtServerException {

        // Validate userCriteria is not null
        validateNotNull(selectiveDO.getUserCriteria(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_INVALID.getMessage(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_INVALID.getCode());

        // Validate that userCriteria contains the required USER_IDS key and is not null
        if (!selectiveDO.getUserCriteria().containsKey(USER_IDS) ||
                selectiveDO.getUserCriteria().get(USER_IDS) == null) {
            throwValidationException(UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getMessage(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getCode(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getDescription());
        }

        // Validate organizations list is not null
        validateNotNull(selectiveDO.getOrganizations(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_ORGANIZATIONS_NULL.getMessage(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_ORGANIZATIONS_NULL.getCode());

        // Validate each organization in the list
        for (UserShareSelectiveOrgDetailsDO orgDetails : selectiveDO.getOrganizations()) {
            validateNotNull(orgDetails.getOrganizationId(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_ORG_ID_NULL.getMessage(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_ORG_ID_NULL.getCode());

            validateNotNull(orgDetails.getPolicy(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_POLICY_NULL.getMessage(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_POLICY_NULL.getCode());

            // Validate roles list is not null (it can be empty)
            if (orgDetails.getRoles() == null) {
                throwValidationException(UserSharingConstants.ErrorMessage.ERROR_CODE_ROLES_NULL.getMessage(),
                        UserSharingConstants.ErrorMessage.ERROR_CODE_ROLES_NULL.getCode(),
                        UserSharingConstants.ErrorMessage.ERROR_CODE_ROLES_NULL.getDescription());
            } else {
                // Validate each role's properties if present
                for (RoleWithAudienceDO role : orgDetails.getRoles()) {
                    validateNotNull(role.getRoleName(),
                            UserSharingConstants.ErrorMessage.ERROR_CODE_ROLE_NAME_NULL.getMessage(),
                            UserSharingConstants.ErrorMessage.ERROR_CODE_ROLE_NAME_NULL.getCode());

                    validateNotNull(role.getAudienceName(),
                            UserSharingConstants.ErrorMessage.ERROR_CODE_AUDIENCE_NAME_NULL.getMessage(),
                            UserSharingConstants.ErrorMessage.ERROR_CODE_AUDIENCE_NAME_NULL.getCode());

                    validateNotNull(role.getAudienceType(),
                            UserSharingConstants.ErrorMessage.ERROR_CODE_AUDIENCE_TYPE_NULL.getMessage(),
                            UserSharingConstants.ErrorMessage.ERROR_CODE_AUDIENCE_TYPE_NULL.getCode());
                }
            }
        }
    }

    private void validateGeneralDO(UserShareGeneralDO generalDO) throws UserShareMgtServerException {

        validateNotNull(generalDO.getUserCriteria(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_INVALID.getMessage(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_INVALID.getCode());
        if (!generalDO.getUserCriteria().containsKey(USER_IDS) || generalDO.getUserCriteria().get(USER_IDS) == null) {
            throwValidationException(UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getMessage(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getCode(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getDescription());
        }

        validateNotNull(generalDO.getPolicy(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_POLICY_NULL.getMessage(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_POLICY_NULL.getCode());

        validateNotNull(generalDO.getRoles(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_ROLES_NULL.getMessage(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_ROLES_NULL.getCode());

        // Validate each role's properties if present
        for (RoleWithAudienceDO role : generalDO.getRoles()) {
            validateNotNull(role.getRoleName(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_ROLE_NAME_NULL.getMessage(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_ROLE_NAME_NULL.getCode());

            validateNotNull(role.getAudienceName(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_AUDIENCE_NAME_NULL.getMessage(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_AUDIENCE_NAME_NULL.getCode());

            validateNotNull(role.getAudienceType(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_AUDIENCE_TYPE_NULL.getMessage(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_AUDIENCE_TYPE_NULL.getCode());
        }
    }

    private void validateNotNull(Object obj, String errorMessage, String errorCode)
            throws UserShareMgtServerException {

        if (obj == null) {
            throwValidationException(errorMessage, errorCode, errorMessage);
        }
    }

    private void throwValidationException(String message, String errorCode, String description)
            throws UserShareMgtServerException {

        throw new UserShareMgtServerException(message, new NullPointerException(message), errorCode, description);
    }

    //Business Logics


    @Override
    public void propagateUserGeneralShare(UserShareGeneralDO userShareGeneralDO)
            throws UserShareMgtException, OrganizationManagementException, IdentityRoleManagementException,
            IdentityApplicationManagementException {

    }

    @Override
    public void propagateUserSelectiveUnshare(UserUnshareSelectiveDO userUnshareSelectiveDO) {

    }

    @Override
    public void propagateUserGeneralUnshare(UserUnshareGeneralDO userUnshareGeneralDO) {

    }

}
