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
import org.wso2.carbon.identity.organization.management.organization.user.sharing.dao.ResourceSharingPolicyHandlerDAO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.dao.ResourceSharingPolicyHandlerDAOImpl;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.exception.UserShareMgtServerException;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.internal.OrganizationUserSharingDataHolder;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.RoleWithAudienceDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareBaseDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareGeneralDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareSelective;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareSelectiveDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareSelectiveOrgDetailsDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserSharingDetails;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserUnshareGeneralDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserUnshareSelectiveDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.userCriteria.UserCriteriaType;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.userCriteria.UserIds;
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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.APPLICATION;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.LOG_INFO_SELECTIVE_SHARE_COMPLETED;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.NULL_INPUT_MESSAGE;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.NULL_INPUT_MESSAGE_SUFFIX;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ORGANIZATION;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ORG_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.POLICY_CODE_FOR_EXISTING_AND_FUTURE;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.POLICY_CODE_FOR_FUTURE_ONLY;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.SHARING_TYPE_SHARED;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.USER;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.USER_GROUPS;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.USER_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.USER_IDS;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.VALIDATION_CONTEXT_USER_SHARE_SELECTIVE_DO;
import static org.wso2.carbon.identity.organization.management.service.util.Utils.getOrganizationId;
import static org.wso2.carbon.identity.organization.management.service.util.Utils.getUserStoreManager;

/**
 * Service implementation for handling user sharing policies.
 */
public class UserSharingPolicyHandlerServiceImpl implements UserSharingPolicyHandlerService {

    private static final Log LOG = LogFactory.getLog(UserSharingPolicyHandlerServiceImpl.class);
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
    public void populateSelectiveUserShare(UserShareSelectiveDO userShareSelectiveDO)
            throws UserShareMgtServerException, OrganizationManagementException, IdentityRoleManagementException,
            UserStoreException, IdentityApplicationManagementException {

        validateInput(userShareSelectiveDO);
        List<UserShareSelectiveOrgDetailsDO> organizations = userShareSelectiveDO.getOrganizations();
        Map<String, UserCriteriaType> userCriteria = userShareSelectiveDO.getUserCriteria();

        for (UserShareSelectiveOrgDetailsDO organization : organizations) {
            populateSelectiveUserShareByCriteria(organization, userCriteria);
        }

        LOG.info(LOG_INFO_SELECTIVE_SHARE_COMPLETED);

        // After parallel processing, check for errors and handle them.
        if (!errorMessages.isEmpty()) {
            throw new OrganizationManagementException(
                    "Failed to share user with some organizations: " + String.join(", ", errorMessages));
        }

    }

    private void populateSelectiveUserShareByCriteria(UserShareSelectiveOrgDetailsDO organization,
                                                                           Map<String, UserCriteriaType> userCriteria)
            throws OrganizationManagementException, IdentityApplicationManagementException,
            IdentityRoleManagementException, UserStoreException {

        for (Map.Entry<String, UserCriteriaType> criterion : userCriteria.entrySet()) {
            String criterionKey = criterion.getKey();
            UserCriteriaType criterionValues = criterion.getValue();

            switch (criterionKey) {
                case USER_IDS:
                    if (criterionValues instanceof UserIds) {
                        populateSelectiveUserShareByUserIds((UserIds) criterionValues, organization);
                    } else {
                        throw new OrganizationManagementException("Invalid type for USER_IDS criterion.");
                    }
                    break;
                case USER_GROUPS:
                    // Placeholder for future user criteria.
                    break;
                default:
                    throw new OrganizationManagementException("Invalid user criterion provided: " + criterionKey);
            }
        }
    }

    private void populateSelectiveUserShareByUserIds(UserIds userIds,
                                                           UserShareSelectiveOrgDetailsDO organization)
            throws IdentityApplicationManagementException, OrganizationManagementException, UserStoreException,
            IdentityRoleManagementException {

        for (String userId : userIds.getIds()) {
            processSelectiveUserShare(userId, organization);
        }
    }

    private void processSelectiveUserShare(String userId, UserShareSelectiveOrgDetailsDO organization)
            throws IdentityApplicationManagementException, OrganizationManagementException,
            IdentityRoleManagementException, UserStoreException {

        OrganizationUserSharingService sharingService = getOrganizationUserSharingService();

        UserShareSelective userShareSelective = createUserShareSelective(userId, organization);
        String organizationId = organization.getOrganizationId();

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        AbstractUserStoreManager userStoreManager = getUserStoreManager(tenantId);

        String sharingUserId = userShareSelective.getUserId(); //TODO: Make a comment
        String sharingInitiatedOrgId = getOrganizationId();

        Map<String, String> originalUserDetails = sharingService.getOriginalUserDetailsFromSharingUser(sharingUserId);
        String originalUserId = originalUserDetails.get(USER_ID);
        String originalUserResidenceOrgId = originalUserDetails.get(ORG_ID);
        String originalUserName = userStoreManager.getUserNameFromUserID(sharingUserId);

        UserSharingDetails userSharingDetails =
                new UserSharingDetails()
                        .withSharingUserId(sharingUserId)
                        .withSharingInitiatedOrgId(sharingInitiatedOrgId)
                        .withOriginalUserId(originalUserId)
                        .withOriginalOrgId(originalUserResidenceOrgId)
                        .withOriginalUserName(originalUserName)
                        .withSharingType(SHARING_TYPE_SHARED)
                        .withRoleIds(userShareSelective.getRoles())
                        .withAppliedSharingPolicy(userShareSelective.getPolicy());

        List<String> targetOrganizations =
                getOrgsToShareUserWithPerPolicy(organizationId, userShareSelective.getPolicy());

        for (String targetOrg : targetOrganizations) {
            LOG.info("Processing sharing for target organization: " + targetOrg);
            shareUser(sharingService, userSharingDetails.withTargetOrgId(targetOrg));
            LOG.info("Completed sharing for target organization: " + targetOrg);
        }
    }

    private void shareUser(
            OrganizationUserSharingService sharingService, UserSharingDetails userSharingDetails)
            throws UserStoreException, OrganizationManagementException {

        // Keep a String to save sharingUserId which equals to userSharingDetails.getSharingUserId()
        String sharingInitiatedOrgId = userSharingDetails.getSharingInitiatedOrgId();
        String targetOrg = userSharingDetails.getTargetOrgId();
        String originalUserId = userSharingDetails.getOriginalUserId();
        String originalUserName = userSharingDetails.getOriginalUserName();
        String originalUserResidenceOrgId = userSharingDetails.getOriginalOrgId();
        String sharingType = userSharingDetails.getSharingType();
        List<String> roleIds = userSharingDetails.getRoleIds();
        PolicyEnum appliedSharingPolicy = userSharingDetails.getAppliedSharingPolicy();

        if (isExistingUserInTargetOrg(originalUserName, targetOrg)) {
            //TODO: Put userName in the error message.
            errorMessages.add("User already shared with organization: " + targetOrg);
            return;
        }

        String sharedUserId = null;
        try {

            // Get shared user ID for further operations
            sharedUserId = shareUserWithTargetOrg(sharingService, originalUserId, originalUserResidenceOrgId,
                    targetOrg, sharingInitiatedOrgId, sharingType);

            // Assign roles if any are present
            //TODO: Params sequence -> user, orgs, roles
            assignRolesIfPresent(roleIds, sharedUserId, targetOrg);

            // Handle future propagation if policy indicates it is required
            //TODO: Save the roles as well in
            //TODO: Rename the below method as storeSharingPolicy
            handleFuturePropagationIfRequired(USER, originalUserId, originalUserResidenceOrgId, targetOrg,
                    appliedSharingPolicy);

        } catch (OrganizationManagementException | IdentityRoleManagementException e) {
            handleErrorWhileSharingUser(targetOrg, e);
            rollbackSharingIfNecessary(sharingService, sharedUserId, targetOrg);
        }
    }

    private String shareUserWithTargetOrg(
            OrganizationUserSharingService sharingService, String originalUserId, String originalUserResidenceOrgId,
            String targetOrg, String sharingInitiatedOrgId, String sharingType)
            throws OrganizationManagementException, UserStoreException {

        sharingService.shareOrganizationUser(targetOrg, originalUserId, originalUserResidenceOrgId,
                sharingInitiatedOrgId, sharingType);
        return sharingService.getUserAssociationOfAssociatedUserByOrgId(originalUserId, targetOrg).getUserId();
    }

    private void handleErrorWhileSharingUser(String targetOrg, Exception e) {

        errorMessages.add("Error while sharing user with organization: " + targetOrg + " - " + e.getMessage());
    }

    private void rollbackSharingIfNecessary(OrganizationUserSharingService sharingService, String sharedUserId,
                                            String targetOrg) {

        if (sharedUserId != null) {
            try {
                sharingService.unshareOrganizationUsers(sharedUserId, targetOrg);
            } catch (OrganizationManagementException rollbackException) {
                errorMessages.add(
                        "Failed to rollback sharing for user: " + sharedUserId + " from organization: " + targetOrg +
                                " - " + rollbackException.getMessage());
            }
        }
    }

    private void assignRolesIfPresent(List<String> roleIds, String sharedUserId, String targetOrg)
            throws IdentityRoleManagementException, OrganizationManagementException {

        if (!roleIds.isEmpty()) {
            assignRolesToTheSharedUser(roleIds, sharedUserId, targetOrg);
        }
    }

    private void handleFuturePropagationIfRequired(String resourceType, String originalUserId,
                                                   String originalUserResidenceOrgId, String targetOrg,
                                                   PolicyEnum policy)
            throws OrganizationManagementServerException {

        if (getPoliciesForFuturePropagation().contains(policy.getPolicyCode())) {
            saveForFuturePropagations(resourceType, originalUserId, originalUserResidenceOrgId, targetOrg, policy);
        }
    }
    //TODO: Make names readable and make comment
    private UserShareSelective createUserShareSelective(String userId, UserShareSelectiveOrgDetailsDO orgDetails)
            throws OrganizationManagementException, IdentityApplicationManagementException,
            IdentityRoleManagementException {

        return new UserShareSelective.Builder()
                .withUserId(userId)
                .withOrganizationId(orgDetails.getOrganizationId())
                .withPolicy(orgDetails.getPolicy())
                .withRoles(getRoleIdsFromRoleNameAndAudience(orgDetails.getRoles())).build();
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

    private void saveForFuturePropagations(String resourceType, String originalUser, String initiatedOrg,
                                           String policyHoldingOrg, PolicyEnum policy)
            throws OrganizationManagementServerException {

        resourceSharingPolicyHandlerDAO.createResourceSharingPolicyRecord(originalUser, resourceType, initiatedOrg,
                policyHoldingOrg, policy.getPolicyCode());

    }

    private void assignRolesToTheSharedUser(List<String> roles, String sharedUser, String targetOrg)
            throws IdentityRoleManagementException, OrganizationManagementException {

        String targetOrgTenantDomain = getOrganizationManager().resolveTenantDomain(targetOrg);

        //TODO: Update the query

        List<String> originalRoles = getRoleManagementService().getMainRoleUUIDsForSharedRoles(roles);

        Map<String, String> mainRoleToSharedRoleMappingsBySubOrg =
                getRoleManagementService().getMainRoleToSharedRoleMappingsBySubOrg(originalRoles, targetOrgTenantDomain);

        //TODO: Since we are going only with POST, even for role updates, we have to get the earlier roles and delete it
        //TODO: Handle sub-org role assignments (consider only roles assigned from parents)
        for (String role : mainRoleToSharedRoleMappingsBySubOrg.values()) {
            getRoleManagementService().updateUserListOfRole(role, Collections.singletonList(sharedUser),
                    Collections.emptyList(), targetOrgTenantDomain);
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

        String sharingInitiatedOrgId = getOrganizationId();
        String sharingInitiatedTenantDomain = getOrganizationManager().resolveTenantDomain(sharingInitiatedOrgId);

        List<String> list = new ArrayList<>();
        for (RoleWithAudienceDO roleWithAudienceDO : rolesWithAudience) {
            String audienceId = getAudienceId(roleWithAudienceDO, sharingInitiatedOrgId, sharingInitiatedTenantDomain);
            String roleId = getRoleIdFromAudience(
                    roleWithAudienceDO.getRoleName(),
                    roleWithAudienceDO.getAudienceType(),
                    audienceId,
                    sharingInitiatedTenantDomain);
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

        switch (policy) {
            case ALL_EXISTING_ORGS_ONLY:
            case ALL_EXISTING_AND_FUTURE_ORGS:
                organizationsToShareWithPerPolicy.addAll(getOrganizationManager()
                        .getChildOrganizationsIds(policyHoldingOrgId, true));
                break;

            case IMMEDIATE_EXISTING_ORGS_ONLY:
            case IMMEDIATE_EXISTING_AND_FUTURE_ORGS:
                organizationsToShareWithPerPolicy.addAll(getOrganizationManager()
                        .getChildOrganizationsIds(policyHoldingOrgId, false));
                break;

            case SELECTED_ORG_ONLY:
                organizationsToShareWithPerPolicy.add(policyHoldingOrgId);
                break;

            case SELECTED_ORG_WITH_ALL_EXISTING_CHILDREN_ONLY:
            case SELECTED_ORG_WITH_ALL_EXISTING_AND_FUTURE_CHILDREN:
                organizationsToShareWithPerPolicy.add(policyHoldingOrgId);
                organizationsToShareWithPerPolicy.addAll(getOrganizationManager()
                        .getChildOrganizationsIds(policyHoldingOrgId, true));
                break;

            case SELECTED_ORG_WITH_EXISTING_IMMEDIATE_CHILDREN_ONLY:
            case SELECTED_ORG_WITH_EXISTING_IMMEDIATE_AND_FUTURE_CHILDREN:
                organizationsToShareWithPerPolicy.add(policyHoldingOrgId);
                organizationsToShareWithPerPolicy.addAll(getOrganizationManager()
                        .getChildOrganizationsIds(policyHoldingOrgId, false));
                break;

            default:
                throw new OrganizationManagementException("Invalid policy provided: " + policy.getPolicyName());
        }

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

    private <T extends UserCriteriaType> void validateInput(UserShareBaseDO<T> userShareDO) throws UserShareMgtServerException {

        if (userShareDO == null) {
            throwValidationException(NULL_INPUT_MESSAGE,
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
    public void populateGeneralUserShare(UserShareGeneralDO userShareGeneralDO) {

    }

    @Override
    public void populateSelectiveUserUnshare(UserUnshareSelectiveDO userUnshareSelectiveDO) {

    }

    @Override
    public void populateGeneralUserUnshare(UserUnshareGeneralDO userUnshareGeneralDO) {

    }

}
