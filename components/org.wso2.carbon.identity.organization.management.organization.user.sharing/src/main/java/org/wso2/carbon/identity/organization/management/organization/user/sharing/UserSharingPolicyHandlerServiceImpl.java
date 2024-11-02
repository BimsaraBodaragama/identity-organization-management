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
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.PolicyEnum;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.dao.OrganizationUserSharingDAO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.dao.OrganizationUserSharingDAOImpl;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.dao.ResourceSharingPolicyHandlerDAO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.dao.ResourceSharingPolicyHandlerDAOImpl;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.exception.UserShareMgtServerException;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.internal.OrganizationUserSharingDataHolder;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.RoleWithAudienceDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareBaseDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareGeneral;
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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.PolicyEnum.validateAndGetPolicyEnum;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.LOG_INFO_GENERAL_SHARE_COMPLETED;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.LOG_INFO_SELECTIVE_SHARE_COMPLETED;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.NULL_INPUT_MESSAGE_SUFFIX;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.POLICY_CODE_FOR_EXISTING_AND_FUTURE;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.POLICY_CODE_FOR_FUTURE_ONLY;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.USER_IDS;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.*;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.VALIDATION_CONTEXT_USER_SHARE_GENERAL_DO;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.VALIDATION_CONTEXT_USER_SHARE_SELECTIVE_DO;
import static org.wso2.carbon.identity.organization.management.service.util.Utils.getOrganizationId;
import static org.wso2.carbon.identity.organization.management.service.util.Utils.getUserStoreManager;

/**
 * Service implementation for handling user sharing policies.
 */
public class UserSharingPolicyHandlerServiceImpl implements UserSharingPolicyHandlerService {

    private static final Log LOG = LogFactory.getLog(UserSharingPolicyHandlerServiceImpl.class);
    private static final OrganizationUserSharingDAO organizationUserSharingDAO = new OrganizationUserSharingDAOImpl();
    private static final ResourceSharingPolicyHandlerDAO resourceSharingPolicyHandlerDAO =
            new ResourceSharingPolicyHandlerDAOImpl();

    //Core Methods.

    /**
     * Propagates the selective share of a user to specific organizations.
     *
     * @param userShareSelectiveDO Contains details for selective sharing.
     */
    @Override
    public void propagateUserSelectiveShare(UserShareSelectiveDO userShareSelectiveDO)
            throws UserShareMgtServerException, OrganizationManagementException, IdentityRoleManagementException,
            UserStoreException {

        validateInput(userShareSelectiveDO, VALIDATION_CONTEXT_USER_SHARE_SELECTIVE_DO);

        for (String userId : userShareSelectiveDO.getUserCriteria().get(USER_IDS)) {
            propagateUserSelectiveShareForGivenUser(userId, userShareSelectiveDO.getOrganizations());
        }

        LOG.info(LOG_INFO_SELECTIVE_SHARE_COMPLETED);

    }

    /**
     * Propagates the general share of a user to all organizations.
     *
     * @param userShareGeneralDO Contains details for general sharing.
     */
    @Override
    public void propagateUserGeneralShare(UserShareGeneralDO userShareGeneralDO)
            throws UserShareMgtServerException, OrganizationManagementException, IdentityRoleManagementException {

        validateInput(userShareGeneralDO, VALIDATION_CONTEXT_USER_SHARE_GENERAL_DO);

        for (String userId : userShareGeneralDO.getUserCriteria().get(USER_IDS)) {
            propagateGeneralShareForUser(userId, validateAndGetPolicyEnum(userShareGeneralDO.getPolicy()),
                    getRoleIdsFromRoleNameAndAudience(userShareGeneralDO.getRoles()));
        }

        LOG.info(LOG_INFO_GENERAL_SHARE_COMPLETED);

    }

    @Override
    public void propagateUserSelectiveUnshare(UserUnshareSelectiveDO userUnshareSelectiveDO) {
        // TODO: To be implemented on selective unsharing
    }

    @Override
    public void propagateUserGeneralUnshare(UserUnshareGeneralDO userUnshareGeneralDO) {
        // TODO: To be implemented on general unsharing
    }

    //Business Logic Methods.

    private void propagateUserSelectiveShareForGivenUser(String userId, List<UserShareSelectiveOrgDetailsDO> organizations)
            throws UserShareMgtServerException, OrganizationManagementException, IdentityRoleManagementException,
            UserStoreException {

        for (UserShareSelectiveOrgDetailsDO orgDetails : organizations) {
            UserShareSelective userShareSelective = createUserShareSelective(userId, orgDetails);
            propagateUserSelectiveShareToSelectedOrganization(userShareSelective);
        }
    }

    private void propagateGeneralShareForUser(String userId, PolicyEnum policy, List<String> roleIds) {

        UserShareGeneral userShareGeneral = createUserShareGeneral(userId, policy, roleIds);
        shareUserWithAllOrganizations(userShareGeneral, policy);
    }

    private UserShareSelective createUserShareSelective(String userId, UserShareSelectiveOrgDetailsDO orgDetails)
            throws UserShareMgtServerException, OrganizationManagementException, IdentityRoleManagementException {

        UserShareSelective userShareSelective = new UserShareSelective();
        userShareSelective.setUserId(userId);
        userShareSelective.setOrganizationId(orgDetails.getOrganizationId());
        userShareSelective.setPolicy(validateAndGetPolicyEnum(orgDetails.getPolicy()));
        userShareSelective.setRoles(getRoleIdsFromRoleNameAndAudience(orgDetails.getRoles()));

        return userShareSelective;
    }


    private UserShareGeneral createUserShareGeneral(String userId, PolicyEnum policy, List<String> roleIds) {

        UserShareGeneral userShareGeneral = new UserShareGeneral();
        userShareGeneral.setUserId(userId);
        userShareGeneral.setPolicy(policy);
        userShareGeneral.setRoles(roleIds);
        return userShareGeneral;
    }

    /**
     * Handles storing or processing the user-organization share.
     *
     * @param userShareSelective Contains details for sharing a user with an organization.
     */
    private void propagateUserSelectiveShareToSelectedOrganization(UserShareSelective userShareSelective)
            throws OrganizationManagementException, IdentityRoleManagementException,
            UserStoreException {

        String originalUserId = userShareSelective.getUserId();
        String originalUserResidenceOrgId = getOrganizationId();
        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        AbstractUserStoreManager userStoreManager = getUserStoreManager(tenantId);
        String originalUserName = userStoreManager.getUserNameFromUserID(originalUserId);

        //TODO: HOW TO GET THE ORIGINAL ORG OF THE ORIGINAL USER - "10084a8d-113f-4211-a0d5-efe36b082211";
        PolicyEnum policy = userShareSelective.getPolicy();

        List<String> organizationsToShareUserWith =
                getOrgsToShareUserWithPerPolicy(userShareSelective.getOrganizationId(), policy);

        OrganizationUserSharingService organizationUserSharingService = getOrganizationUserSharingService();

        for(String organizationToShareUserWith : organizationsToShareUserWith) {

            boolean uniqueUser = isUserUniqueInTargetOrg(originalUserName, organizationToShareUserWith);

            if(uniqueUser) {
                organizationUserSharingService.shareOrganizationUser(organizationToShareUserWith, originalUserId,
                        originalUserResidenceOrgId);
                //TODO: Set as pushed user [Can use CLAIMS] (either here or in above method) (I recommend to do this in
                // the above method)
                String sharedUser = organizationUserSharingService
                        .getUserAssociationOfAssociatedUserByOrgId(originalUserId,
                                organizationToShareUserWith).getUserId(); //252 of InvitationMgtCoreImpl

                //TODO: set claim - pushed or pulled

                if (!userShareSelective.getRoles().isEmpty()) {
                    assignRolesToTheSharedUser(sharedUser, organizationToShareUserWith, userShareSelective.getRoles());
                }

                //Save to UM_RESOURCE_SHARING_POLICY
                if(getPoliciesForFuturePropagation().contains(policy.getPolicyCode())) {
                    saveForFuturePropagations(originalUserId, originalUserResidenceOrgId, organizationToShareUserWith,
                            policy);
                }

            }else{
                //do something - add to a instance variable list and finally return the list in the response as well
                //My suggestion- manage original org with user and ask for tenant in login if duplicate users found
            }
        }

    }

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

    private String resolveTenantDomain(String orgId) throws UserShareMgtServerException {

        try {
            return getOrganizationManager().resolveTenantDomain(orgId);
        } catch (OrganizationManagementException e) {
            throw new UserShareMgtServerException(ERROR_CODE_GET_TENANT_FROM_ORG.getCode(), e,
                    ERROR_CODE_GET_TENANT_FROM_ORG.getMessage(),
                    String.format(ERROR_CODE_GET_TENANT_FROM_ORG.getDescription(), orgId));
        }
    }

    private OrganizationManager getOrganizationManager() {

        return OrganizationUserSharingDataHolder.getInstance().getOrganizationManager();
    }

    private OrganizationUserSharingService getOrganizationUserSharingService() {

        return OrganizationUserSharingDataHolder.getInstance().getOrganizationUserSharingService();
    }

    private RoleManagementService getRoleManagementService() {

        return OrganizationUserSharingDataHolder.getInstance().getRoleManagementService();
    }

    /**
     * Handles storing or processing the general user share.
     *
     * @param userShareGeneral Contains details for sharing a user with all organizations.
     */
    private void shareUserWithAllOrganizations(UserShareGeneral userShareGeneral, PolicyEnum policy) {

        // We get all orgs under the policy given by userShareGeneral.
        // We can use private List<String> getOrganizationsBasedOnPolicy(String policy) for that
        // Then we iterate through those orgs and create an UserAssociation model and share the user
        // Then inside that loop, we do the role assign for each inside that
    }

    private void saveForFuturePropagations(String originalUser, String initiatedOrg, String policyHoldingOrg,
                                                   PolicyEnum policy) throws OrganizationManagementServerException {
        //Check if the policy is for future and save to UM_RESOURCE_SHARING_POLICY table and UM_SHARING_REQUEST_ROLES
        // table
        // Save the resource type as User.

        resourceSharingPolicyHandlerDAO.createResourceSharingPolicyRecord(originalUser, "User", initiatedOrg,
                policyHoldingOrg, policy.getPolicyCode());

        //error handling (db level errors?)
    }

    private boolean isUserUniqueInTargetOrg(String userName, String organizationId)
            throws OrganizationManagementException, UserStoreException {
        //Need to decide how the usher share is handled in the duplicate user issue.

        String tenantDomain = getOrganizationManager().resolveTenantDomain(organizationId);
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        AbstractUserStoreManager userStoreManager = getUserStoreManager(tenantId);

        return userStoreManager.isExistingUser(userName);
    }

    private List<String> getOrgsToShareUserWithPerPolicy(String policyHoldingOrg, PolicyEnum policy)
            throws OrganizationManagementException {
        Set<String> organizationsToShareWithPerPolicy = new HashSet<>();

        // Retrieve the list of organizations according to the policy
        List<BasicOrganization> allChildOrganizations = getOrganizationManager().getChildOrganizations(policyHoldingOrg, true);
        List<BasicOrganization> immediateChildOrganizations = getOrganizationManager().getChildOrganizations(policyHoldingOrg, false);

        switch (policy) {
            case ALL_EXISTING_ORGS_ONLY:
            case ALL_EXISTING_AND_FUTURE_ORGS:
                // Share with all existing organizations (entire hierarchy)
                allChildOrganizations.stream()
                        .map(BasicOrganization::getId)
                        .forEach(organizationsToShareWithPerPolicy::add);
                break;

            case IMMEDIATE_EXISTING_ORGS_ONLY:
            case IMMEDIATE_EXISTING_AND_FUTURE_ORGS:
                // Share with only the immediate existing child organizations
                immediateChildOrganizations.stream()
                        .map(BasicOrganization::getId)
                        .forEach(organizationsToShareWithPerPolicy::add);
                break;

            case SELECTED_ORG_ONLY:
                organizationsToShareWithPerPolicy.add(policyHoldingOrg);
                break;

            case SELECTED_ORG_WITH_ALL_EXISTING_CHILDREN_ONLY:
            case SELECTED_ORG_WITH_ALL_EXISTING_AND_FUTURE_CHILDREN:
                organizationsToShareWithPerPolicy.add(policyHoldingOrg);
                allChildOrganizations.stream()
                        .map(BasicOrganization::getId)
                        .forEach(organizationsToShareWithPerPolicy::add);
                break;

            case SELECTED_ORG_WITH_EXISTING_IMMEDIATE_CHILDREN_ONLY:
            case SELECTED_ORG_WITH_EXISTING_IMMEDIATE_AND_FUTURE_CHILDREN:
                organizationsToShareWithPerPolicy.add(policyHoldingOrg);
                immediateChildOrganizations.stream()
                        .map(BasicOrganization::getId)
                        .forEach(organizationsToShareWithPerPolicy::add);
                break;

            default:
                throw new OrganizationManagementException("Invalid policy provided: " + policy.getPolicyName());
        }

        // Convert to a List only at the end
        return new ArrayList<>(organizationsToShareWithPerPolicy);
    }

    //Validation Methods.

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

    //Utility Methods.

    /**
     * Converts roles to role IDs.
     *
     * @param roles The list of roles containing display name and audience details.
     * @return The list of role IDs.
     */
    private List<String> getRoleIdsFromRoleNameAndAudience(List<RoleWithAudienceDO> roles)
            throws OrganizationManagementException, IdentityRoleManagementException {

        List<String> roleIds = new ArrayList<>();

        for(RoleWithAudienceDO role : roles) {
            String roleName = role.getRoleName();
            String audienceName = role.getAudienceName();
            String audienceType = role.getAudienceType();
            String audienceId;
            int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
            String originalOrganizationId = getOrganizationId();
            String originalTenantDomain = getOrganizationManager().resolveTenantDomain(originalOrganizationId);

            if(audienceType=="Organization"){
                audienceId = originalOrganizationId;
            } else if (audienceType=="Application"){
                //audienceId =getRoleManagementService().;
                audienceId = originalTenantDomain;
            } else {
                throw new OrganizationManagementException("Invalid audience type: " + audienceType);
            }

            String roleId = getRoleManagementService().getRoleIdByName(roleName, audienceName, audienceId,
                    originalTenantDomain);
            roleIds.add(roleId);
        }

        //TODO:
        // roleName, audienceName, audienceType
        // if audienceType: org -> getOrgIdOfTheParent UUID ~ This is audienceId
        // if audienceType: app -> audienceName, parentTenantId -> get app UUID ~ This is audienceId
        // call RoleMgtService: getRoleManagementService().getRoleIdByName(params)
        // return roleIDs

        return roleIds;
    }


    private void validateUserShareSelectiveDO(UserShareSelectiveDO userShareSelectiveDO) {
        // TODO: HOPE EVERYTHING HAS ALREADY BEEN TAKEN CARE OF AT DB LEVEL
        //  1. validate if the user is in db
        //  2. validate if the org is in db --not priority
        //  3. validate if the policy is in ENUM
        //  4. validate each roles are in db --not priority
        //  5. validate if roles have any conflicts with the roles in the given org

    }
}
