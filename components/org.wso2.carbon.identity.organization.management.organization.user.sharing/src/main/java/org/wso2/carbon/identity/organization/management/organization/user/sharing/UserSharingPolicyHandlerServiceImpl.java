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
import org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.PolicyEnum;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.dao.OrganizationUserSharingDAO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.dao.OrganizationUserSharingDAOImpl;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.dao.ResourceSharingPolicyHandlerDAO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.dao.ResourceSharingPolicyHandlerDAOImpl;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.exception.UserShareMgtServerException;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.internal.OrganizationUserSharingDataHolder;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareBaseDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareGeneral;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareGeneralDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareSelective;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareSelectiveDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserUnshareGeneralDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserUnshareSelectiveDO;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementServerException;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.PolicyEnum.validateAndGetPolicy;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.LOG_INFO_GENERAL_SHARE_COMPLETED;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.LOG_INFO_SELECTIVE_SHARE_COMPLETED;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.NULL_INPUT_MESSAGE_SUFFIX;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.NULL_POLICY;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ORG_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.POLICY;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.POLICY_CODE_FOR_EXISTING_AND_FUTURE;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.POLICY_CODE_FOR_FUTURE_ONLY;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ROLES;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.USER_IDS;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.*;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.VALIDATION_CONTEXT_USER_SHARE_GENERAL_DO;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.VALIDATION_CONTEXT_USER_SHARE_SELECTIVE_DO;

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
    public void propagateSelectiveShare(UserShareSelectiveDO userShareSelectiveDO)
            throws UserShareMgtServerException, OrganizationManagementException, IdentityRoleManagementException {

        validateInput(userShareSelectiveDO, VALIDATION_CONTEXT_USER_SHARE_SELECTIVE_DO);

        for (String userId : userShareSelectiveDO.getUserCriteria().get(USER_IDS)) {
            propagateSelectiveShareForUser(userId, userShareSelectiveDO.getOrganizations());
        }

        LOG.info(LOG_INFO_SELECTIVE_SHARE_COMPLETED);

    }

    /**
     * Propagates the general share of a user to all organizations.
     *
     * @param userShareGeneralDO Contains details for general sharing.
     */
    @Override
    public void propagateGeneralShare(UserShareGeneralDO userShareGeneralDO) throws UserShareMgtServerException {

        validateInput(userShareGeneralDO, VALIDATION_CONTEXT_USER_SHARE_GENERAL_DO);

        for (String userId : userShareGeneralDO.getUserCriteria().get(USER_IDS)) {
            propagateGeneralShareForUser(userId, validateAndGetPolicy(userShareGeneralDO.getPolicy()),
                    getRoleIds(userShareGeneralDO.getRoles()));
        }

        LOG.info(LOG_INFO_GENERAL_SHARE_COMPLETED);

    }

    @Override
    public void propagateSelectiveUnshare(UserUnshareSelectiveDO userUnshareSelectiveDO) {
        // TODO: To be implemented on selective unsharing
    }

    @Override
    public void propagateGeneralUnshare(UserUnshareGeneralDO userUnshareGeneralDO) {
        // TODO: To be implemented on general unsharing
    }

    //Business Logic Methods.

    private void propagateSelectiveShareForUser(String userId, List<Map<String, Object>> organizations)
            throws UserShareMgtServerException, OrganizationManagementException, IdentityRoleManagementException {

        for (Map<String, Object> orgDetails : organizations) {
            UserShareSelective userShareSelective = createUserShareSelective(userId, orgDetails);
            shareUserWithOrganization(userShareSelective);
        }
    }

    private void propagateGeneralShareForUser(String userId, PolicyEnum policy, List<String> roleIds) {

        UserShareGeneral userShareGeneral = createUserShareGeneral(userId, policy, roleIds);
        shareUserWithAllOrganizations(userShareGeneral, policy);
    }

    private UserShareSelective createUserShareSelective(String userId, Map<String, Object> orgDetails)
            throws UserShareMgtServerException {

        validateUserAndOrgDetails(userId, orgDetails);

        UserShareSelective userShareSelective = new UserShareSelective();
        userShareSelective.setUserId(userId);
        userShareSelective.setOrganizationId((String) orgDetails.get(ORG_ID));

        setPolicyIfPresent(orgDetails, userShareSelective);
        setRolesIfPresent(orgDetails, userShareSelective);

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
    private void shareUserWithOrganization(UserShareSelective userShareSelective)
            throws OrganizationManagementException, UserShareMgtServerException, IdentityRoleManagementException {

        // In this method we create an UserAssociation model and share the user
        // We do the role assign here as well

        String originalUser = userShareSelective.getUserId();
        String originalUserResidenceOrgId = "10084a8d-113f-4211-a0d5-efe36b082211";
        //TODO: HOW TO GET THE ORIGINAL ORG OF THE ORIGINAL USER
        PolicyEnum policy = userShareSelective.getPolicy();

        List<String> organizationsToShareUserWith =
                getOrgsToShareUserWithPerPolicy(userShareSelective.getOrganizationId(), policy);

        OrganizationUserSharingService organizationUserSharingService = getOrganizationUserSharingService();

        for(String organizationToShareUserWith : organizationsToShareUserWith) {

            boolean uniqueUser = isUserUniquenessInTargetOrg(originalUser, organizationToShareUserWith);

            if(uniqueUser) {
                organizationUserSharingService.shareOrganizationUser(organizationToShareUserWith, originalUser,
                        originalUserResidenceOrgId);
                //TODO: Set as pushed user (either here or in above method) (I recommend to do this in the above method)
                String sharedUser = organizationUserSharingService
                        .getUserAssociationOfAssociatedUserByOrgId(originalUser,
                                organizationToShareUserWith).getUserId(); //252 of InvitationMgtCoreImpl

                if (!userShareSelective.getRoles().isEmpty()) {
                    assignRolesToTheSharedUser(sharedUser, organizationToShareUserWith, userShareSelective.getRoles());
                }

                //Save to UM_RESOURCE_SHARING_POLICY
                if(getPoliciesForFuturePropagation().contains(policy.getPolicyCode())) {
                    saveForFuturePropagations(originalUser, originalUserResidenceOrgId, organizationToShareUserWith,
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
            throws UserShareMgtServerException, IdentityRoleManagementException {

        String sharedTenantDomain = resolveTenantDomain(sharedOrganization);
        //assign the roles to the sharedUser
        for (String role : roles) {

            getRoleManagementService().updateUserListOfRole(role, Collections.singletonList(sharedUser),
                    Collections.emptyList(), sharedTenantDomain);

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

    private boolean isUserUniquenessInTargetOrg(String userId, String eachOrganization) {
        //Need to decide how the usher share is handled in the duplicate user issue.

        return true;
    }

    private List<String> getOrgsToShareUserWithPerPolicy(String policyHoldingOrg, PolicyEnum policy) {
        List<String> organizationsToShareWithPerPolicy = new ArrayList<>();
        organizationsToShareWithPerPolicy.add(policyHoldingOrg);

        //get the orgs which user need to be shared (Don't forget the policy holding org as well)

        return organizationsToShareWithPerPolicy;
    }

    //Setter Methods.

    private void setPolicyIfPresent(Map<String, Object> orgDetails, UserShareSelective userShareSelective)
            throws UserShareMgtServerException {

        Object requestedPolicy = orgDetails.get(POLICY);
        PolicyEnum policy = validateAndGetPolicy(requestedPolicy);
        if (policy != null) {
            userShareSelective.setPolicy(policy);
        } else {
            throw new UserShareMgtServerException(NULL_POLICY, new NullPointerException(NULL_POLICY),
                    ERROR_CODE_POLICY_NULL.getCode(), ERROR_CODE_POLICY_NULL.getDescription());
        }
    }

    private void setRolesIfPresent(Map<String, Object> orgDetails, UserShareSelective userShareSelective) {

        List<String> roleIds = extractRoleIds(orgDetails.get(ROLES));
        if (!roleIds.isEmpty()) {
            userShareSelective.setRoles(roleIds);
        } else {
            userShareSelective.setRoles(Collections.emptyList());
        }
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

        validateNotNull(selectiveDO.getUserCriteria(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_INVALID.getMessage(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_INVALID.getCode());
        if (!selectiveDO.getUserCriteria().containsKey(USER_IDS) ||
                selectiveDO.getUserCriteria().get(USER_IDS) == null) {
            throwValidationException(UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getMessage(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getCode(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getDescription());
        }
        validateNotNull(selectiveDO.getOrganizations(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_ORGANIZATIONS_NULL.getMessage(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_ORGANIZATIONS_NULL.getCode());
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
        validateNotNull(generalDO.getPolicy(), UserSharingConstants.ErrorMessage.ERROR_CODE_POLICY_NULL.getMessage(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_POLICY_NULL.getCode());
        validateNotNull(generalDO.getRoles(), UserSharingConstants.ErrorMessage.ERROR_CODE_ROLES_NULL.getMessage(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_ROLES_NULL.getCode());
    }

    private void validateUserAndOrgDetails(String userId, Map<String, Object> orgDetails)
            throws UserShareMgtServerException {

        validateUserId(userId);
        validateOrgDetails(orgDetails);
    }

    private void validateUserId(String userId) throws UserShareMgtServerException {

        validateNotNull(userId, UserSharingConstants.ErrorMessage.ERROR_CODE_USER_ID_NULL.getMessage(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_USER_ID_NULL.getCode());
    }

    private void validateOrgDetails(Map<String, Object> orgDetails) throws UserShareMgtServerException {

        validateNotNull(orgDetails, UserSharingConstants.ErrorMessage.ERROR_CODE_ORG_DETAILS_NULL.getMessage(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_ORG_DETAILS_NULL.getCode());
        validateNotNull(orgDetails.get(UserSharingConstants.ORG_ID),
                UserSharingConstants.ErrorMessage.ERROR_CODE_ORG_ID_NULL.getMessage(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_ORG_ID_NULL.getCode());
        validateNotNull(orgDetails.get(UserSharingConstants.POLICY),
                UserSharingConstants.ErrorMessage.ERROR_CODE_POLICY_NULL.getMessage(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_POLICY_NULL.getCode());
        validateNotNull(orgDetails.get(UserSharingConstants.ROLES),
                UserSharingConstants.ErrorMessage.ERROR_CODE_ROLES_NULL.getMessage(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_ROLES_NULL.getCode());
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
    private List<String> getRoleIds(List<Map<String, String>> roles) {

        List<String> roleIds = new ArrayList<>();

        // We have to get the role name, audience name and type and get the role id from the db and return the
        // roleId list

        //call roleMgtService and get a method to do this. Save the not-found roles in a instance variable List or skip
//        if (getRoleManagementService().isExistingRole(roleAssignments.getRoleId(),
//                invitedTenantDomain)) {
//            getRoleManagementService().updateUserListOfRole(roleAssignments.getRoleId(),
//                    Collections.singletonList(associatedUserId), Collections.emptyList(),
//                    invitedTenantDomain);
//        } else {
//            if (LOG.isDebugEnabled()) {
//                LOG.debug("Role: " + roleAssignments.getRoleId()
//                        + " is not exist in the invitedTenantDomain : " + invitedTenantDomain);
//            }
//        }

        return roleIds;
    }

    /**
     * Extracts role IDs from the given roles object.
     *
     * @param rolesObj The roles object to be processed.
     * @return A list of role IDs.
     */
    private List<String> extractRoleIds(Object rolesObj) {

        List<String> roleIds = new ArrayList<>();

        if (rolesObj instanceof List<?>) {
            List<?> rolesList = (List<?>) rolesObj;
            if (!rolesList.isEmpty() && rolesList.get(0) instanceof Map) {
                try {
                    @SuppressWarnings("unchecked")
                    List<Map<String, String>> castedRolesList = (List<Map<String, String>>) rolesList;
                    roleIds = getRoleIds(castedRolesList);
                } catch (ClassCastException e) {
                    throw new IllegalArgumentException(ERROR_INVALID_ROLES_FORMAT.getMessage(), e);
                }
            }
        }

        return roleIds;
    }

    private void validateUserShareSelectiveDO(UserShareSelectiveDO userShareSelectiveDO) {
        // TODO:
        //  1. validate if the user is in db
        //  2. validate if the org is in db --not priority
        //  3. validate if the policy is in ENUM
        //  4. validate each roles are in db --not priority
        //  5. validate if roles have any conflicts with the roles in the given org

    }
}
