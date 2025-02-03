/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ApplicationBasicInfo;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.EditOperation;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.SharedType;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.exception.UserSharingMgtClientException;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.exception.UserSharingMgtException;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.exception.UserSharingMgtServerException;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.internal.OrganizationUserSharingDataHolder;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.BaseUserShare;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.GeneralUserShare;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.SelectiveUserShare;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.SharedResult;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserAssociation;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.BaseUserShareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.BaseUserUnshareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.GeneralUserShareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.GeneralUserUnshareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.ResponseLinkDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.ResponseOrgDetailsDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.ResponseSharedOrgsDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.ResponseSharedRolesDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.RoleWithAudienceDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.SelectiveUserShareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.SelectiveUserShareOrgDetailsDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.SelectiveUserUnshareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.usercriteria.UserCriteriaType;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.usercriteria.UserIdList;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.ResourceSharingPolicyHandlerService;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.OrganizationScope;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.PolicyEnum;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.ResourceType;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.SharedAttributeType;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.exception.ResourceSharingPolicyMgtException;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.model.ResourceSharingPolicy;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.model.SharedResourceAttribute;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.v2.mgt.core.model.Role;
import org.wso2.carbon.identity.role.v2.mgt.core.util.UserIDResolver;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.API_REF_GET_SHARED_ROLES_OF_USER_IN_ORG;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.APPLICATION;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_AUDIENCE_NAME_NULL;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_AUDIENCE_NOT_FOUND;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_AUDIENCE_TYPE_NULL;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_GET_IMMEDIATE_CHILD_ORGS;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_GET_ORGS_TO_SHARE_USER_WITH;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_GET_ROLES_SHARED_WITH_SHARED_USER;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_GET_ROLE_IDS;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_GET_ROLE_WITH_AUDIENCE_BY_ROLE_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_GET_SHARED_ORGANIZATIONS_OF_USER;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_INVALID_AUDIENCE_TYPE;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_INVALID_POLICY;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_NULL_SHARE;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_NULL_UNSHARE;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_ORGANIZATIONS_NULL;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_ORG_ID_NULL;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_POLICY_NULL;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_ROLES_NULL;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_ROLE_NAME_NULL;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_ROLE_NOT_FOUND;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_INVALID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.LOG_WARN_SKIP_ORG_SHARE_MESSAGE;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ORGANIZATION;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.USER_IDS;
import static org.wso2.carbon.identity.organization.management.service.util.Utils.getOrganizationId;

/**
 * Implementation of the user sharing policy handler service.
 */
public class UserSharingPolicyHandlerServiceImpl implements UserSharingPolicyHandlerService {

    private static final Log LOG = LogFactory.getLog(UserSharingPolicyHandlerServiceImpl.class);
    private final UserIDResolver userIDResolver = new UserIDResolver();
    private static final ExecutorService EXECUTOR = Executors.newFixedThreadPool(1);
    private ConcurrentLinkedQueue<SharedResult> sharedResults = new ConcurrentLinkedQueue<>();

    @Override
    public void populateSelectiveUserShare(SelectiveUserShareDO selectiveUserShareDO) throws UserSharingMgtException {

        validateUserShareInput(selectiveUserShareDO);
        String sharingInitiatedOrgId = getOrganizationId();

        List<SelectiveUserShareOrgDetailsDO> organizations = selectiveUserShareDO.getOrganizations();
        Map<String, UserCriteriaType> userCriteria = selectiveUserShareDO.getUserCriteria();

        List<SelectiveUserShareOrgDetailsDO> validOrganizations =
                filterValidOrganizations(organizations, sharingInitiatedOrgId);

        // Run the sharing logic asynchronously.
        CompletableFuture.runAsync(
                        () -> processSelectiveUserShare(validOrganizations, userCriteria, sharingInitiatedOrgId),
                        EXECUTOR)
                .exceptionally(ex -> {
                    LOG.error("Error occurred during async user selective share processing.", ex);
                    return null;
                });
    }

    @Override
    public void populateGeneralUserShare(GeneralUserShareDO generalUserShareDO) throws UserSharingMgtException {

        validateUserShareInput(generalUserShareDO);
        String sharingInitiatedOrgId = getOrganizationId();

        Map<String, UserCriteriaType> userCriteria = generalUserShareDO.getUserCriteria();
        PolicyEnum policy = generalUserShareDO.getPolicy();
        List<String> roleIds = getRoleIds(generalUserShareDO.getRoles(), sharingInitiatedOrgId);

        // Run the sharing logic asynchronously.
        CompletableFuture.runAsync(() -> processGeneralUserShare(userCriteria, policy, roleIds, sharingInitiatedOrgId),
                        EXECUTOR)
                .exceptionally(ex -> {
                    LOG.error("Error occurred during async general user share processing.", ex);
                    return null;
                });
    }

    @Override
    public void populateSelectiveUserUnshare(SelectiveUserUnshareDO selectiveUserUnshareDO)
            throws UserSharingMgtException {

        validateUserUnshareInput(selectiveUserUnshareDO);
        String sharingInitiatedOrgId = getOrganizationId();

        Map<String, UserCriteriaType> userCriteria = selectiveUserUnshareDO.getUserCriteria();
        List<String> organizations = selectiveUserUnshareDO.getOrganizations();

        // Run the unsharing logic asynchronously.
        CompletableFuture.runAsync(
                        () -> processSelectiveUserUnshare(userCriteria, organizations, sharingInitiatedOrgId), EXECUTOR)
                .exceptionally(ex -> {
                    LOG.error("Error occurred during async user selective unshare processing.", ex);
                    return null;
                });
    }

    @Override
    public void populateGeneralUserUnshare(GeneralUserUnshareDO generalUserUnshareDO) throws UserSharingMgtException {

        validateUserUnshareInput(generalUserUnshareDO);
        String sharingInitiatedOrgId = getOrganizationId();

        Map<String, UserCriteriaType> userCriteria = generalUserUnshareDO.getUserCriteria();

        // Run the unsharing logic asynchronously.
        CompletableFuture.runAsync(() -> processGeneralUserUnshare(userCriteria, sharingInitiatedOrgId), EXECUTOR)
                .exceptionally(ex -> {
                    LOG.error("Error occurred during async general user unshare processing.", ex);
                    return null;
                });
    }

    @Override
    public ResponseSharedOrgsDO getSharedOrganizationsOfUser(String associatedUserId, String after, String before,
                                                             Integer limit, String filter, Boolean recursive)
            throws UserSharingMgtException {

        try {
            String sharingInitiatedOrgId = getOrganizationId();
            List<ResponseOrgDetailsDO> responseOrgDetailsDOS = new ArrayList<>();
            List<ResponseLinkDO> responseLinkList = Collections.singletonList(new ResponseLinkDO());
            List<UserAssociation> userAssociations =
                    getOrganizationUserSharingService().getUserAssociationsOfGivenUser(associatedUserId,
                            sharingInitiatedOrgId);

            for (UserAssociation userAssociation : userAssociations) {
                ResponseOrgDetailsDO responseOrgDetailsDO = new ResponseOrgDetailsDO();
                responseOrgDetailsDO.setOrganizationId(userAssociation.getOrganizationId());
                responseOrgDetailsDO.setOrganizationName(getOrganizationName(userAssociation.getOrganizationId()));
                responseOrgDetailsDO.setSharedUserId(userAssociation.getUserId());
                responseOrgDetailsDO.setSharedType(userAssociation.getSharedType());
                responseOrgDetailsDO.setRolesRef(getRolesRef(associatedUserId, userAssociation.getOrganizationId()));
                responseOrgDetailsDOS.add(responseOrgDetailsDO);
            }

            return new ResponseSharedOrgsDO(responseLinkList, responseOrgDetailsDOS);
        } catch (OrganizationManagementException e) {
            throw new UserSharingMgtClientException(ERROR_CODE_GET_SHARED_ORGANIZATIONS_OF_USER);
        }
    }

    @Override
    public ResponseSharedRolesDO getRolesSharedWithUserInOrganization(String associatedUserId, String orgId,
                                                                      String after, String before, Integer limit,
                                                                      String filter, Boolean recursive)
            throws UserSharingMgtException {

        try {
            List<RoleWithAudienceDO> roleWithAudienceList = new ArrayList<>();
            List<ResponseLinkDO> responseLinkList = Collections.singletonList(new ResponseLinkDO());
            UserAssociation userAssociation =
                    getOrganizationUserSharingService().getUserAssociationOfAssociatedUserByOrgId(associatedUserId,
                            orgId);

            if (userAssociation == null) {
                return new ResponseSharedRolesDO(responseLinkList, roleWithAudienceList);
            }

            String tenantDomain = getOrganizationManager().resolveTenantDomain(orgId);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

            String usernameWithDomain = getUserNameByUserID(userAssociation.getUserId(), tenantDomain);
            String username = UserCoreUtil.removeDomainFromName(usernameWithDomain);
            String domainName = UserCoreUtil.extractDomainFromName(usernameWithDomain);

            List<String> sharedRoleIdsInOrg =
                    getOrganizationUserSharingService().getRolesSharedWithUserInOrganization(username, tenantId,
                            domainName);

            if (CollectionUtils.isEmpty(sharedRoleIdsInOrg)) {
                return new ResponseSharedRolesDO(responseLinkList, roleWithAudienceList);
            }

            RoleManagementService roleManagementService = getRoleManagementService();

            for (String sharedRoleId : sharedRoleIdsInOrg) {
                Role role = roleManagementService.getRole(sharedRoleId, tenantDomain);
                RoleWithAudienceDO roleWithAudience = new RoleWithAudienceDO();
                roleWithAudience.setRoleName(role.getName());
                roleWithAudience.setAudienceName(role.getAudienceName());
                roleWithAudience.setAudienceType(role.getAudience());
                roleWithAudienceList.add(roleWithAudience);
            }

            return new ResponseSharedRolesDO(responseLinkList, roleWithAudienceList);
        } catch (OrganizationManagementException | IdentityRoleManagementException e) {
            throw new UserSharingMgtClientException(ERROR_CODE_GET_ROLES_SHARED_WITH_SHARED_USER);
        }
    }

    private SharedResult buildOrUpdateSharedResult(SharedResult currentSharedResult, String userId, String orgId,
                                                   String associatedUserId, String associatedOrgId,
                                                   SharedResult.SharingType sharingType, RoleWithAudienceDO role,
                                                   SharedResult.SharedStatus status, String statusDetail,
                                                   Throwable error) {

        SharedResult.Builder builder = (currentSharedResult != null)
                ? currentSharedResult.toBuilder()
                : new SharedResult.Builder();

        return builder.userId(userId)
                .orgId(orgId)
                .associatedUserId(associatedUserId)
                .associatedOrgId(associatedOrgId)
                .sharingType(sharingType)
                .role(role)
                .status(status)
                .statusDetail(statusDetail)
                .error(error)
                .build();
    }

    private void processSelectiveUserShare(List<SelectiveUserShareOrgDetailsDO> validOrganizations,
                                           Map<String, UserCriteriaType> userCriteria, String sharingInitiatedOrgId) {

        try {
            startTenantFlowFromOrganization(sharingInitiatedOrgId);
            sharedResults.clear();
            for (SelectiveUserShareOrgDetailsDO organization : validOrganizations) {
                for (Map.Entry<String, UserCriteriaType> criterion : userCriteria.entrySet()) {
                    String criterionKey = criterion.getKey();
                    UserCriteriaType criterionValues = criterion.getValue();
                    switch (criterionKey) {
                        case USER_IDS:
                            if (criterionValues instanceof UserIdList) {
                                selectiveUserShareByUserIds((UserIdList) criterionValues, organization,
                                        sharingInitiatedOrgId);
                            } else {
                                LOG.error("Invalid user criteria provided for selective user share: " + criterionKey);
                            }
                            break;
                        default:
                            LOG.error("Invalid user criteria provided for selective user share: " + criterionKey);
                    }
                }
            }
            LOG.debug("Completed user selective share initiated from " + sharingInitiatedOrgId + ".");
        } finally {
            //todo: display errors
            sharedResults.clear();
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    private void processGeneralUserShare(Map<String, UserCriteriaType> userCriteria, PolicyEnum policy,
                                         List<String> roleIds, String sharingInitiatedOrgId) {

        try {
            startTenantFlowFromOrganization(sharingInitiatedOrgId);
            sharedResults.clear();
            for (Map.Entry<String, UserCriteriaType> criterion : userCriteria.entrySet()) {
                String criterionKey = criterion.getKey();
                UserCriteriaType criterionValues = criterion.getValue();
                switch (criterionKey) {
                    case USER_IDS:
                        if (criterionValues instanceof UserIdList) {
                            generalUserShareByUserIds((UserIdList) criterionValues, policy, roleIds,
                                    sharingInitiatedOrgId);
                        } else {
                            LOG.error("Invalid user criteria provided for general user share: " + criterionKey);
                        }
                        break;
                    default:
                        LOG.error("Invalid user criteria provided for general user share: " + criterionKey);
                }
            }
            LOG.debug("Completed general user share initiated from " + sharingInitiatedOrgId + ".");
        } finally {
            //todo: display errors
            sharedResults.clear();
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    private void processSelectiveUserUnshare(Map<String, UserCriteriaType> userCriteria, List<String> organizations,
                                             String sharingInitiatedOrgId) {

        try {
            startTenantFlowFromOrganization(sharingInitiatedOrgId);
            sharedResults.clear();
            for (Map.Entry<String, UserCriteriaType> criterion : userCriteria.entrySet()) {
                String criterionKey = criterion.getKey();
                UserCriteriaType criterionValues = criterion.getValue();
                switch (criterionKey) {
                    case USER_IDS:
                        if (criterionValues instanceof UserIdList) {
                            selectiveUserUnshareByUserIds((UserIdList) criterionValues, organizations,
                                    sharingInitiatedOrgId);
                        } else {
                            LOG.error("Invalid user criteria provided for selective user unshare: " + criterionKey);
                        }
                        break;
                    default:
                        LOG.error("Invalid user criteria provided for selective user unshare: " + criterionKey);
                }
            }
            LOG.debug("Completed selective user unshare initiated from " + sharingInitiatedOrgId + ".");
        } finally {
            //todo: display errors
            sharedResults.clear();
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    private void processGeneralUserUnshare(Map<String, UserCriteriaType> userCriteria, String sharingInitiatedOrgId) {

        try {
            startTenantFlowFromOrganization(sharingInitiatedOrgId);
            sharedResults.clear();
            for (Map.Entry<String, UserCriteriaType> criterion : userCriteria.entrySet()) {
                String criterionKey = criterion.getKey();
                UserCriteriaType criterionValues = criterion.getValue();
                switch (criterionKey) {
                    case USER_IDS:
                        if (criterionValues instanceof UserIdList) {
                            generalUserUnshareByUserIds((UserIdList) criterionValues, sharingInitiatedOrgId);
                        } else {
                            LOG.error("Invalid user criteria provided for general user unshare: " + criterionKey);
                        }
                        break;
                    default:
                        LOG.error("Invalid user criteria provided for general user unshare: " + criterionKey);
                }
            }
            LOG.debug("Completed general user unshare initiated from " + sharingInitiatedOrgId + ".");
        } finally {
            //todo: display errors
            sharedResults.clear();
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    private List<SelectiveUserShareOrgDetailsDO> filterValidOrganizations(
            List<SelectiveUserShareOrgDetailsDO> organizations, String sharingInitiatedOrgId)
            throws UserSharingMgtServerException {

        List<String> immediateChildOrgs = getChildOrgsOfSharingInitiatedOrg(sharingInitiatedOrgId);

        List<SelectiveUserShareOrgDetailsDO> validOrganizations = organizations.stream()
                .filter(org -> immediateChildOrgs.contains(org.getOrganizationId()))
                .collect(Collectors.toList());

        List<String> skippedOrganizations = organizations.stream()
                .map(SelectiveUserShareOrgDetailsDO::getOrganizationId)
                .filter(orgId -> !immediateChildOrgs.contains(orgId))
                .collect(Collectors.toList());

        if (!skippedOrganizations.isEmpty()) {
            LOG.warn(String.format(LOG_WARN_SKIP_ORG_SHARE_MESSAGE, skippedOrganizations));
        }

        return validOrganizations;
    }

    private void selectiveUserShareByUserIds(UserIdList userIds, SelectiveUserShareOrgDetailsDO organization,
                                             String sharingInitiatedOrgId) {

        for (String associatedUserId : userIds.getIds()) {
            try {
                SelectiveUserShare selectiveUserShare = new SelectiveUserShare.Builder()
                        .userId(associatedUserId)
                        .organizationId(organization.getOrganizationId())
                        .policy(organization.getPolicy())
                        .roles(getRoleIds(organization.getRoles(), sharingInitiatedOrgId))
                        .build();
                shareUser(selectiveUserShare, sharingInitiatedOrgId);
            } catch (UserSharingMgtException e) {
                SharedResult sharedResult = buildOrUpdateSharedResult(null, null, organization.getOrganizationId(),
                        associatedUserId, sharingInitiatedOrgId, SharedResult.SharingType.SHARE, null,
                        SharedResult.SharedStatus.FAILED, e.getMessage(), e);
                sharedResults.add(sharedResult);
            }
        }
    }

    private void shareUser(BaseUserShare userShare, String sharingInitiatedOrgId) {

        List<String> orgsToShareUserWith = getOrgsToShareUserWithBasedOnSharingType(userShare, sharingInitiatedOrgId);
        if (isUserAlreadyShared(userShare.getUserId(), sharingInitiatedOrgId)) {
            handleExistingSharedUser(userShare, sharingInitiatedOrgId, orgsToShareUserWith);
        } else {
            createNewUserShare(userShare, sharingInitiatedOrgId, orgsToShareUserWith);
        }
    }

    private List<String> getOrgsToShareUserWithBasedOnSharingType(BaseUserShare userShare,
                                                                  String sharingInitiatedOrgId) {

        try {
            if (userShare instanceof SelectiveUserShare) {
                return getOrgsToShareUserWith(((SelectiveUserShare) userShare).getOrganizationId(),
                        userShare.getPolicy());
            }
            return getOrgsToShareUserWith(sharingInitiatedOrgId, userShare.getPolicy());
        } catch (UserSharingMgtException e) {
            SharedResult sharedResult = new SharedResult.Builder().associatedUserId(userShare.getUserId())
                    .associatedOrgId(sharingInitiatedOrgId)
                    .status(SharedResult.SharedStatus.FAILED)
                    .statusDetail(e.getMessage())
                    .build();
            sharedResults.add(sharedResult);
        }
        return new ArrayList<>();
    }

    private void handleExistingSharedUser(BaseUserShare userShare, String sharingInitiatedOrgId,
                                          List<String> orgsToShareUserWith) {

        List<UserAssociation> userAssociations =
                getSharedUserAssociationsOfGivenUser(userShare.getUserId(), sharingInitiatedOrgId);
        List<String> retainedSharedOrganizations = new ArrayList<>();

        for (UserAssociation association : userAssociations) {
            if (!orgsToShareUserWith.contains(association.getOrganizationId())) {
                unshareUserFromPreviousOrg(association, sharingInitiatedOrgId);
            } else {
                retainedSharedOrganizations.add(association.getOrganizationId());
                updateRolesIfNecessary(association, userShare.getRoles(), sharingInitiatedOrgId);
            }
        }

        shareWithNewOrganizations(userShare, sharingInitiatedOrgId, orgsToShareUserWith, retainedSharedOrganizations);
        updateResourceSharingPolicy(userShare, sharingInitiatedOrgId);
    }

    private void unshareUserFromPreviousOrg(UserAssociation association, String sharingInitiatedOrgId) {

        selectiveUserUnshareByUserIds(new UserIdList(Collections.singletonList(association.getAssociatedUserId())),
                Collections.singletonList(association.getOrganizationId()), sharingInitiatedOrgId);
    }

    private void shareWithNewOrganizations(BaseUserShare userShare, String sharingInitiatedOrgId,
                                           List<String> orgsToShareUserWith, List<String> alreadySharedOrgs) {

        List<String> newlySharedOrgs = new ArrayList<>(orgsToShareUserWith);
        newlySharedOrgs.removeAll(alreadySharedOrgs);

        for (String orgId : newlySharedOrgs) {
            shareAndAssignRolesIfPresent(orgId, userShare, sharingInitiatedOrgId);
        }
    }

    private void createNewUserShare(BaseUserShare userShare, String sharingInitiatedOrgId,
                                    List<String> orgsToShareUserWith) {

        for (String orgId : orgsToShareUserWith) {
            shareAndAssignRolesIfPresent(orgId, userShare, sharingInitiatedOrgId);
        }

        if (isApplicableOrganizationScopeForSavingPolicy(userShare.getPolicy())) {
            saveUserSharingPolicy(userShare, sharingInitiatedOrgId);
        }
    }

    private List<String> getChildOrgsOfSharingInitiatedOrg(String sharingInitiatedOrgId)
            throws UserSharingMgtServerException {

        try {
            return getOrganizationManager().getChildOrganizationsIds(getOrganizationId(), false);
        } catch (OrganizationManagementException e) {
            String errorMessage = String.format(
                    ERROR_CODE_GET_IMMEDIATE_CHILD_ORGS.getMessage(), sharingInitiatedOrgId);
            throw new UserSharingMgtServerException(ERROR_CODE_GET_IMMEDIATE_CHILD_ORGS, errorMessage);
        }
    }

    private void generalUserShareByUserIds(UserIdList userIds, PolicyEnum policy, List<String> roleIds,
                                           String sharingInitiatedOrgId) {

        for (String associatedUserId : userIds.getIds()) {
            try {
                GeneralUserShare generalUserShare = new GeneralUserShare.Builder()
                        .userId(associatedUserId)
                        .policy(policy)
                        .roles(roleIds)
                        .build();
                shareUser(generalUserShare, sharingInitiatedOrgId);
            } catch (UserSharingMgtException e) {
                sharedResults.add(buildOrUpdateSharedResult(null, null, null, associatedUserId, sharingInitiatedOrgId
                        , SharedResult.SharingType.SHARE, null, SharedResult.SharedStatus.FAILED, e.getMessage(), e));
            }
        }
    }

    private boolean hasRoleChanges(List<String> oldSharedRoleIds, List<String> newRoleIds) {

        return !new HashSet<>(oldSharedRoleIds).equals(new HashSet<>(newRoleIds));
    }

    private void updateRolesIfNecessary(UserAssociation userAssociation, List<String> roleIds,
                                        String sharingInitiatedOrgId) {

        List<String> currentSharedRoleIds;
        try {
            currentSharedRoleIds = getCurrentSharedRoleIdsForSharedUser(userAssociation);
        } catch (UserSharingMgtServerException e) {
            SharedResult sharedResult = buildOrUpdateSharedResult(null, userAssociation.getUserId(),
                    userAssociation.getOrganizationId(), userAssociation.getAssociatedUserId(),
                    userAssociation.getUserResidentOrganizationId(), SharedResult.SharingType.SHARE, null,
                    SharedResult.SharedStatus.FAILED, ERROR_CODE_GET_ROLES_SHARED_WITH_SHARED_USER.getMessage(), e);
            sharedResults.add(sharedResult);
            return;
        }
        List<String> newSharedRoleIds = getRolesToBeAddedAfterUpdate(userAssociation, currentSharedRoleIds, roleIds);

        if (hasRoleChanges(currentSharedRoleIds, newSharedRoleIds)) {
            SharedResult sharedResult =
                    new SharedResult.Builder().associatedUserId(userAssociation.getAssociatedUserId())
                            .associatedOrgId(userAssociation.getUserResidentOrganizationId())
                            .status(SharedResult.SharedStatus.SUCCESSFUL)
                            .build();
            assignRolesIfPresent(userAssociation, sharingInitiatedOrgId, newSharedRoleIds, sharedResult);
        }
    }

    private List<String> getCurrentSharedRoleIdsForSharedUser(UserAssociation userAssociation)
            throws UserSharingMgtServerException {

        try {
            String userId = userAssociation.getUserId();
            String orgId = userAssociation.getOrganizationId();
            String tenantDomain = getOrganizationManager().resolveTenantDomain(orgId);

            List<String> allUserRolesOfSharedUser =
                    getRoleManagementService().getRoleIdListOfUser(userId, tenantDomain);

            return getOrganizationUserSharingService().getSharedUserRolesFromUserRoles(allUserRolesOfSharedUser,
                    tenantDomain);
        } catch (OrganizationManagementException | IdentityRoleManagementException e) {
            throw new UserSharingMgtServerException(ERROR_CODE_GET_ROLES_SHARED_WITH_SHARED_USER);
        }
    }

    private void updateResourceSharingPolicy(BaseUserShare baseUserShare, String sharingInitiatedOrgId) {

        //Delete old sharing policy.
        deleteOldResourceSharingPolicy(baseUserShare, sharingInitiatedOrgId);

        //Create new sharing policy.
        if (isApplicableOrganizationScopeForSavingPolicy(baseUserShare.getPolicy())) {
            saveUserSharingPolicy(baseUserShare, sharingInitiatedOrgId);
        }
    }

    private void deleteOldResourceSharingPolicy(BaseUserShare baseUserShare, String sharingInitiatedOrgId) {

        try {
            getResourceSharingPolicyHandlerService().deleteResourceSharingPolicyInOrgByResourceTypeAndId(
                    sharingInitiatedOrgId, ResourceType.USER, baseUserShare.getUserId(), sharingInitiatedOrgId);
        } catch (ResourceSharingPolicyMgtException e) {
            SharedResult sharedResult = new SharedResult.Builder().associatedUserId(baseUserShare.getUserId())
                    .associatedOrgId(sharingInitiatedOrgId)
                    .status(SharedResult.SharedStatus.FAILED)
                    .statusDetail(e.getMessage())
                    .error(e)
                    .build();
            sharedResults.add(sharedResult);
        }
    }

    private void saveUserSharingPolicy(BaseUserShare userShare, String sharingInitiatedOrgId) {

        try {
            ResourceSharingPolicyHandlerService resourceSharingPolicyHandlerService =
                    getResourceSharingPolicyHandlerService();

            ResourceSharingPolicy resourceSharingPolicy =
                    new ResourceSharingPolicy.Builder().withResourceType(ResourceType.USER)
                            .withResourceId(userShare.getUserId())
                            .withInitiatingOrgId(sharingInitiatedOrgId)
                            .withPolicyHoldingOrgId(getPolicyHoldingOrgId(userShare, sharingInitiatedOrgId))
                            .withSharingPolicy(userShare.getPolicy()).build();

            List<SharedResourceAttribute> sharedResourceAttributes = new ArrayList<>();
            for (String roleId : userShare.getRoles()) {
                SharedResourceAttribute sharedResourceAttribute =
                        new SharedResourceAttribute.Builder().withSharedAttributeType(SharedAttributeType.ROLE)
                                .withSharedAttributeId(roleId).build();
                sharedResourceAttributes.add(sharedResourceAttribute);
            }

            resourceSharingPolicyHandlerService.addResourceSharingPolicyWithAttributes(resourceSharingPolicy,
                    sharedResourceAttributes);
        } catch (ResourceSharingPolicyMgtException e) {
            SharedResult sharedResult = new SharedResult.Builder().associatedUserId(userShare.getUserId())
                    .associatedOrgId(sharingInitiatedOrgId)
                    .status(SharedResult.SharedStatus.FAILED)
                    .statusDetail("Error occurred while saving user sharing policy.")
                    .build();
            sharedResults.add(sharedResult);
        }
    }

    /**
     * Determines the policy-holding organization ID based on the type of user share.
     * For a selective user share, the policy-holding organization is the organization specified in the selective
     * share request.
     * For a general user share, the policy-holding organization is the organization from which the
     * sharing request was initiated.
     *
     * @param userShare             The user share object, which can be either selective or general.
     * @param sharingInitiatedOrgId The ID of the organization from which the sharing request was initiated.
     * @return The ID of the policy-holding organization based on the type of user share.
     */
    private String getPolicyHoldingOrgId(BaseUserShare userShare, String sharingInitiatedOrgId) {

        if (userShare instanceof SelectiveUserShare) {
            return ((SelectiveUserShare) userShare).getOrganizationId();
        } else {
            return sharingInitiatedOrgId;
        }
    }

    private boolean isApplicableOrganizationScopeForSavingPolicy(PolicyEnum policy) {

        return OrganizationScope.EXISTING_ORGS_AND_FUTURE_ORGS_ONLY.equals(policy.getOrganizationScope()) ||
                OrganizationScope.FUTURE_ORGS_ONLY.equals(policy.getOrganizationScope());
    }

    private void shareAndAssignRolesIfPresent(String orgId, BaseUserShare baseUserShare,
                                              String sharingInitiatedOrgId) {

        String associatedUserId = baseUserShare.getUserId();
        List<String> roleIds = baseUserShare.getRoles();

        SharedResult sharedResult = buildOrUpdateSharedResult(null, null, orgId, associatedUserId,
                sharingInitiatedOrgId, SharedResult.SharingType.SHARE, null, null, null, null);

        try {
            UserAssociation userAssociation = shareUserWithOrganization(orgId, associatedUserId, sharingInitiatedOrgId);
            sharedResult = buildOrUpdateSharedResult(sharedResult, userAssociation.getUserId(), orgId, associatedUserId,
                    sharingInitiatedOrgId, SharedResult.SharingType.SHARE, null, SharedResult.SharedStatus.SUCCESSFUL,
                    "User Shared Successfully.", null);
            assignRolesIfPresent(userAssociation, sharingInitiatedOrgId, roleIds, sharedResult);
        } catch (OrganizationManagementException e) {
            sharedResult = buildOrUpdateSharedResult(sharedResult, null, orgId, associatedUserId, sharingInitiatedOrgId,
                    SharedResult.SharingType.SHARE, null, SharedResult.SharedStatus.FAILED, e.getMessage(), e);
            sharedResults.add(sharedResult);
        }
    }

    private boolean isUserAlreadyShared(String associatedUserId, String associatedOrgId) {

        List<UserAssociation> userAssociationsOfGivenUser =
                getSharedUserAssociationsOfGivenUser(associatedUserId, associatedOrgId);

        return userAssociationsOfGivenUser != null && !userAssociationsOfGivenUser.isEmpty();
    }

    private List<UserAssociation> getSharedUserAssociationsOfGivenUser(String associatedUserId,
                                                                       String associatedOrgId) {

        try {
            return getOrganizationUserSharingService().getUserAssociationsOfGivenUser(associatedUserId, associatedOrgId,
                    SharedType.SHARED);
        } catch (OrganizationManagementException e) {
            SharedResult sharedResult = buildOrUpdateSharedResult(null, null, null, associatedUserId, associatedOrgId,
                    SharedResult.SharingType.SHARE, null, SharedResult.SharedStatus.FAILED,
                    ERROR_CODE_GET_SHARED_ORGANIZATIONS_OF_USER.getMessage(), e);
            sharedResults.add(sharedResult);
        }
        return Collections.emptyList();
    }

    private List<String> getRolesToBeAddedAfterUpdate(UserAssociation userAssociation, List<String> currentRoleIds,
                                                      List<String> newRoleIds) {

        // Roles to be added are those in newRoleIds that are not in currentRoleIds.
        List<String> rolesToBeAdded = new ArrayList<>(newRoleIds);
        rolesToBeAdded.removeAll(currentRoleIds);

        // Roles to be removed are those in currentRoleIds that are not in newRoleIds.
        List<String> rolesToBeRemoved = new ArrayList<>(currentRoleIds);
        rolesToBeRemoved.removeAll(newRoleIds);

        deleteOldSharedRoles(userAssociation, rolesToBeRemoved);
        return rolesToBeAdded;
    }

    private void deleteOldSharedRoles(UserAssociation userAssociation, List<String> rolesToBeRemoved) {

        String userId = userAssociation.getUserId();
        String orgId = userAssociation.getOrganizationId();
        OrganizationManager organizationManager = getOrganizationManager();

        for (String roleId : rolesToBeRemoved) {
            SharedResult sharedResult = new SharedResult.Builder().build();
            try {
                getRoleManagementService().updateUserListOfRole(roleId, Collections.emptyList(),
                        Collections.singletonList(userId), organizationManager.resolveTenantDomain(orgId));
                sharedResult = sharedResult.toBuilder().associatedUserId(userId)
                        .associatedOrgId(userAssociation.getUserResidentOrganizationId())
                        .orgId(orgId)
                        .role(getRoleWithAudienceByRoleId(roleId))
                        .status(SharedResult.SharedStatus.SUCCESSFUL)
                        .build();
                sharedResults.add(sharedResult);
            } catch (OrganizationManagementException | IdentityRoleManagementException e) {
                sharedResult = sharedResult.toBuilder().status(SharedResult.SharedStatus.FAILED)
                        .statusDetail("Role unassignment from the shared user failed.")
                        .error(e)
                        .build();
                sharedResults.add(sharedResult);
            }
        }
    }

    private void assignRolesIfPresent(UserAssociation userAssociation, String sharingInitiatedOrgId,
                                      List<String> roleIds, SharedResult sharedResult) {

        if (roleIds.isEmpty()) {
            sharedResults.add(sharedResult);
            return;
        }
        assignRolesToTheSharedUser(userAssociation, sharingInitiatedOrgId, roleIds, sharedResult);
    }

    private void assignRolesToTheSharedUser(UserAssociation userAssociation, String sharingInitiatedOrgId,
                                            List<String> roleIds, SharedResult sharedResult) {

        try {
            String userId = userAssociation.getUserId();
            String orgId = userAssociation.getOrganizationId();
            String sharingInitiatedOrgTenantDomain =
                    getOrganizationManager().resolveTenantDomain(sharingInitiatedOrgId);
            String targetOrgTenantDomain = getOrganizationManager().resolveTenantDomain(orgId);

            String usernameWithDomain = getUserNameByUserID(userId, targetOrgTenantDomain);
            String username = UserCoreUtil.removeDomainFromName(usernameWithDomain);
            String domainName = UserCoreUtil.extractDomainFromName(usernameWithDomain);

            RoleManagementService roleManagementService = getRoleManagementService();
            Map<String, String> sharedRoleToMainRoleMappingsBySubOrg =
                    roleManagementService.getSharedRoleToMainRoleMappingsBySubOrg(roleIds,
                            sharingInitiatedOrgTenantDomain);

            List<String> mainRoles = new ArrayList<>();
            for (String roleId : roleIds) {
                mainRoles.add(sharedRoleToMainRoleMappingsBySubOrg.getOrDefault(roleId, roleId));
            }

            Map<String, String> mainRoleToSharedRoleMappingsBySubOrg =
                    roleManagementService.getMainRoleToSharedRoleMappingsBySubOrg(mainRoles, targetOrgTenantDomain);

            for (String roleId : mainRoleToSharedRoleMappingsBySubOrg.values()) {

                assignRoleAndAddEditRestriction(roleId, userId, username, targetOrgTenantDomain, domainName,
                        sharingInitiatedOrgId, sharedResult);
            }
        } catch (OrganizationManagementException | IdentityRoleManagementException e) {
            sharedResult = buildOrUpdateSharedResult(sharedResult, sharedResult.getUserId(), sharedResult.getOrgId(),
                    sharedResult.getAssociatedUserId(), sharedResult.getAssociatedOrgId(),
                    SharedResult.SharingType.SHARE, null,
                    SharedResult.SharedStatus.FAILED, sharedResult.getStatusDetail() +
                            " Role Assignment to the shared user failed at retrieving the roleId in the sub org.", e);
            sharedResults.add(sharedResult);
        }
    }

    private void assignRoleAndAddEditRestriction(String roleId, String userId, String username, String tenantDomain,
                                                 String domainName, String sharingInitiatedOrgId,
                                                 SharedResult sharedResult) {

        try {
            getRoleManagementService().updateUserListOfRole(roleId, Collections.singletonList(userId),
                    Collections.emptyList(), tenantDomain);

            sharedResult = buildOrUpdateSharedResult(sharedResult, sharedResult.getUserId(), sharedResult.getOrgId(),
                    sharedResult.getAssociatedUserId(), sharedResult.getAssociatedOrgId(),
                    sharedResult.getSharingType(), getRoleWithAudienceByRoleId(roleId),
                    SharedResult.SharedStatus.SUCCESSFUL,
                    sharedResult.getStatusDetail() + " Role assigned successfully.", null);
        } catch (IdentityRoleManagementException e) {
            sharedResult = buildOrUpdateSharedResult(sharedResult, sharedResult.getUserId(), sharedResult.getOrgId(),
                    sharedResult.getAssociatedUserId(), sharedResult.getAssociatedOrgId(),
                    sharedResult.getSharingType(), null, SharedResult.SharedStatus.FAILED,
                    sharedResult.getStatusDetail() + " Role Assignment to the shared user failed.", e);
            sharedResults.add(sharedResult);
        }

        addEditRestriction(roleId, username, tenantDomain, domainName, sharingInitiatedOrgId, sharedResult);
    }

    private void addEditRestriction(String roleId, String username,
                                    String tenantDomain, String domainName, String sharingInitiatedOrgId,
                                    SharedResult sharedResult) {

        try {
            getOrganizationUserSharingService().addEditRestrictionsForSharedUserRole(roleId, username,
                    tenantDomain, domainName, EditOperation.DELETE, sharingInitiatedOrgId);
            sharedResult = buildOrUpdateSharedResult(sharedResult, sharedResult.getUserId(), sharedResult.getOrgId(),
                    sharedResult.getAssociatedUserId(), sharedResult.getAssociatedOrgId(),
                    sharedResult.getSharingType(), getRoleWithAudienceByRoleId(roleId),
                    SharedResult.SharedStatus.SUCCESSFUL,
                    sharedResult.getStatusDetail() + " Role edit restrictions added successfully.", null);
            sharedResults.add(sharedResult);
        } catch (UserSharingMgtException e) {
            RoleWithAudienceDO role = getRoleWithAudienceByRoleId(roleId);
            sharedResult = buildOrUpdateSharedResult(sharedResult, sharedResult.getUserId(), sharedResult.getOrgId(),
                    sharedResult.getAssociatedUserId(), sharedResult.getAssociatedOrgId(),
                    sharedResult.getSharingType(), role, SharedResult.SharedStatus.FAILED, String.format("Error " +
                            "occurred while adding edit restrictions for shared user roleId: %s", roleId), e);
            sharedResults.add(sharedResult);
        }
    }

    private RoleWithAudienceDO getRoleWithAudienceByRoleId(String roleId) {

        try {
            Role role = getRoleManagementService().getRole(roleId);
            RoleWithAudienceDO roleWithAudienceDO = new RoleWithAudienceDO();
            roleWithAudienceDO.setRoleName(role.getName());
            roleWithAudienceDO.setAudienceName(role.getAudienceName());
            roleWithAudienceDO.setAudienceType(role.getAudience());
            return roleWithAudienceDO;
        } catch (IdentityRoleManagementException e) {
            LOG.error(String.format(ERROR_CODE_GET_ROLE_WITH_AUDIENCE_BY_ROLE_ID.getMessage(), roleId));
        }
        return null;
    }

    private UserAssociation shareUserWithOrganization(String orgId, String associatedUserId, String associatedOrgId)
            throws OrganizationManagementException {

        OrganizationUserSharingService organizationUserSharingService = getOrganizationUserSharingService();
        organizationUserSharingService.shareOrganizationUser(orgId, associatedUserId, associatedOrgId,
                SharedType.SHARED);
        return organizationUserSharingService.getUserAssociationOfAssociatedUserByOrgId(associatedUserId, orgId);
    }

    private List<String> getOrgsToShareUserWith(String policyHoldingOrgId, PolicyEnum policy)
            throws UserSharingMgtException {

        Set<String> orgsToShareUserWith = new HashSet<>();

        try {
            switch (policy) {
                case ALL_EXISTING_ORGS_ONLY:
                case ALL_EXISTING_AND_FUTURE_ORGS:
                    orgsToShareUserWith.addAll(getOrganizationManager()
                            .getChildOrganizationsIds(policyHoldingOrgId, true));
                    break;

                case IMMEDIATE_EXISTING_ORGS_ONLY:
                case IMMEDIATE_EXISTING_AND_FUTURE_ORGS:
                    orgsToShareUserWith.addAll(getOrganizationManager()
                            .getChildOrganizationsIds(policyHoldingOrgId, false));
                    break;

                case SELECTED_ORG_ONLY:
                    orgsToShareUserWith.add(policyHoldingOrgId);
                    break;

                case SELECTED_ORG_WITH_ALL_EXISTING_CHILDREN_ONLY:
                case SELECTED_ORG_WITH_ALL_EXISTING_AND_FUTURE_CHILDREN:
                    orgsToShareUserWith.add(policyHoldingOrgId);
                    orgsToShareUserWith.addAll(getOrganizationManager()
                            .getChildOrganizationsIds(policyHoldingOrgId, true));
                    break;

                case SELECTED_ORG_WITH_EXISTING_IMMEDIATE_CHILDREN_ONLY:
                case SELECTED_ORG_WITH_EXISTING_IMMEDIATE_AND_FUTURE_CHILDREN:
                    orgsToShareUserWith.add(policyHoldingOrgId);
                    orgsToShareUserWith.addAll(getOrganizationManager()
                            .getChildOrganizationsIds(policyHoldingOrgId, false));
                    break;

                case NO_SHARING:
                    break;

                default:
                    throw new UserSharingMgtClientException(ERROR_CODE_INVALID_POLICY,
                            String.format(ERROR_CODE_INVALID_POLICY.getMessage(), policy.getPolicyName()));
            }
        } catch (OrganizationManagementException e) {
            throw new UserSharingMgtServerException(ERROR_CODE_GET_ORGS_TO_SHARE_USER_WITH);
        }

        return new ArrayList<>(orgsToShareUserWith);
    }

    private List<String> getRoleIds(List<RoleWithAudienceDO> rolesWithAudience, String sharingInitiatedOrgId)
            throws UserSharingMgtException {

        try {
            String sharingInitiatedTenantDomain = getOrganizationManager().resolveTenantDomain(sharingInitiatedOrgId);

            List<String> list = new ArrayList<>();
            for (RoleWithAudienceDO roleWithAudienceDO : rolesWithAudience) {
                String audienceId =
                        getAudienceId(roleWithAudienceDO, sharingInitiatedOrgId, sharingInitiatedTenantDomain);
                Optional<String> roleId =
                        getRoleIdFromAudience(roleWithAudienceDO.getRoleName(), roleWithAudienceDO.getAudienceType(),
                                audienceId, sharingInitiatedTenantDomain);
                if (!roleId.isPresent()) {
                    continue;
                }
                list.add(roleId.get());
            }
            return list;
        } catch (OrganizationManagementException e) {
            throw new UserSharingMgtServerException(ERROR_CODE_GET_ROLE_IDS);
        }
    }

    private String getAudienceId(RoleWithAudienceDO role, String originalOrgId, String tenantDomain) {

        if (role == null || role.getAudienceType() == null) {
            return null;
        }

        try {
            if (StringUtils.equals(ORGANIZATION, role.getAudienceType())) {
                return originalOrgId;
            }
            if (StringUtils.equals(APPLICATION, role.getAudienceType())) {
                return getApplicationResourceId(role.getAudienceName(), tenantDomain);
            }
            LOG.warn(String.format(ERROR_CODE_INVALID_AUDIENCE_TYPE.getDescription(), role.getAudienceType()));
        } catch (IdentityApplicationManagementException e) {
            LOG.warn(String.format(ERROR_CODE_AUDIENCE_NOT_FOUND.getMessage(), role.getAudienceName()));
        }
        return null;
    }

    private String getApplicationResourceId(String audienceName, String tenantDomain)
            throws IdentityApplicationManagementException {

        ApplicationBasicInfo applicationBasicInfo = getApplicationManagementService()
                .getApplicationBasicInfoByName(audienceName, tenantDomain);

        if (applicationBasicInfo != null) {
            return applicationBasicInfo.getApplicationResourceId();
        }
        LOG.warn(String.format(ERROR_CODE_AUDIENCE_NOT_FOUND.getMessage(), audienceName));
        return null;
    }

    private Optional<String> getRoleIdFromAudience(String roleName, String audienceType, String audienceId,
                                                   String tenantDomain) {

        if (audienceId == null) {
            return Optional.empty();
        }

        try {
            return Optional.of(
                    getRoleManagementService().getRoleIdByName(roleName, audienceType, audienceId, tenantDomain));
        } catch (IdentityRoleManagementException e) {
            LOG.warn(String.format(ERROR_CODE_ROLE_NOT_FOUND.getMessage(), roleName, audienceType, audienceId));
            return Optional.empty();
        }
    }

    private void selectiveUserUnshareByUserIds(UserIdList userIds, List<String> organizations,
                                               String unsharingInitiatedOrgId) {

        for (String associatedUserId : userIds.getIds()) {
            for (String organizationId : organizations) {
                SharedResult sharedResult;
                try {
                    getOrganizationUserSharingService().unshareOrganizationUserInSharedOrganization(
                            associatedUserId,
                            organizationId);

                    sharedResult = buildOrUpdateSharedResult(null, null, organizationId, associatedUserId,
                            unsharingInitiatedOrgId, SharedResult.SharingType.UNSHARE, null,
                            SharedResult.SharedStatus.SUCCESSFUL, "User Unshared Successfully.", null);

                    deleteResourceSharingPolicyIfAny(organizationId, associatedUserId, unsharingInitiatedOrgId,
                            sharedResult);
                } catch (OrganizationManagementException e) {
                    sharedResult = buildOrUpdateSharedResult(null, null, organizationId, associatedUserId,
                            unsharingInitiatedOrgId, SharedResult.SharingType.UNSHARE, null,
                            SharedResult.SharedStatus.FAILED, "User unsharing failed.", e);
                    sharedResults.add(sharedResult);
                }
            }
        }
    }

    private void deleteResourceSharingPolicyIfAny(String organizationId, String associatedUserId,
                                                  String unsharingInitiatedOrgId, SharedResult sharedResult) {

        try {
            if (organizationId == null) {
                getResourceSharingPolicyHandlerService().deleteResourceSharingPolicyByResourceTypeAndId(
                        ResourceType.USER, associatedUserId, unsharingInitiatedOrgId);
            } else {
                getResourceSharingPolicyHandlerService().deleteResourceSharingPolicyInOrgByResourceTypeAndId(
                        organizationId, ResourceType.USER, associatedUserId, unsharingInitiatedOrgId);
            }
            sharedResult = buildOrUpdateSharedResult(sharedResult, sharedResult.getUserId(), organizationId,
                    associatedUserId, unsharingInitiatedOrgId, SharedResult.SharingType.UNSHARE, null,
                    SharedResult.SharedStatus.SUCCESSFUL,
                    sharedResult.getStatusDetail() + " Resource sharing policy successfully removed, if applicable.",
                    null);
            sharedResults.add(sharedResult);
        } catch (ResourceSharingPolicyMgtException e) {
            sharedResult = buildOrUpdateSharedResult(sharedResult, sharedResult.getUserId(), sharedResult.getOrgId(),
                    sharedResult.getAssociatedUserId(), sharedResult.getAssociatedOrgId(),
                    sharedResult.getSharingType(), sharedResult.getRole(),
                    SharedResult.SharedStatus.FAILED,
                    sharedResult.getStatusDetail() + " Error occurred while deleting resource sharing policy.", e);
            sharedResults.add(sharedResult);
        }
    }

    private void generalUserUnshareByUserIds(UserIdList userIds, String unsharingInitiatedOrgId) {

        for (String associatedUserId : userIds.getIds()) {
            SharedResult sharedResult;
            try {
                getOrganizationUserSharingService().unshareOrganizationUsers(associatedUserId, unsharingInitiatedOrgId);

                sharedResult = buildOrUpdateSharedResult(null, null, null, associatedUserId, unsharingInitiatedOrgId,
                        SharedResult.SharingType.UNSHARE, null, SharedResult.SharedStatus.SUCCESSFUL,
                        "User Unshared Successfully.", null);

                deleteResourceSharingPolicyIfAny(null, associatedUserId, unsharingInitiatedOrgId, sharedResult);
            } catch (OrganizationManagementException e) {
                sharedResult = buildOrUpdateSharedResult(null, null, null, associatedUserId, unsharingInitiatedOrgId,
                        SharedResult.SharingType.UNSHARE, null, SharedResult.SharedStatus.FAILED,
                        "User unsharing failed.", e);
                sharedResults.add(sharedResult);
            }
        }
    }

    private String getOrganizationName(String organizationId) throws OrganizationManagementException {

        return getOrganizationManager().getOrganizationNameById(organizationId);
    }

    private String getUserNameByUserID(String userId, String tenantDomain) throws IdentityRoleManagementException {

        return userIDResolver.getNameByID(userId, tenantDomain);
    }

    private String getRolesRef(String userId, String orgId) {

        return String.format(API_REF_GET_SHARED_ROLES_OF_USER_IN_ORG, userId, orgId);
    }

    //Validation methods.

    private <T extends UserCriteriaType> void validateUserShareInput(BaseUserShareDO<T> userShareDO)
            throws UserSharingMgtClientException {

        if (userShareDO == null) {
            throwValidationException(ERROR_CODE_NULL_SHARE);
        }

        if (userShareDO instanceof SelectiveUserShareDO) {
            validateSelectiveUserShareDO((SelectiveUserShareDO) userShareDO);
        } else if (userShareDO instanceof GeneralUserShareDO) {
            validateGeneralUserShareDO((GeneralUserShareDO) userShareDO);
        }
    }

    private void validateSelectiveUserShareDO(SelectiveUserShareDO selectiveUserShareDO)
            throws UserSharingMgtClientException {

        // Validate userCriteria is not null.
        validateNotNull(selectiveUserShareDO.getUserCriteria(), ERROR_CODE_USER_CRITERIA_INVALID);

        // Validate that userCriteria contains the required USER_IDS key and is not null.
        if (!selectiveUserShareDO.getUserCriteria().containsKey(USER_IDS) ||
                selectiveUserShareDO.getUserCriteria().get(USER_IDS) == null) {
            throwValidationException(ERROR_CODE_USER_CRITERIA_MISSING);
        }

        // Validate organizations list is not null.
        validateNotNull(selectiveUserShareDO.getOrganizations(), ERROR_CODE_ORGANIZATIONS_NULL);

        // Validate each organization in the list.
        for (SelectiveUserShareOrgDetailsDO orgDetails : selectiveUserShareDO.getOrganizations()) {
            validateNotNull(orgDetails.getOrganizationId(), ERROR_CODE_ORG_ID_NULL);
            validateNotNull(orgDetails.getPolicy(), ERROR_CODE_POLICY_NULL);

            // Validate roles list is not null (it can be empty).
            if (orgDetails.getRoles() == null) {
                throwValidationException(ERROR_CODE_ROLES_NULL);
            } else {
                // Validate each role's properties if present.
                for (RoleWithAudienceDO role : orgDetails.getRoles()) {
                    validateNotNull(role.getRoleName(), ERROR_CODE_ROLE_NAME_NULL);
                    validateNotNull(role.getAudienceName(), ERROR_CODE_AUDIENCE_NAME_NULL);
                    validateNotNull(role.getAudienceType(), ERROR_CODE_AUDIENCE_TYPE_NULL);
                }
            }
        }
    }

    private void validateGeneralUserShareDO(GeneralUserShareDO generalDO) throws UserSharingMgtClientException {

        validateNotNull(generalDO.getUserCriteria(), ERROR_CODE_USER_CRITERIA_INVALID);
        if (!generalDO.getUserCriteria().containsKey(USER_IDS) || generalDO.getUserCriteria().get(USER_IDS) == null) {
            throwValidationException(ERROR_CODE_USER_CRITERIA_MISSING);
        }
        validateNotNull(generalDO.getPolicy(), ERROR_CODE_POLICY_NULL);
        validateNotNull(generalDO.getRoles(), ERROR_CODE_ROLES_NULL);

        // Validate each role's properties if present.
        for (RoleWithAudienceDO role : generalDO.getRoles()) {
            validateNotNull(role.getRoleName(), ERROR_CODE_ROLE_NAME_NULL);
            validateNotNull(role.getAudienceName(), ERROR_CODE_AUDIENCE_NAME_NULL);
            validateNotNull(role.getAudienceType(), ERROR_CODE_AUDIENCE_TYPE_NULL);
        }
    }

    private <T extends UserCriteriaType> void validateUserUnshareInput(BaseUserUnshareDO<T> userUnshareDO)
            throws UserSharingMgtClientException {

        if (userUnshareDO == null) {
            throwValidationException(ERROR_CODE_NULL_UNSHARE);
        }

        if (userUnshareDO instanceof SelectiveUserUnshareDO) {
            validateSelectiveUserUnshareDO((SelectiveUserUnshareDO) userUnshareDO);
        } else if (userUnshareDO instanceof GeneralUserUnshareDO) {
            validateGeneralUserUnshareDO((GeneralUserUnshareDO) userUnshareDO);
        }
    }

    private void validateSelectiveUserUnshareDO(SelectiveUserUnshareDO selectiveUserUnshareDO)
            throws UserSharingMgtClientException {

        // Validate userCriteria is not null.
        validateNotNull(selectiveUserUnshareDO.getUserCriteria(), ERROR_CODE_USER_CRITERIA_INVALID);

        // Validate that userCriteria contains the required USER_IDS key and is not null.
        if (!selectiveUserUnshareDO.getUserCriteria().containsKey(USER_IDS) ||
                selectiveUserUnshareDO.getUserCriteria().get(USER_IDS) == null) {
            throwValidationException(ERROR_CODE_USER_CRITERIA_MISSING);
        }

        // Validate organizations list is not null.
        validateNotNull(selectiveUserUnshareDO.getOrganizations(), ERROR_CODE_ORGANIZATIONS_NULL);

        for (String organization : selectiveUserUnshareDO.getOrganizations()) {
            validateNotNull(organization, ERROR_CODE_ORG_ID_NULL);
        }
    }

    private void validateGeneralUserUnshareDO(GeneralUserUnshareDO generalUserUnshareDO)
            throws UserSharingMgtClientException {

        // Validate userCriteria is not null.
        validateNotNull(generalUserUnshareDO.getUserCriteria(), ERROR_CODE_USER_CRITERIA_INVALID);

        // Validate that userCriteria contains the required USER_IDS key and is not null.
        if (!generalUserUnshareDO.getUserCriteria().containsKey(USER_IDS) ||
                generalUserUnshareDO.getUserCriteria().get(USER_IDS) == null) {
            throwValidationException(ERROR_CODE_USER_CRITERIA_MISSING);
        }
    }

    private void validateNotNull(Object obj, UserSharingConstants.ErrorMessage error)
            throws UserSharingMgtClientException {

        if (obj == null) {
            throwValidationException(error);
        }
    }

    private void throwValidationException(UserSharingConstants.ErrorMessage error)
            throws UserSharingMgtClientException {

        throw new UserSharingMgtClientException(error.getCode(), error.getMessage(), error.getDescription());
    }

    private OrganizationUserSharingService getOrganizationUserSharingService() {

        return OrganizationUserSharingDataHolder.getInstance().getOrganizationUserSharingService();
    }

    private ResourceSharingPolicyHandlerService getResourceSharingPolicyHandlerService() {

        return OrganizationUserSharingDataHolder.getInstance().getResourceSharingPolicyHandlerService();
    }

    private OrganizationManager getOrganizationManager() {

        return OrganizationUserSharingDataHolder.getInstance().getOrganizationManager();
    }

    private RoleManagementService getRoleManagementService() {

        return OrganizationUserSharingDataHolder.getInstance().getRoleManagementService();
    }

    private ApplicationManagementService getApplicationManagementService() {

        return OrganizationUserSharingDataHolder.getInstance().getApplicationManagementService();
    }

    private void startTenantFlowFromOrganization(String sharingInitiatedOrgId) {

        try {
            String sharingInitiatedTenantDomain = getOrganizationManager().resolveTenantDomain(sharingInitiatedOrgId);
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(sharingInitiatedTenantDomain, true);
        } catch (OrganizationManagementException e) {
            LOG.error("Error occurred while starting tenant flow from organization: " + sharingInitiatedOrgId, e);
        }
    }
}
