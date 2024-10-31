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
import org.wso2.carbon.identity.organization.management.organization.user.sharing.exception.UserShareMgtServerException;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.helper.UserSharingValidationHelper;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareGeneral;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareGeneralDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareSelective;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareSelectiveDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserUnshareGeneralDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserUnshareSelectiveDO;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.LOG_INFO_GENERAL_SHARE_COMPLETED;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.LOG_INFO_SELECTIVE_SHARE_COMPLETED;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.NULL_POLICY;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ORG_ID;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.POLICY;
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

    /**
     * Propagates the selective share of a user to specific organizations.
     *
     * @param userShareSelectiveDO Contains details for selective sharing.
     */
    @Override
    public void propagateSelectiveShare(UserShareSelectiveDO userShareSelectiveDO) throws UserShareMgtServerException {

        UserSharingValidationHelper.validateInput(userShareSelectiveDO, VALIDATION_CONTEXT_USER_SHARE_SELECTIVE_DO);

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

        UserSharingValidationHelper.validateInput(userShareGeneralDO, VALIDATION_CONTEXT_USER_SHARE_GENERAL_DO);

        for (String userId : userShareGeneralDO.getUserCriteria().get(USER_IDS)) {
            propagateGeneralShareForUser(userId, userShareGeneralDO.getPolicy(),
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

    //TODO: set Enums for policy?

    private void propagateSelectiveShareForUser(String userId, List<Map<String, Object>> organizations)
            throws UserShareMgtServerException {

        for (Map<String, Object> orgDetails : organizations) {
            UserShareSelective userShareSelective = createUserShareSelective(userId, orgDetails);
            shareUserWithOrganization(userShareSelective);
        }
    }

    private void propagateGeneralShareForUser(String userId, String policy, List<String> roleIds) {

        UserShareGeneral userShareGeneral = createUserShareGeneral(userId, policy, roleIds);
        shareUserWithAllOrganizations(userShareGeneral);
    }

    private UserShareSelective createUserShareSelective(String userId, Map<String, Object> orgDetails)
            throws UserShareMgtServerException {

        UserSharingValidationHelper.validateUserAndOrgDetails(userId, orgDetails);

        UserShareSelective userShareSelective = new UserShareSelective();
        userShareSelective.setUserId(userId);
        userShareSelective.setOrganizationId((String) orgDetails.get(ORG_ID));

        setPolicyIfPresent(orgDetails, userShareSelective);
        setRolesIfPresent(orgDetails, userShareSelective);

        return userShareSelective;
    }

    private UserShareGeneral createUserShareGeneral(String userId, String policy, List<String> roleIds) {

        UserShareGeneral userShareGeneral = new UserShareGeneral();
        userShareGeneral.setUserId(userId);
        userShareGeneral.setPolicy(policy);
        userShareGeneral.setRoles(roleIds);
        return userShareGeneral;
    }

    private void setPolicyIfPresent(Map<String, Object> orgDetails, UserShareSelective userShareSelective)
            throws UserShareMgtServerException {

        String policy = (String) orgDetails.get(POLICY);
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

    /**
     * Handles storing or processing the user-organization share.
     *
     * @param userShareSelective Contains details for sharing a user with an organization.
     */
    private void shareUserWithOrganization(UserShareSelective userShareSelective) {

        // In this method we create an UserAssociation model and share the user
        // We do the role assign here as well
    }

    /**
     * Handles storing or processing the general user share.
     *
     * @param userShareGeneral Contains details for sharing a user with all organizations.
     */
    private void shareUserWithAllOrganizations(UserShareGeneral userShareGeneral) {

        // We get all orgs under the policy given by userShareGeneral.
        // We can use private List<String> getOrganizationsBasedOnPolicy(String policy) for that
        // Then we iterate through those orgs and create an UserAssociation model and share the user
        // Then inside that loop, we do the role assign for each inside that
    }

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
