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

package org.wso2.carbon.identity.organization.management.organization.user.sharing.helper;

import org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.ErrorMessage;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.exception.UserShareMgtServerException;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareGeneralDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareSelectiveDO;

import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.USER_IDS;

import java.util.Map;

public class UserSharingValidationHelper {

    public static void validateInput(Object userShareDO, String context) throws UserShareMgtServerException {
        if (userShareDO == null) {
            throwValidationException(context + " is null", ErrorMessage.ERROR_CODE_NULL_INPUT.getCode(), ErrorMessage.ERROR_CODE_NULL_INPUT.getDescription());
        }

        if (userShareDO instanceof UserShareSelectiveDO) {
            validateSelectiveDO((UserShareSelectiveDO) userShareDO);
        } else if (userShareDO instanceof UserShareGeneralDO) {
            validateGeneralDO((UserShareGeneralDO) userShareDO);
        }
    }

    public static void validateSelectiveDO(UserShareSelectiveDO selectiveDO) throws UserShareMgtServerException {
        validateNotNull(selectiveDO.getUserCriteria(), ErrorMessage.ERROR_CODE_USER_CRITERIA_INVALID.getMessage(), ErrorMessage.ERROR_CODE_USER_CRITERIA_INVALID.getCode());
        if (!selectiveDO.getUserCriteria().containsKey(USER_IDS) || selectiveDO.getUserCriteria().get(USER_IDS) == null) {
            throwValidationException(ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getMessage(), ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getCode(), ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getDescription());
        }
        validateNotNull(selectiveDO.getOrganizations(), ErrorMessage.ERROR_CODE_ORGANIZATIONS_NULL.getMessage(), ErrorMessage.ERROR_CODE_ORGANIZATIONS_NULL.getCode());
    }

    public static void validateGeneralDO(UserShareGeneralDO generalDO) throws UserShareMgtServerException {
        validateNotNull(generalDO.getUserCriteria(), ErrorMessage.ERROR_CODE_USER_CRITERIA_INVALID.getMessage(), ErrorMessage.ERROR_CODE_USER_CRITERIA_INVALID.getCode());
        if (!generalDO.getUserCriteria().containsKey("userIds") || generalDO.getUserCriteria().get("userIds") == null) {
            throwValidationException(ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getMessage(), ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getCode(), ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getDescription());
        }
        validateNotNull(generalDO.getPolicy(), ErrorMessage.ERROR_CODE_POLICY_NULL.getMessage(), ErrorMessage.ERROR_CODE_POLICY_NULL.getCode());
        validateNotNull(generalDO.getRoles(), ErrorMessage.ERROR_CODE_ROLES_NULL.getMessage(), ErrorMessage.ERROR_CODE_ROLES_NULL.getCode());
    }

    public static void validateUserAndOrgDetails(String userId, Map<String, Object> orgDetails) throws UserShareMgtServerException {
        validateUserId(userId);
        validateOrgDetails(orgDetails);
    }

    public static void validateUserId(String userId) throws UserShareMgtServerException {
        validateNotNull(userId, ErrorMessage.ERROR_CODE_USER_ID_NULL.getMessage(), ErrorMessage.ERROR_CODE_USER_ID_NULL.getCode());
    }

    public static void validateOrgDetails(Map<String, Object> orgDetails) throws UserShareMgtServerException {
        validateNotNull(orgDetails, ErrorMessage.ERROR_CODE_ORG_DETAILS_NULL.getMessage(), ErrorMessage.ERROR_CODE_ORG_DETAILS_NULL.getCode());
        validateNotNull(orgDetails.get(UserSharingConstants.ORG_ID), ErrorMessage.ERROR_CODE_ORG_ID_NULL.getMessage(), ErrorMessage.ERROR_CODE_ORG_ID_NULL.getCode());
        validateNotNull(orgDetails.get(UserSharingConstants.POLICY), ErrorMessage.ERROR_CODE_POLICY_NULL.getMessage(), ErrorMessage.ERROR_CODE_POLICY_NULL.getCode());
        validateNotNull(orgDetails.get(UserSharingConstants.ROLES), ErrorMessage.ERROR_CODE_ROLES_NULL.getMessage(), ErrorMessage.ERROR_CODE_ROLES_NULL.getCode());
    }

    private static void validateNotNull(Object obj, String errorMessage, String errorCode) throws UserShareMgtServerException {
        if (obj == null) {
            throwValidationException(errorMessage, errorCode, errorMessage);
        }
    }

    private static void throwValidationException(String message, String errorCode, String description) throws UserShareMgtServerException {
        throw new UserShareMgtServerException(message, new NullPointerException(message), errorCode, description);
    }

}
