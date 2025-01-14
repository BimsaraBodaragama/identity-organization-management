package org.wso2.carbon.identity.organization.management.organization.user.sharing;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.exception.UserShareMgtClientException;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.exception.UserShareMgtException;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.exception.UserShareMgtServerException;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.BaseUserShareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.BaseUserUnshareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.GeneralUserShareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.GeneralUserUnshareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.RoleWithAudienceDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.SelectiveUserShareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.SelectiveUserShareOrgDetailsDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.dos.SelectiveUserUnshareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.usercriteria.UserCriteriaType;

import java.util.concurrent.ConcurrentLinkedQueue;

import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.NULL_SHARE_INPUT_MESSAGE;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.NULL_UNSHARE_INPUT_MESSAGE;
import static org.wso2.carbon.identity.organization.management.organization.user.sharing.constant.UserSharingConstants.USER_IDS;

public class UserSharingPolicyHandlerServiceImpl implements UserSharingPolicyHandlerService {

    private static final Log LOG = LogFactory.getLog(UserSharingPolicyHandlerServiceImpl.class);
    private static ConcurrentLinkedQueue<String> errorMessages;

    @Override
    public void populateSelectiveUserShare(SelectiveUserShareDO selectiveUserShareDO) throws UserShareMgtException {

        LOG.debug("Came in user selective share");
        validateUserShareInput(selectiveUserShareDO);
        LOG.debug("Validated user selective share input");
    }

    @Override
    public void populateGeneralUserShare(GeneralUserShareDO generalUserShareDO) throws UserShareMgtException {

        LOG.debug("Came in user general share");
        validateUserShareInput(generalUserShareDO);
        LOG.debug("Validated user general share input");
    }

    @Override
    public void populateSelectiveUserUnshare(SelectiveUserUnshareDO selectiveUserUnshareDO)
            throws UserShareMgtException {

        LOG.debug("Came in user selective unshare");
        validateUserUnshareInput(selectiveUserUnshareDO);
        LOG.debug("Validated user selective unshare input");
    }

    @Override
    public void populateGeneralUserUnshare(GeneralUserUnshareDO generalUserUnshareDO) throws UserShareMgtException {

        LOG.debug("Came in user general unshare");
        validateUserUnshareInput(generalUserUnshareDO);
        LOG.debug("Validated user general unshare input");
    }

    //Validation methods

    private <T extends UserCriteriaType> void validateUserShareInput(BaseUserShareDO<T> userShareDO)
            throws UserShareMgtClientException {

        if (userShareDO == null) {
            throwValidationException(NULL_SHARE_INPUT_MESSAGE,
                    UserSharingConstants.ErrorMessage.ERROR_CODE_NULL_INPUT.getCode(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_NULL_INPUT.getDescription());
        }

        if (userShareDO instanceof SelectiveUserShareDO) {
            validateSelectiveUserShareDO((SelectiveUserShareDO) userShareDO);
        } else if (userShareDO instanceof GeneralUserShareDO) {
            validateGeneralUserShareDO((GeneralUserShareDO) userShareDO);
        }
    }

    private void validateSelectiveUserShareDO(SelectiveUserShareDO selectiveUserShareDO)
            throws UserShareMgtClientException {

        // Validate userCriteria is not null
        validateNotNull(selectiveUserShareDO.getUserCriteria(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_INVALID.getMessage(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_INVALID.getCode());

        // Validate that userCriteria contains the required USER_IDS key and is not null
        if (!selectiveUserShareDO.getUserCriteria().containsKey(USER_IDS) ||
                selectiveUserShareDO.getUserCriteria().get(USER_IDS) == null) {
            throwValidationException(UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getMessage(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getCode(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getDescription());
        }

        // Validate organizations list is not null
        validateNotNull(selectiveUserShareDO.getOrganizations(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_ORGANIZATIONS_NULL.getMessage(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_ORGANIZATIONS_NULL.getCode());

        // Validate each organization in the list
        for (SelectiveUserShareOrgDetailsDO orgDetails : selectiveUserShareDO.getOrganizations()) {
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

    private void validateGeneralUserShareDO(GeneralUserShareDO generalDO) throws UserShareMgtClientException {

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

    private <T extends UserCriteriaType> void validateUserUnshareInput(BaseUserUnshareDO<T> userUnshareDO)
            throws UserShareMgtClientException {

        if (userUnshareDO == null) {
            throwValidationException(NULL_UNSHARE_INPUT_MESSAGE,
                    UserSharingConstants.ErrorMessage.ERROR_CODE_NULL_INPUT.getCode(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_NULL_INPUT.getDescription());
        }

        if (userUnshareDO instanceof SelectiveUserUnshareDO) {
            validateSelectiveUserUnshareDO((SelectiveUserUnshareDO) userUnshareDO);
        } else if (userUnshareDO instanceof GeneralUserUnshareDO) {
            validateGeneralUserUnshareDO((GeneralUserUnshareDO) userUnshareDO);
        }
    }

    private void validateSelectiveUserUnshareDO(SelectiveUserUnshareDO selectiveUserUnshareDO)
            throws UserShareMgtClientException {

        // Validate userCriteria is not null
        validateNotNull(selectiveUserUnshareDO.getUserCriteria(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_INVALID.getMessage(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_INVALID.getCode());

        // Validate that userCriteria contains the required USER_IDS key and is not null
        if (!selectiveUserUnshareDO.getUserCriteria().containsKey(USER_IDS) ||
                selectiveUserUnshareDO.getUserCriteria().get(USER_IDS) == null) {
            throwValidationException(UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getMessage(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getCode(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getDescription());
        }

        // Validate organizations list is not null
        validateNotNull(selectiveUserUnshareDO.getOrganizations(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_ORGANIZATIONS_NULL.getMessage(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_ORGANIZATIONS_NULL.getCode());

        for (String organization : selectiveUserUnshareDO.getOrganizations()) {
            validateNotNull(organization,
                    UserSharingConstants.ErrorMessage.ERROR_CODE_ORG_ID_NULL.getMessage(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_ORG_ID_NULL.getCode());
        }
    }

    private void validateGeneralUserUnshareDO(GeneralUserUnshareDO generalUserUnshareDO)
            throws UserShareMgtClientException {

        // Validate userCriteria is not null
        validateNotNull(generalUserUnshareDO.getUserCriteria(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_INVALID.getMessage(),
                UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_INVALID.getCode());

        // Validate that userCriteria contains the required USER_IDS key and is not null
        if (!generalUserUnshareDO.getUserCriteria().containsKey(USER_IDS) ||
                generalUserUnshareDO.getUserCriteria().get(USER_IDS) == null) {
            throwValidationException(UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getMessage(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getCode(),
                    UserSharingConstants.ErrorMessage.ERROR_CODE_USER_CRITERIA_MISSING.getDescription());
        }
    }

    private void validateNotNull(Object obj, String errorMessage, String errorCode)
            throws UserShareMgtClientException {

        if (obj == null) {
            throwValidationException(errorMessage, errorCode, errorMessage);
        }
    }

    private void throwValidationException(String message, String errorCode, String description)
            throws UserShareMgtClientException {

        throw new UserShareMgtClientException(message, new NullPointerException(message), errorCode, description);
    }
}
