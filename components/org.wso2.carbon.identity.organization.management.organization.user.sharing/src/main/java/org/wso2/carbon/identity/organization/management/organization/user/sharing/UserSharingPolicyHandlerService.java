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

import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.exception.UserShareMgtException;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.GeneralUserShareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.GeneralUserUnshareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.SelectiveUserShareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.SelectiveUserUnshareDO;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.exception.ResourceSharingPolicyMgtException;
import org.wso2.carbon.identity.role.v2.mgt.core.exception.IdentityRoleManagementException;
import org.wso2.carbon.user.api.UserStoreException;

/**
 * Service that manages the user sharing policy handler.
 */
public interface UserSharingPolicyHandlerService {

    void populateSelectiveUserShare(SelectiveUserShareDO selectiveUserShareDO);

    void populateGeneralUserShare(GeneralUserShareDO generalUserShareDO);

    void populateSelectiveUserUnshare(SelectiveUserUnshareDO selectiveUserUnshareDO);

    void populateGeneralUserUnshare(GeneralUserUnshareDO generalUserUnshareDO);

}
