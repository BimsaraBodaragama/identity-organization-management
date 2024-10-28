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
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareGeneralDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserShareSelectiveDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserUnshareGeneralDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.UserUnshareSelectiveDO;

/**
 * Service implementation for handling user sharing policies.
 */
public class UserSharingPolicyHandlerServiceImpl implements UserSharingPolicyHandlerService {

    private static final Log LOG = LogFactory.getLog(UserSharingPolicyHandlerServiceImpl.class);

    @Override
    public void propagateSelectiveShare(UserShareSelectiveDO userShareSelectiveDO) {

        LOG.info("Came in to propagateSelectiveShare");

        validateUserShareSelectiveDO(userShareSelectiveDO);
        //Create a shared user object for the given org - use current user association method ?What's this domain story?
        //Then assign each role - use current role assignment method
        //    - get the role id from the given (role name + audience name + audience type)
        //Then check the policy
        //    - If policy comes with a code type for future create a UserSharingPolicyRecord and save to DB

        //?? do we have to validate the data on the payload by checking if the user exists in the db by sending a
        // db call and check the roles in the db  and check if the policy is a valid policy??

        LOG.info("Went out from propagateSelectiveShare");

    }

    private void validateUserShareSelectiveDO(UserShareSelectiveDO userShareSelectiveDO) {
        //TODO:
        //  1. validate if the user is in db
        //  2. validate if the org is in db --not priority
        //  3. validate if the policy is in ENUM
        //  4. validate each roles are in db --not priority
        //  5. validate if roles have any conflicts with the roles in the given org

    }

    @Override
    public void propagateGeneralShare(UserShareGeneralDO userShareGeneralDO) {

    }

    @Override
    public void propagateSelectiveUnshare(UserUnshareSelectiveDO userUnshareSelectiveDO) {

    }

    @Override
    public void propagateGeneralUnshare(UserUnshareGeneralDO userUnshareGeneralDO) {

    }
}
