package org.wso2.carbon.identity.organization.management.organization.user.sharing;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.GeneralUserShareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.GeneralUserUnshareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.SelectiveUserShareDO;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.models.SelectiveUserUnshareDO;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.ResourceSharingPolicyHandlerService;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.ResourceSharingPolicyHandlerServiceImpl;

import java.util.concurrent.ConcurrentLinkedQueue;

public class UserSharingPolicyHandlerServiceImpl implements UserSharingPolicyHandlerService {

    private static final Log LOG = LogFactory.getLog(UserSharingPolicyHandlerServiceImpl.class);
//    private static final ResourceSharingPolicyHandlerService resourceSharingPolicyHandlerService =
//            new ResourceSharingPolicyHandlerServiceImpl();
    private static ConcurrentLinkedQueue<String> errorMessages;

    @Override
    public void populateSelectiveUserShare(SelectiveUserShareDO selectiveUserShareDO) {

        LOG.info("Came in user selective share");
    }

    @Override
    public void populateGeneralUserShare(GeneralUserShareDO generalUserShareDO) {

        LOG.info("Came in user general share");
    }

    @Override
    public void populateSelectiveUserUnshare(SelectiveUserUnshareDO selectiveUserUnshareDO) {

        LOG.info("Came in user selective unshare");
    }

    @Override
    public void populateGeneralUserUnshare(GeneralUserUnshareDO generalUserUnshareDO) {

        LOG.info("Came in user general unshare");
    }
}
