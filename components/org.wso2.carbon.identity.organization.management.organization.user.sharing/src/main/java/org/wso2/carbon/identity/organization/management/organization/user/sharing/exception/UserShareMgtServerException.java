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

package org.wso2.carbon.identity.organization.management.organization.user.sharing.exception;

/**
 * Exception class for organization user share management for server exceptions.
 */
public class UserShareMgtServerException extends UserShareMgtException {

    public UserShareMgtServerException(String message, String errorCode, String description) {

        super(message, errorCode, description);
    }

    public UserShareMgtServerException(String errorCode, String description) {

        super(errorCode, description);
    }

    public UserShareMgtServerException(Throwable cause, String errorCode, String description) {

        super(cause, errorCode, description);
    }

    public UserShareMgtServerException(String message, Throwable cause, String errorCode, String description) {

        super(message, cause, errorCode, description);
    }

    public UserShareMgtServerException(String message, Throwable cause, boolean enableSuppression,
                                       boolean writableStackTrace, String errorCode, String description) {

        super(message, cause, enableSuppression, writableStackTrace, errorCode, description);
    }
}
