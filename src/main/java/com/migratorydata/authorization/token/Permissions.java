package com.migratorydata.authorization.token;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.util.HashMap;
import java.util.Map;

import static com.migratorydata.authorization.config.Util.*;
import static com.migratorydata.authorization.token.Permissions.Operation.*;

public class Permissions {
    private Map<String, Operation> permissions = new HashMap<>();

    /*
    Here is an example of the payload of a JWT token:
    {
      "permissions": [
        {
          "s": "/server/status",
          "op": "ps"
        },
        {
          "s": "/demo/notification",
          "op": "s"
        },
        {
          "s": "/sensor/temp",
          "op": "p"
        },
      ]
    }
    */
    public Permissions(JSONArray permissionClaims) throws Exception {
        for (Object permissionClaim : permissionClaims) {
            String subject = (String) ((JSONObject) permissionClaim).get(SUBJECT_FIELD);
            String operation = (String) ((JSONObject) permissionClaim).get(OPERATION_FIELD);

            if (isSubjectValid(subject) && isOperationValid(operation)) {
                this.permissions.put(subject, parseOperation(operation));
            } else {
                throw new Exception("Invalid syntax of permissions");
            }
        }
    }

    private Operation parseOperation(String permission) {
        Operation operation = null;
        if (PUBLISH_SUBSCRIBE.getCode().equals(permission)) {
            operation = Operation.PUBLISH_SUBSCRIBE;
        } else if (SUBSCRIBE.getCode().equals(permission)) {
            operation = Operation.SUBSCRIBE;
        } else if (PUBLISH.getCode().equals(permission)) {
            operation = PUBLISH;
        }
        return operation;
    }

    public Operation getOperation(String subject) {
        return permissions.get(subject);
    }

    public enum Operation {
        SUBSCRIBE("s"), PUBLISH("p"), PUBLISH_SUBSCRIBE("ps");

        private String code;

        Operation(String code) {
            this.code = code;
        }

        public String getCode() {
            return code;
        }
    }
}
