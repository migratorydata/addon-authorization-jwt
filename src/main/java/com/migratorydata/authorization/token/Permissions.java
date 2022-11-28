package com.migratorydata.authorization.token;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.migratorydata.authorization.config.Util.*;

public class Permissions {
    private final Map<String, Permission> permissions = new HashMap<>();

    /*
    Here is an example of the payload of a JWT token:
    {
    "permissions": {
        "sub": [
          "/demo/notification"
        ],
        "pub": [
          "/sensor/temp"
        ],
        "all": [
          "/server/status"
        ]
      }
    }
    */
    public Permissions(Map<String, List<String>> permissionClaims) throws Exception {
        for (Map.Entry<String, List<String>> entry : permissionClaims.entrySet()) {
            for (String subject : entry.getValue()) {
                Permission permission = Permission.getPermission(entry.getKey());
                if (isSubjectValid(subject) && permission != null) {
                    putPermission(subject, permission);
                } else {
                    throw new Exception("Invalid syntax for subject " + subject + ", or permission " + entry.getKey());
                }
            }
        }
    }

    private void putPermission(String subject, Permission permission) {
        if (permissions.containsKey(subject) && permissions.get(subject) != permission) {
            permissions.put(subject, Permission.ALL);
        } else {
            permissions.put(subject, permission);
        }
    }

    public Permission getPermission(String subject) {
        return permissions.get(subject);
    }

    public enum Permission {
        SUB("sub"), PUB("pub"), ALL("all");

        private String code;

        Permission(String code) {
            this.code = code;
        }

        public String getCode() {
            return code;
        }

        public static Permission getPermission(String code) {
            Permission Permission = null;
            if (PUB.getCode().equals(code)) {
                Permission = PUB;
            } else if (SUB.getCode().equals(code)) {
                Permission = SUB;
            } else if (ALL.getCode().equals(code)) {
                Permission = ALL;
            }
            return Permission;
        }
    }
}
