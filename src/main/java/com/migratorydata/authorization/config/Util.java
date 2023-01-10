package com.migratorydata.authorization.config;

import java.util.regex.Pattern;

public class Util {
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
          "/server/status",
          "/sensors/*"
        ]
      }
    }
    */
    public static final String PERMISSIONS_FIELD = "permissions";
    public static final String SUB_FIELD = "sub";
    public static final String PUB_FIELD = "pub";
    public static final String ALL_FIELD = "all";


    private static final Pattern subjectSyntax = Pattern.compile("^\\/([^\\/]+\\/)*([^\\/]+|\\*)$");

    public static boolean isSubjectValid(String subject) {
        String sbj = subject;
        int index = subject.indexOf("/", 1);
        if (index == -1) {
            sbj = subject.substring(1);
            if ("*".equals(sbj)) {
                return true;
            }
        }

        return subjectSyntax.matcher(sbj).matches();
    }
}
