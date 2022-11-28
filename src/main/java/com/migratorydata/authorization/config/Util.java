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
          "/server/status"
        ]
      }
    }
    */
    public static final String PERMISSIONS_FIELD = "permissions";
    public static final String SUB_FIELD = "sub";
    public static final String PUB_FIELD = "pub";
    public static final String ALL_FIELD = "all";

    private static final Pattern subjectSyntax = Pattern.compile("[a-zA-Z0-9\\._\\-]+");
    private static int maxSubjectLength = 249;

    /*
    A subject is valid if it is a string of UTF-8 characters that respects a syntax similar to the Unix absolute paths,
    consisting of an initial slash (/) character followed by two or more character strings, called segments, separated
    by the single slash (/) character. Within a segment, the slash (/) character is reserved. Each subject must have two
    or more segments. Example of valid subject: /car45/sensor/temp
     */
    public static boolean isSubjectValid(String subject) {
        String sbj = subject;
        int index = subject.indexOf("/", 1);
        if (index != -1) {
            sbj = subject.substring(1, index);
        } else if (subject.length() > 1) {
            sbj = subject.substring(1);
        }
        if (sbj.length() < 0) {
            return false;
        } else if (sbj.equals(".") || sbj.equals("..")) {
            return false;
        } else if (sbj.length() > maxSubjectLength) {
            return false;
        }
        return subjectSyntax.matcher(sbj).matches();
    }
}
