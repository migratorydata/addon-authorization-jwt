package com.migratorydata.authorization.config;

import java.util.regex.Pattern;

public class Util {
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
    public static final String PERMISSIONS_FIELD = "permissions";
    public static final String SUBJECT_FIELD = "s";
    public static final String OPERATION_FIELD = "op";

    public static final String SUBSCRIBE_PERMISSION = "s";
    public static final String PUBLISH_PERMISSION = "p";
    public static final String PUBLISH_SUBSCRIBE_PERMISSION = "ps";

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

    /*
    Currently, the permitted operations concerning a subject are: subscribe, publish, or both publish and subscribe.
     */
    public static boolean isOperationValid(String operation) {
        return (SUBSCRIBE_PERMISSION.equals(operation) ||
                PUBLISH_PERMISSION.equals(operation) ||
                PUBLISH_SUBSCRIBE_PERMISSION.equals(operation));
    }
}
