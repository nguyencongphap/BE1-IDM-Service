package com.github.klefstad_teaching.cs122b.idm.util;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
public final class Validate
{
    public void validatePassword(char[] pw) {
        if (pw == null) {
            throw new ResultError(IDMResults.PASSWORD_DOES_NOT_MEET_LENGTH_REQUIREMENTS);
        }

        if (pw.length < 10 || pw.length > 20) {
            throw new ResultError(IDMResults.PASSWORD_DOES_NOT_MEET_LENGTH_REQUIREMENTS);
        }

        // validate Password Characters
        String pwString = new String(pw);

        String regexOneUpperCase = "[A-Z]";
        String regexOneLowerCase = "[a-z]";
        String regexOneNumeric = "[0-9]";

        boolean hasOneUpperCase = Pattern.compile(regexOneUpperCase).matcher(pwString).find();
        boolean hasOneLowerCase = Pattern.compile(regexOneLowerCase).matcher(pwString).find();
        boolean hasOneNumeric = Pattern.compile(regexOneNumeric).matcher(pwString).find();

        if (!(hasOneUpperCase && hasOneLowerCase && hasOneNumeric)) {
            throw new ResultError(IDMResults.PASSWORD_DOES_NOT_MEET_CHARACTER_REQUIREMENT);
        }
    }

    public void validateEmail(String email) {
        if (email == null) {
            throw new ResultError(IDMResults.EMAIL_ADDRESS_HAS_INVALID_FORMAT);
        }

        if (email.length() < 6 || email.length() > 32) {
            throw new ResultError(IDMResults.EMAIL_ADDRESS_HAS_INVALID_LENGTH);
        }

        String regexEmailForm = "^[a-zA-Z0-9]+@[a-zA-Z0-9]+.[a-zA-Z0-9]+$";

        if (!Pattern.compile(regexEmailForm).matcher(email).find()) {
            throw new ResultError(IDMResults.EMAIL_ADDRESS_HAS_INVALID_FORMAT);
        }
    }
}
