package com.github.klefstad_teaching.cs122b.idm.model.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.github.klefstad_teaching.cs122b.core.base.ResponseModel;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthenticateResponse extends ResponseModel<AuthenticateResponse>
{
}
