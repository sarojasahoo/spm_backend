package com.spm.portfolio.dto;

import lombok.Builder;
import lombok.ToString;


@ToString
@Builder
public class TokenDto {

    private String access_token;
    private String userId;
}
