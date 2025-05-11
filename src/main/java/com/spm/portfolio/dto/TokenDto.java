package com.spm.portfolio.dto;

import lombok.Builder;
import lombok.Data;
import lombok.ToString;


@ToString
@Builder
@Data
public class TokenDto {

    private String userId;
    private String userName;
}
