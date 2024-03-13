package com.fas.models.utils;

import com.fas.models.enums.Code;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MessageDetails<T> {
    private String message;
    private T data;
    private Code code;
}
