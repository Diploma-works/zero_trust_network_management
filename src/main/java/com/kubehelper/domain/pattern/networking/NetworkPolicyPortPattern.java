package com.kubehelper.domain.pattern.networking;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class NetworkPolicyPortPattern {
    private Integer port;
    private String protocol;
}
