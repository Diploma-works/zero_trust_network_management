package com.kubehelper.domain.pattern.networking;

import lombok.Data;

@Data
public class IPBlockPattern {
    private String cidr;
    private String except;
}
