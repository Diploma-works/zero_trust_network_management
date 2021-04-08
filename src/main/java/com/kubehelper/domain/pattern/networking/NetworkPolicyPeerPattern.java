package com.kubehelper.domain.pattern.networking;

import lombok.Data;

import java.util.Map;

@Data
public class NetworkPolicyPeerPattern {
    private IPBlockPattern ipBlock;
    private String namespaceName;
    private Map<String, String> podSelectorLabels;

    private String podSelectorLabelsString;
}
