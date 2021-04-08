package com.kubehelper.domain.pattern.networking;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class NetworkPolicyRulePattern {
    private List<NetworkPolicyPortPattern> ports = new ArrayList<>();
    private NetworkPolicyPeerPattern selector = new NetworkPolicyPeerPattern();
}
