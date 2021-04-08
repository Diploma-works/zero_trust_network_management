package com.kubehelper.domain.pattern.networking;

import lombok.Data;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Data
public class NetworkPolicyPattern {
    private String name = "";
    private String namespace = "";
    private String description;
    private String type = "Ingress";

    private Map<String, String> podSelectorLabels = new HashMap<>();
    private String podSelectorLabelsString;

    private String port;
    private String protocol;

    private String cidr;
    private String except;

    private String ruleNamespace;
    private String rulePodSelectorLabels;

    // ingress or egress
    private NetworkPolicyRulePattern rule = new NetworkPolicyRulePattern();

    public void parse() {
        podSelectorLabels = mapFromLabelsString(podSelectorLabelsString);
        if((port != null && !port.isEmpty()) || (protocol != null && !protocol.isEmpty())) {
            rule.setPorts(
                    Collections.singletonList(
                            new NetworkPolicyPortPattern(port == null ? null : Integer.parseInt(port), protocol)));
        }

        if(rulePodSelectorLabels != null && !rulePodSelectorLabels.isEmpty()) {
            rule.getSelector().setPodSelectorLabels(mapFromLabelsString(rulePodSelectorLabels));
        }

        if(cidr != null && !cidr.isEmpty()) {
            IPBlockPattern ipBlockPattern = new IPBlockPattern();
            ipBlockPattern.setCidr(cidr);
            ipBlockPattern.setExcept((except != null && !except.isEmpty()) ? except : null);
            rule.getSelector().setIpBlock(ipBlockPattern);
        }

        if(ruleNamespace != null && !ruleNamespace.isEmpty()) {
            rule.getSelector().setNamespaceName(ruleNamespace);
        }
    }

    private static Map<String, String> mapFromLabelsString(String mapAsString) {
        return Arrays.stream(mapAsString.split(","))
                .map(entry -> entry.split("=", 2))
                .collect(Collectors.toMap(entry -> entry[0], entry -> entry[1]));
    }
}
