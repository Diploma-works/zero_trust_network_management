/*
Kube Helper
Copyright (C) 2021 JDev

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package com.kubehelper.domain.results;

import com.kubehelper.common.Resource;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author gulyaev13
 */
public class NetworkPolicyResult {
    private static final Resource resourceType = Resource.NETWORK_POLICY;

    private String resourceName = "";
    private String namespace = "";
    private String creationTime = "";
    private String fullDefinition = "";

    private Map<String, String> annotations = new HashMap<>();
    private Map<String, String> podSelectorLabels = new HashMap<>();

    public String getResourceName() {
        return resourceName;
    }

    public String getNamespace() {
        return namespace;
    }

    public Map<String, String> getAnnotations() {
        return annotations;
    }

    public String getAnnotationsAsString() {
        return annotations.entrySet()
                .stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining(",\n"));
    }

    public Map<String, String> getPodSelectorLabels() {
        return podSelectorLabels;
    }

    public String getPodSelectorLabelsAsString() {
        return podSelectorLabels.entrySet()
                .stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining(",\n"));
    }

    public String getFullDefinition() {
        return fullDefinition;
    }

    public String getCreationTime() {
        return creationTime;
    }

    public Resource getRawResourceType() {
        return resourceType;
    }

    public NetworkPolicyResult setResourceName(String resourceName) {
        this.resourceName = resourceName;
        return this;
    }

    public NetworkPolicyResult setNamespace(String namespace) {
        this.namespace = namespace;
        return this;
    }

    public NetworkPolicyResult setPodSelectorLabels(Map<String, String> podSelectorLabels) {
        this.podSelectorLabels = podSelectorLabels;
        return this;
    }

    public NetworkPolicyResult setAnnotations(Map<String, String> annotations) {
        this.annotations = annotations;
        return this;
    }

    public NetworkPolicyResult setCreationTime(String creationTime) {
        this.creationTime = creationTime;
        return this;
    }

    public NetworkPolicyResult setFullDefinition(String fullDefinition) {
        this.fullDefinition = fullDefinition;
        return this;
    }
}
