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
package com.kubehelper.services;

import com.kubehelper.common.KubeAPI;
import com.kubehelper.common.Resource;
import com.kubehelper.domain.models.SecurityModel;
import com.kubehelper.domain.pattern.networking.NetworkPolicyPattern;
import com.kubehelper.domain.pattern.networking.NetworkPolicyPeerPattern;
import com.kubehelper.domain.pattern.networking.NetworkPolicyPortPattern;
import com.kubehelper.domain.results.ContainerSecurityResult;
import com.kubehelper.domain.results.NetworkPolicyResult;
import com.kubehelper.domain.results.PodSecurityContextResult;
import com.kubehelper.domain.results.PodSecurityPoliciesResult;
import com.kubehelper.domain.results.RBACResult;
import com.kubehelper.domain.results.RoleResult;
import com.kubehelper.domain.results.RoleRuleResult;
import com.kubehelper.domain.results.ServiceAccountResult;
import io.fabric8.kubernetes.api.model.IntOrString;
import io.fabric8.kubernetes.api.model.LabelSelector;
import io.fabric8.kubernetes.api.model.LabelSelectorRequirement;
import io.fabric8.kubernetes.api.model.networking.v1.IPBlock;
import io.fabric8.kubernetes.api.model.networking.v1.NetworkPolicy;
import io.fabric8.kubernetes.api.model.networking.v1.NetworkPolicyBuilder;
import io.fabric8.kubernetes.api.model.networking.v1.NetworkPolicyFluent.SpecNested;
import io.fabric8.kubernetes.api.model.networking.v1.NetworkPolicyPeer;
import io.fabric8.kubernetes.api.model.networking.v1.NetworkPolicyPort;
import io.fabric8.kubernetes.api.model.networking.v1.NetworkPolicySpecFluent.EgressNested;
import io.fabric8.kubernetes.api.model.networking.v1.NetworkPolicySpecFluent.IngressNested;
import io.fabric8.kubernetes.api.model.rbac.ClusterRoleBinding;
import io.fabric8.kubernetes.api.model.rbac.RoleBinding;
import io.fabric8.kubernetes.api.model.rbac.Subject;
import io.fabric8.kubernetes.client.DefaultKubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.kubernetes.client.openapi.models.V1Container;
import io.kubernetes.client.openapi.models.V1NetworkPolicy;
import io.kubernetes.client.openapi.models.V1NetworkPolicyList;
import io.kubernetes.client.openapi.models.V1NetworkPolicySpec;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1ObjectReference;
import io.kubernetes.client.openapi.models.V1Pod;
import io.kubernetes.client.openapi.models.V1PodList;
import io.kubernetes.client.openapi.models.V1PodSecurityContext;
import io.kubernetes.client.openapi.models.V1SecurityContext;
import io.kubernetes.client.openapi.models.V1ServiceAccount;
import io.kubernetes.client.openapi.models.V1ServiceAccountList;
import io.kubernetes.client.openapi.models.V1beta1ClusterRole;
import io.kubernetes.client.openapi.models.V1beta1ClusterRoleBinding;
import io.kubernetes.client.openapi.models.V1beta1ClusterRoleBindingList;
import io.kubernetes.client.openapi.models.V1beta1ClusterRoleList;
import io.kubernetes.client.openapi.models.V1beta1PodSecurityPolicy;
import io.kubernetes.client.openapi.models.V1beta1PodSecurityPolicyList;
import io.kubernetes.client.openapi.models.V1beta1PodSecurityPolicySpec;
import io.kubernetes.client.openapi.models.V1beta1PolicyRule;
import io.kubernetes.client.openapi.models.V1beta1Role;
import io.kubernetes.client.openapi.models.V1beta1RoleBinding;
import io.kubernetes.client.openapi.models.V1beta1RoleBindingList;
import io.kubernetes.client.openapi.models.V1beta1RoleList;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.kubehelper.common.Resource.CLUSTER_ROLE;
import static com.kubehelper.common.Resource.ROLE;

/**
 * Security service.
 *
 * @author JDev
 */
@Service
public class SecurityService {

    private static Logger logger = LoggerFactory.getLogger(SecurityService.class);

    @Autowired
    private KubeAPI kubeAPI;

    private KubernetesClient fabricClient = new DefaultKubernetesClient();

    public void getRoles(SecurityModel model) {
        model.getRolesResults().clear();
        model.getSearchExceptions().clear();
        searchInClusterRoles(model);
        searchInRoles(model);
        searchInClusterRoleBindings(model);
        searchInRoleBindings(model);
    }

    public void getRBACs(SecurityModel model) {
        model.getRbacsResults().clear();
        model.getSearchExceptions().clear();
        searchForRBACsInRoles(model);
        if ("all".equals(model.getSelectedRBACsNamespace())) {
            searchForRBACsInClusterRoles(model);
        }
    }

    public void getPodsSecurityContexts(SecurityModel model) {
        model.getPodsSecurityContextsResults().clear();
        model.getSearchExceptions().clear();
        searchInPodSecurityContexts(model);
    }

    public void getContainersSecurityContexts(SecurityModel model) {
        model.getContainersSecurityResults().clear();
        model.getSearchExceptions().clear();
        searchInContainersSecurityContexts(model);
    }

    public void getPodsSecurityPolicies(SecurityModel model) {
        model.getPodSecurityPoliciesResults().clear();
        model.getSearchExceptions().clear();
        searchInPodSecurityPolicies(model);
    }

    public void getServiceAccounts(SecurityModel model) {
        model.getServiceAccountsResults().clear();
        model.getSearchExceptions().clear();
        searchInServiceAccounts(model);
    }

    public void getNetworkPolicies(SecurityModel model) {
        model.getNetworkPolicyResults().clear();
        model.getSearchExceptions().clear();
        searchInNetworkPolicies(model);
    }


    // RBAC =============


    private void searchForRBACsInClusterRoles(SecurityModel model) {
        try {
            V1beta1ClusterRoleList rolesList = kubeAPI.getV1ClusterRolesList(model);
            for (V1beta1ClusterRole role : rolesList.getItems()) {
                Optional<ClusterRoleBinding> roleBinding =
                        fabricClient.rbac().clusterRoleBindings().list().getItems().stream().filter(crb -> role.getMetadata().getName().equals(crb.getMetadata().getName())).findFirst();
                if (roleBinding.isPresent() && Objects.nonNull(roleBinding.get().getSubjects())) {
                    buildRoleAndRoleBindingWithSubjects(role.getRules(), roleBinding.get().getSubjects(), role.getMetadata(), model, CLUSTER_ROLE);
                } else {
                    buildRoleAndRoleBindingWithoutSubjects(role.getRules(), role.getMetadata(), model, CLUSTER_ROLE);
                }
            }
        } catch (RuntimeException e) {
            model.addSearchException(e);
            logger.error(e.getMessage(), e);
        }
    }

    private void searchForRBACsInRoles(SecurityModel model) {
        try {
            V1beta1RoleList rolesList = kubeAPI.getV1RolesList(model.getSelectedRBACsNamespace(), model);
            for (V1beta1Role role : rolesList.getItems()) {
                String namespace = role.getMetadata().getNamespace() == null ? "default" : role.getMetadata().getNamespace();
                Optional<RoleBinding> roleBinding =
                        fabricClient.rbac().roleBindings().inNamespace(namespace).list().getItems().stream().filter(crb -> role.getMetadata().getName().equals(crb.getMetadata().getName())).findFirst();
                if (roleBinding.isPresent() && Objects.nonNull(roleBinding.get().getSubjects())) {
                    buildRoleAndRoleBindingWithSubjects(role.getRules(), roleBinding.get().getSubjects(), role.getMetadata(), model, ROLE);
                } else {
                    buildRoleAndRoleBindingWithoutSubjects(role.getRules(), role.getMetadata(), model, ROLE);
                }
            }
        } catch (RuntimeException e) {
            model.addSearchException(e);
            logger.error(e.getMessage(), e);
        }
    }

    private void buildRoleAndRoleBindingWithSubjects(List<V1beta1PolicyRule> rules, List<Subject> subjects, V1ObjectMeta roleMeta, SecurityModel model, Resource role) {
        subjects.forEach(subject -> rules.forEach(rule -> {
            if (Optional.ofNullable(rule.getResources()).isPresent()) {
                rule.getResources().forEach(resource -> {
                    rule.getVerbs().forEach(verb -> {
                        buildRBACResultWithSubject(model, roleMeta, subject, resource, verb, role);
                    });
                });
            }
        }));
    }

    private void buildRoleAndRoleBindingWithoutSubjects(List<V1beta1PolicyRule> rules, V1ObjectMeta roleMeta, SecurityModel model, Resource role) {
        rules.forEach(rule -> {
            if (Optional.ofNullable(rule.getResources()).isPresent()) {
                rule.getResources().forEach(resource -> rule.getVerbs().forEach(verb -> {
                    buildRBACResultWithoutSubject(model, roleMeta, resource, verb, role);
                }));
            }
        });
    }

    private void buildRBACResultWithSubject(SecurityModel model, V1ObjectMeta roleMeta, Subject subject, String resource, String verb, Resource role) {
        if (skipKubeNamespace(model, subject.getNamespace())) {
            return;
        }
        RBACResult rbacResult = new RBACResult(model.getRbacsResults().size() + 1)
                .setResourceName(resource)
                .setSubjectKind(subject.getKind())
                .setSubjectName(subject.getName())
                .setRoleName(roleMeta.getName())
                .setResourceType(role)
                .setNamespace(Objects.isNull(subject.getNamespace()) ? "N/A" : subject.getNamespace())
                .setApiGroup(Objects.isNull(subject.getApiGroup()) ? "" : subject.getApiGroup())
                .setVerb(verb);
        model.addRBACResult(rbacResult);
    }

    private void buildRBACResultWithoutSubject(SecurityModel model, V1ObjectMeta roleMeta, String resource, String verb, Resource role) {
        if (skipKubeNamespace(model, roleMeta.getNamespace())) {
            return;
        }
        RBACResult rbacResult = new RBACResult(model.getRbacsResults().size() + 1)
                .setResourceName(resource)
                .setSubjectKind("N/A")
                .setSubjectName("N/A")
                .setRoleName(roleMeta.getName())
                .setResourceType(role)
                .setNamespace(roleMeta.getNamespace() == null ? "N/A" : roleMeta.getNamespace())
                .setApiGroup("")
                .setVerb(verb);
        model.addRBACResult(rbacResult);
    }


    // ROLES =============


    private void searchInClusterRoles(SecurityModel model) {
        V1beta1ClusterRoleList clusterRolesList = kubeAPI.getV1ClusterRolesList(model);
        for (V1beta1ClusterRole clusterRole : clusterRolesList.getItems()) {
            try {
                addRoleResultToModel(clusterRole.getMetadata(), model, CLUSTER_ROLE, clusterRole.toString(), clusterRole.getRules());
            } catch (RuntimeException e) {
                model.addSearchException(e);
                logger.error(e.getMessage(), e);
            }
        }
    }


    private void searchInRoles(SecurityModel model) {
        V1beta1RoleList rolesList = kubeAPI.getV1RolesList(model.getSelectedRolesNamespace(), model);
        for (V1beta1Role role : rolesList.getItems()) {
            try {
                addRoleResultToModel(role.getMetadata(), model, ROLE, role.toString(), role.getRules());
            } catch (RuntimeException e) {
                model.addSearchException(e);
                logger.error(e.getMessage(), e);
            }
        }
    }

    private void searchInClusterRoleBindings(SecurityModel model) {
        V1beta1ClusterRoleBindingList clusterRoleBindingsList = kubeAPI.getV1ClusterRolesBindingsList(model);
        for (V1beta1ClusterRoleBinding binding : clusterRoleBindingsList.getItems()) {
            try {
                model.addRoleSubjects(binding.getRoleRef().getName(), CLUSTER_ROLE, binding.getSubjects());
            } catch (RuntimeException e) {
                model.addSearchException(e);
                logger.error(e.getMessage(), e);
            }
        }
    }

    private void searchInRoleBindings(SecurityModel model) {
        V1beta1RoleBindingList rolesBindingsList = kubeAPI.getV1RolesBindingList(model.getSelectedRolesNamespace(), model);
        for (V1beta1RoleBinding roleBinding : rolesBindingsList.getItems()) {
            try {
                model.addRoleSubjects(roleBinding.getRoleRef().getName(), ROLE, roleBinding.getSubjects());
            } catch (RuntimeException e) {
                model.addSearchException(e);
                logger.error(e.getMessage(), e);
            }
        }
    }

    /**
     * Add new found variable/text/string to search result.
     *
     * @param meta     - kubernetes resource/object meta
     * @param model    - security model
     * @param resource - kubernetes @{@link Resource}
     */
    private void addRoleResultToModel(V1ObjectMeta meta, SecurityModel model, Resource resource, String fullDefinition, List<V1beta1PolicyRule> rules) {
        RoleResult newRoleResult = new RoleResult(model.getRolesResults().size() + 1)
                .setNamespace(meta.getNamespace() == null ? "N/A" : meta.getNamespace())
                .setResourceType(resource)
                .setResourceName(meta.getName())
                .setCreationTime(getParsedCreationTime(meta.getCreationTimestamp()))
                .setFullDefinition(fullDefinition);
        addRoleRulesToRoleResult(newRoleResult, rules);
        model.addRoleResult(newRoleResult);
    }

    private void addRoleRulesToRoleResult(RoleResult roleResult, List<V1beta1PolicyRule> rules) {
        List<RoleRuleResult> roleRules = new ArrayList<>();
        rules.forEach(rule -> roleRules.add(new RoleRuleResult(roleRules.size() + 1)
                .setApiGroups(rule.getApiGroups())
                .setResources(rule.getResources())
                .setNonResourceURLs(rule.getNonResourceURLs())
                .setVerbs(rule.getVerbs())
                .setResourceNames(rule.getResourceNames())
                .setFullDefinition(rule.toString())));
        roleResult.addRoleRules(roleRules);
    }


    // POD SECURITY CONTEXTS =============


    private void searchInPodSecurityContexts(SecurityModel model) {
        V1PodList podsList = kubeAPI.getV1PodsList(model.getSelectedPodsSecurityContextsNamespace(), model);
        for (V1Pod pod : podsList.getItems()) {
            try {
                addPodSecurityContextToModel(pod.getMetadata(), model, pod.getSpec().getSecurityContext());
            } catch (RuntimeException e) {
                model.addSearchException(e);
                logger.error(e.getMessage(), e);
            }
        }
    }


    private void addPodSecurityContextToModel(V1ObjectMeta meta, SecurityModel model, V1PodSecurityContext securityContext) {
        PodSecurityContextResult result = new PodSecurityContextResult(model.getPodsSecurityContextsResults().size() + 1)
                .setResourceName(meta.getName())
                .setFsGroup(String.valueOf(securityContext.getFsGroup()))
                .setFsGroupChangePolicy(StringUtils.isEmpty(securityContext.getFsGroupChangePolicy()) ? "null" : securityContext.getFsGroupChangePolicy())
                .setRunAsGroup(String.valueOf(securityContext.getRunAsGroup()))
                .setRunAsNonRoot(String.valueOf(securityContext.getRunAsNonRoot()))
                .setRunAsUser(String.valueOf(securityContext.getRunAsUser()))
                .setSeLinuxOptions(securityContext.getSeLinuxOptions() == null ? "null" : securityContext.getSeLinuxOptions().toString())
                .setSupplementalGroups(securityContext.getSupplementalGroups() == null ? "null" : securityContext.getSupplementalGroups().toString())
                .setSysctls(securityContext.getSysctls() == null ? "null" : securityContext.getSysctls().toString())
                .setWindowsOptions(securityContext.getWindowsOptions() == null ? "null" : securityContext.getWindowsOptions().toString())
                .setCreationTime(getParsedCreationTime(meta.getCreationTimestamp()))
                .setFullDefinition(securityContext.toString())
                .setNamespace(meta.getNamespace());
        model.addPodSecurityContext(result);
    }


    // CONTAINER SECURITY CONTEXTS =============


    private void searchInContainersSecurityContexts(SecurityModel model) {
        V1PodList podsList = kubeAPI.getV1PodsList(model.getSelectedContainersSecurityNamespace(), model);
        for (V1Pod pod : podsList.getItems()) {
            try {
                for (V1Container container : pod.getSpec().getContainers()) {
                    addPodSecurityContextToModel(pod.getMetadata(), container, model);
                }
            } catch (RuntimeException e) {
                model.addSearchException(e);
                logger.error(e.getMessage(), e);
            }
        }
    }


    private void addPodSecurityContextToModel(V1ObjectMeta meta, V1Container container, SecurityModel model) {
        V1SecurityContext securityContext = container.getSecurityContext();
        ContainerSecurityResult result = new ContainerSecurityResult(model.getContainersSecurityResults().size() + 1)
                .setResourceName(container.getName())
                .setPodName(meta.getName())
                .setCreationTime(getParsedCreationTime(meta.getCreationTimestamp()))
                .setNamespace(meta.getNamespace());

        if (Objects.nonNull(securityContext)) {
            result.setAllowPrivilegeEscalation(String.valueOf(securityContext.getAllowPrivilegeEscalation()))
                    .setCapabilities(securityContext.getCapabilities() == null ? "null" : securityContext.getCapabilities().toString())
                    .setPrivileged(String.valueOf(securityContext.getPrivileged()))
                    .setProcMount(securityContext.getProcMount())
                    .setReadOnlyRootFilesystem(String.valueOf(securityContext.getReadOnlyRootFilesystem()))
                    .setRunAsGroup(String.valueOf(securityContext.getRunAsGroup()))
                    .setRunAsNonRoot(String.valueOf(securityContext.getRunAsNonRoot()))
                    .setRunAsUser(String.valueOf(securityContext.getRunAsUser()))
                    .setSeLinuxOptions(securityContext.getSeLinuxOptions() == null ? "null" : securityContext.getSeLinuxOptions().toString())
                    .setWindowsOptions(securityContext.getWindowsOptions() == null ? "null" : securityContext.getWindowsOptions().toString())
                    .setFullDefinition(securityContext.toString());
        }
        model.addContainerSecurityResult(result);
    }


    // SERVICE ACCOUNTS =============


    private void searchInServiceAccounts(SecurityModel model) {
        V1ServiceAccountList serviceAccountsList = kubeAPI.getV1ServiceAccountsList(model.getSelectedServiceAccountsNamespace(), model);
        for (V1ServiceAccount sa : serviceAccountsList.getItems()) {
            try {
                ServiceAccountResult saResult = new ServiceAccountResult(model.getServiceAccountsResults().size() + 1)
                        .setResourceName(sa.getMetadata().getName())
                        .setKind(sa.getKind())
                        .setNamespace(sa.getMetadata().getNamespace())
                        .setSecrets(Strings.join(sa.getSecrets().stream().map(V1ObjectReference::getName).collect(Collectors.toList()), ','))
                        .setCreationTime(getParsedCreationTime(sa.getMetadata().getCreationTimestamp()))
                        .setFullDefinition(sa.toString());
                model.addServiceAccountResult(saResult);
            } catch (RuntimeException e) {
                model.addSearchException(e);
                logger.error(e.getMessage(), e);
            }
        }
    }


    // POD SECURITY POLICIES =============


    private void searchInPodSecurityPolicies(SecurityModel model) {
        V1beta1PodSecurityPolicyList policiesList = kubeAPI.getPolicyV1beta1PodSecurityPolicyList(model);
        for (V1beta1PodSecurityPolicy policy : policiesList.getItems()) {
            try {
                addPodSecurityPolicyToModel(policy.getMetadata(), model, policy.getSpec(), policy.toString());
            } catch (RuntimeException e) {
                model.addSearchException(e);
                logger.error(e.getMessage(), e);
            }
        }
    }


    private void addPodSecurityPolicyToModel(V1ObjectMeta meta, SecurityModel model, V1beta1PodSecurityPolicySpec spec, String fullDefinition) {
        PodSecurityPoliciesResult result = new PodSecurityPoliciesResult(model.getPodSecurityPoliciesResults().size() + 1)
                .setResourceName(meta.getName() == null ? "null" : meta.getName())
                .setAllowPrivilegeEscalation(spec.getAllowPrivilegeEscalation() == null ? "null" : spec.getAllowPrivilegeEscalation().toString())
                .setDefaultAllowPrivilegeEscalation(spec.getDefaultAllowPrivilegeEscalation() == null ? "null" : spec.getDefaultAllowPrivilegeEscalation().toString())
                .setAllowedCSIDrivers(spec.getAllowedCSIDrivers() == null ? "null" : spec.getAllowedCSIDrivers().toString())
                .setAllowedCapabilities(spec.getAllowedCapabilities() == null ? "null" : spec.getAllowedCapabilities().toString())
                .setAllowedFlexVolumes(spec.getAllowedFlexVolumes() == null ? "null" : spec.getAllowedFlexVolumes().toString())
                .setAllowedHostPaths(spec.getAllowedHostPaths() == null ? "null" : spec.getAllowedHostPaths().toString())
                .setAllowedProcMountTypes(spec.getAllowedProcMountTypes() == null ? "null" : spec.getAllowedProcMountTypes().toString())
                .setAllowedUnsafeSysctls(spec.getAllowedUnsafeSysctls() == null ? "null" : spec.getAllowedUnsafeSysctls().toString())
                .setDefaultAddCapabilities(spec.getDefaultAddCapabilities() == null ? "null" : spec.getDefaultAddCapabilities().toString())
                .setForbiddenSysctls(spec.getForbiddenSysctls() == null ? "null" : spec.getForbiddenSysctls().toString())
                .setFsGroup(spec.getFsGroup() == null ? "null" : spec.getFsGroup().toString())
                .setHostIPC(spec.getHostIPC() == null ? "null" : spec.getHostIPC().toString())
                .setHostNetwork(spec.getHostNetwork() == null ? "null" : spec.getHostNetwork().toString())
                .setHostPID(spec.getHostPID() == null ? "null" : spec.getHostPID().toString())
                .setHostPorts(spec.getHostPorts() == null ? "null" : spec.getHostPorts().toString())
                .setPrivileged(spec.getPrivileged() == null ? "null" : spec.getPrivileged().toString())
                .setReadOnlyRootFilesystem(spec.getReadOnlyRootFilesystem() == null ? "null" : spec.getReadOnlyRootFilesystem().toString())
                .setRequiredDropCapabilities(spec.getRequiredDropCapabilities() == null ? "null" : spec.getRequiredDropCapabilities().toString())
                .setRunAsGroup(spec.getRunAsGroup() == null ? "null" : spec.getRunAsGroup().toString())
                .setRunAsUser(spec.getRunAsUser() == null ? "null" : spec.getRunAsUser().toString())
                .setRuntimeClass(spec.getRuntimeClass() == null ? "null" : spec.getRuntimeClass().toString())
                .setSeLinux(spec.getSeLinux() == null ? "null" : spec.getSeLinux().toString())
                .setSupplementalGroups(spec.getSupplementalGroups() == null ? "null" : spec.getSupplementalGroups().toString())
                .setVolumes(spec.getVolumes() == null ? "null" : spec.getVolumes().toString())
                .setFullDefinition(fullDefinition)
                .setCreationTime(getParsedCreationTime(meta.getCreationTimestamp()))
                .setNamespace(meta.getNamespace() == null ? "null" : meta.getNamespace());
        model.addPodSecurityPolicy(result);
    }


    private String getParsedCreationTime(DateTime dateTime) {
        return dateTime == null ? "null" : dateTime.toString("dd.MM.yyyy HH:mm:ss");
    }

    private boolean skipKubeNamespace(SecurityModel securityModel, String namespace) {
        return securityModel.isSkipKubeNamespaces() && Objects.nonNull(namespace) && namespace.startsWith("kube-");
    }

    // NETWORK POLICIES =============
    private void searchInNetworkPolicies(SecurityModel model) {
        V1NetworkPolicyList policiesList = kubeAPI.getV1NetworkPolicyList(model.getSelectedNetworkPoliciesNamespace(), model);

        for (V1NetworkPolicy policy : policiesList.getItems()) {
            try {
                addNetworkPolicyToModel(policy.getMetadata(), model, policy.getSpec(), policy.toString());
            } catch (RuntimeException e) {
                model.addSearchException(e);
                logger.error(e.getMessage(), e);
            }
        }

    }

    private void addNetworkPolicyToModel(V1ObjectMeta meta, SecurityModel model, V1NetworkPolicySpec spec, String fullDefinition) {
        String deleteAnnotation = "kubectl.kubernetes.io/last-applied-configuration";
        NetworkPolicyResult result = new NetworkPolicyResult()
                .setResourceName(meta.getName() == null ? "null" : meta.getName())
                .setNamespace(meta.getNamespace() == null ? "null" : meta.getNamespace())
                .setAnnotations(meta.getAnnotations() == null ? Collections.emptyMap() : meta.getAnnotations())
                .setPodSelectorLabels(spec.getPodSelector().getMatchLabels())
                .setFullDefinition(fullDefinition)
                .setCreationTime(getParsedCreationTime(meta.getCreationTimestamp()))
                .setEgress(spec.getEgress())
                .setIngress(spec.getIngress());

        result.getAnnotations().remove(deleteAnnotation);
        model.addNetworkPolicy(result);
    }

    public void createNetworkPolicy(SecurityModel model) {
        NetworkPolicyPattern networkPolicyPattern = model.getNetworkPolicyPattern();
        networkPolicyPattern.parse();
        logger.info("Parsed network policy: " + networkPolicyPattern);
        KubernetesClient client;
        if(networkPolicyPattern.getNamespace() == null || networkPolicyPattern.getNamespace().isEmpty()) {
            client = fabricClient;
        } else {
            client = ((DefaultKubernetesClient) fabricClient).inNamespace(networkPolicyPattern.getNamespace());
        }
        try {
            NetworkPolicy networkPolicy = convertPatternToPolicy(model.getNetworkPolicyPattern());
            logger.info("Converted network policy: " + networkPolicy);
            client.network()
                    .networkPolicies()
                    .createOrReplace(networkPolicy);
        } catch (RuntimeException e) {
            model.addSearchException(e);
            logger.error(e.getMessage(), e);
        }
    }

    public static NetworkPolicy convertPatternToPolicy(NetworkPolicyPattern pattern) {
        String DESCRIPTION_ANNOTATION = "kubehelper.com/description";
        NetworkPolicyBuilder builder = new NetworkPolicyBuilder();

        Map<String, String> annotations = new HashMap<>();
        annotations.put(DESCRIPTION_ANNOTATION, pattern.getDescription());

        String namespace = (pattern.getNamespace() == null || pattern.getNamespace().isEmpty()) ? null : pattern.getNamespace();

        builder.withNewMetadata()
                .withName(pattern.getName())
                .withNamespace(namespace)
                .withAnnotations(annotations)
                .endMetadata();

        SpecNested<NetworkPolicyBuilder> spec = builder.withNewSpec();

        // podSelector
        spec.withNewPodSelector()
                .withMatchLabels(pattern.getPodSelectorLabels())
                .endPodSelector();

        // ingress
        if ("Ingress".equals(pattern.getType())) {
            IngressNested<SpecNested<NetworkPolicyBuilder>> ingress = spec.addNewIngress();
            if (pattern.getRule().getPorts() != null && !pattern.getRule().getPorts().isEmpty()) {
                ingress.withPorts(parsePorts(pattern.getRule().getPorts()));
            }
            if (pattern.getRule().getSelector() != null) {
                ingress.withFrom(parsePeer(pattern.getRule().getSelector()));
            }
            ingress.endIngress();
        }

        // egress
        if ("Egress".equals(pattern.getType())) {
            EgressNested<SpecNested<NetworkPolicyBuilder>> egress = spec.addNewEgress();
            if (pattern.getRule().getPorts() != null && !pattern.getRule().getPorts().isEmpty()) {
                egress.withPorts(parsePorts(pattern.getRule().getPorts()));
            }
            if (pattern.getRule().getSelector() != null) {
                egress.withTo(parsePeer(pattern.getRule().getSelector()));
            }
            egress.endEgress();
        }

        // policyTypes
        spec.withPolicyTypes(pattern.getType());
        spec.endSpec();

        return builder.build();
    }

    private static NetworkPolicyPeer parsePeer(NetworkPolicyPeerPattern peer) {
        NetworkPolicyPeer networkPolicyPeer = new NetworkPolicyPeer();
        if (peer.getIpBlock() != null) {
            IPBlock ipBlock = new IPBlock();
            ipBlock.setCidr(peer.getIpBlock().getCidr());
            if (peer.getIpBlock().getExcept() != null) {
                ipBlock.setExcept(Arrays.asList(peer.getIpBlock().getExcept().split(",")));
            }
            networkPolicyPeer.setIpBlock(ipBlock);
        }

        if (peer.getNamespaceName() != null) {
            networkPolicyPeer.setNamespaceSelector(new LabelSelector(
                    Collections.singletonList(
                            new LabelSelectorRequirement(
                                    "name",
                                    "In",
                                    Collections.singletonList(peer.getNamespaceName()))
                    ), null)
            );
        }

        if (peer.getPodSelectorLabels() != null) {
            networkPolicyPeer.setPodSelector(new LabelSelector(null, peer.getPodSelectorLabels()));
        }
        return networkPolicyPeer;
    }

    private static List<NetworkPolicyPort> parsePorts(List<NetworkPolicyPortPattern> ports) {
        List<NetworkPolicyPort> portsList = new ArrayList<>();
        for (NetworkPolicyPortPattern port : ports) {
            portsList.add(new NetworkPolicyPort(new IntOrString(port.getPort()), port.getProtocol()));
        }
        return portsList;
    }

}
