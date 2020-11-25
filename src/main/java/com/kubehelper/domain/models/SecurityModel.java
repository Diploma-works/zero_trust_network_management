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
package com.kubehelper.domain.models;

import com.kubehelper.common.Global;
import com.kubehelper.common.KubeHelperException;
import com.kubehelper.domain.filters.ContainersSecurityFilter;
import com.kubehelper.domain.filters.PodsSecurityFilter;
import com.kubehelper.domain.filters.PodsSecurityPoliciesSecurityFilter;
import com.kubehelper.domain.filters.RoleRulesSecurityFilter;
import com.kubehelper.domain.filters.RolesSecurityFilter;
import com.kubehelper.domain.filters.ServiceAccountsSecurityFilter;
import com.kubehelper.domain.results.ContainerSecurityResult;
import com.kubehelper.domain.results.PodSecurityPoliciesResult;
import com.kubehelper.domain.results.PodSecurityResult;
import com.kubehelper.domain.results.RoleResult;
import com.kubehelper.domain.results.RoleRuleResult;
import com.kubehelper.domain.results.ServiceAccountResult;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author JDev
 */
public class SecurityModel implements PageModel {

    private String templateUrl = "~./zul/pages/security.zul";
    public static String NAME = Global.SECURITY_MODEL;

    private String selectedRolesNamespace = "all";
    private String selectedPodsNamespace = "all";
    private String selectedContainersNamespace = "all";
    private String selectedServiceAccountsNamespace = "all";
    private String selectedPodSecurityPoliciesNamespace = "all";

    private List<String> namespaces = new ArrayList<>();
    private Map<Integer, RoleResult> rolesResults = new HashMap<>();
    private List<PodSecurityResult> podsResults = new ArrayList<>();
    private List<ContainerSecurityResult> containersResults = new ArrayList<>();
    private List<ServiceAccountResult> serviceAccountsResults = new ArrayList<>();
    private List<PodSecurityPoliciesResult> podSecurityPoliciesResults = new ArrayList<>();
    //key is RoleResult id
    private RolesSecurityFilter rolesFilter = new RolesSecurityFilter();
    private RoleRulesSecurityFilter roleRulesFilter = new RoleRulesSecurityFilter();
    private PodsSecurityFilter podsFilter = new PodsSecurityFilter();
    private ContainersSecurityFilter containersFilter = new ContainersSecurityFilter();
    private ServiceAccountsSecurityFilter serviceAccountsFilter = new ServiceAccountsSecurityFilter();
    private PodsSecurityPoliciesSecurityFilter podSecurityPoliciesFilter = new PodsSecurityPoliciesSecurityFilter();
    private List<KubeHelperException> searchExceptions = new ArrayList<>();
    private int selectedRoleId;
    private int selectedRoleRuleId;
//    private boolean caseSensitiveSearch = false;

    public SecurityModel() {
    }

//    public SecurityModel addSearchResult(SearchResult searchResult) {
//        searchResults.add(searchResult);
//        filter.addResourceTypesFilter(searchResult.getResourceType());
//        filter.addNamespacesFilter(searchResult.getNamespace());
//        filter.addResourceNamesFilter(resourceName);
//        return this;
//    }

    public void addSearchException(Exception exception) {
        this.searchExceptions.add(new KubeHelperException(exception));
    }

    public SecurityModel setSearchExceptions(List<KubeHelperException> searchExceptions) {
        this.searchExceptions = searchExceptions;
        return this;
    }


    public List<KubeHelperException> getSearchExceptions() {
        return searchExceptions;
    }

    @Override
    public String getTemplateUrl() {
        return templateUrl;
    }

    @Override
    public String getName() {
        return NAME;
    }


    public boolean hasSearchErrors() {
        return !searchExceptions.isEmpty();
    }

    public String getSelectedRolesNamespace() {
        return selectedRolesNamespace;
    }

    public SecurityModel setSelectedRolesNamespace(String selectedRolesNamespace) {
        this.selectedRolesNamespace = selectedRolesNamespace;
        return this;
    }

    public String getSelectedPodsNamespace() {
        return selectedPodsNamespace;
    }

    public SecurityModel setSelectedPodsNamespace(String selectedPodsNamespace) {
        this.selectedPodsNamespace = selectedPodsNamespace;
        return this;
    }

    public String getSelectedContainersNamespace() {
        return selectedContainersNamespace;
    }

    public SecurityModel setSelectedContainersNamespace(String selectedContainersNamespace) {
        this.selectedContainersNamespace = selectedContainersNamespace;
        return this;
    }

    public String getSelectedServiceAccountsNamespace() {
        return selectedServiceAccountsNamespace;
    }

    public SecurityModel setSelectedServiceAccountsNamespace(String selectedServiceAccountsNamespace) {
        this.selectedServiceAccountsNamespace = selectedServiceAccountsNamespace;
        return this;
    }

    public String getSelectedPodSecurityPoliciesNamespace() {
        return selectedPodSecurityPoliciesNamespace;
    }

    public SecurityModel setSelectedPodSecurityPoliciesNamespace(String selectedPodSecurityPoliciesNamespace) {
        this.selectedPodSecurityPoliciesNamespace = selectedPodSecurityPoliciesNamespace;
        return this;
    }

    public RolesSecurityFilter getRolesFilter() {
        return rolesFilter;
    }

    public RoleRulesSecurityFilter getRoleRulesFilter() {
        return roleRulesFilter;
    }

    public PodsSecurityFilter getPodsFilter() {
        return podsFilter;
    }

    public ContainersSecurityFilter getContainersFilter() {
        return containersFilter;
    }

    public ServiceAccountsSecurityFilter getServiceAccountsFilter() {
        return serviceAccountsFilter;
    }

    public PodsSecurityPoliciesSecurityFilter getPodSecurityPoliciesFilter() {
        return podSecurityPoliciesFilter;
    }

    public SecurityModel setRolesFilter(RolesSecurityFilter rolesFilter) {
        this.rolesFilter = rolesFilter;
        return this;
    }

    public SecurityModel setRoleRulesFilter(RoleRulesSecurityFilter roleRulesFilter) {
        this.roleRulesFilter = roleRulesFilter;
        return this;
    }

    public SecurityModel setPodsFilter(PodsSecurityFilter podsFilter) {
        this.podsFilter = podsFilter;
        return this;
    }

    public SecurityModel setContainersFilter(ContainersSecurityFilter containersFilter) {
        this.containersFilter = containersFilter;
        return this;
    }

    public SecurityModel setServiceAccountsFilter(ServiceAccountsSecurityFilter serviceAccountsFilter) {
        this.serviceAccountsFilter = serviceAccountsFilter;
        return this;
    }

    public SecurityModel setPodSecurityPoliciesFilter(PodsSecurityPoliciesSecurityFilter podSecurityPoliciesFilter) {
        this.podSecurityPoliciesFilter = podSecurityPoliciesFilter;
        return this;
    }

    public Map<Integer, RoleResult> getRolesResults() {
        return rolesResults;
    }

    public SecurityModel setRolesResults(Map<Integer, RoleResult> rolesResults) {
        this.rolesResults = rolesResults;
        return this;
    }

    public List<PodSecurityResult> getPodsResults() {
        return podsResults;
    }

    public SecurityModel setPodsResults(List<PodSecurityResult> podsResults) {
        this.podsResults = podsResults;
        return this;
    }

    public List<RoleRuleResult> getRoleRulesResults(int roleId) {
        return rolesResults.get(roleId).getRoleRules(roleId);
    }

    public List<ContainerSecurityResult> getContainersResults() {
        return containersResults;
    }

    public SecurityModel setContainersResults(List<ContainerSecurityResult> containersResults) {
        this.containersResults = containersResults;
        return this;
    }

    public List<ServiceAccountResult> getServiceAccountsResults() {
        return serviceAccountsResults;
    }

    public SecurityModel setServiceAccountsResults(List<ServiceAccountResult> serviceAccountsResults) {
        this.serviceAccountsResults = serviceAccountsResults;
        return this;
    }

    public List<PodSecurityPoliciesResult> getPodSecurityPoliciesResults() {
        return podSecurityPoliciesResults;
    }

    public SecurityModel setPodSecurityPoliciesResults(List<PodSecurityPoliciesResult> podSecurityPoliciesResults) {
        this.podSecurityPoliciesResults = podSecurityPoliciesResults;
        return this;
    }

    public List<String> getNamespaces() {
        return namespaces;
    }

    public SecurityModel setNamespaces(List<String> namespaces) {
        this.namespaces = namespaces;
        return this;
    }
}