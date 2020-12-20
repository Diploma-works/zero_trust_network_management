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
package com.kubehelper.viewmodels;

import com.kubehelper.common.Global;
import com.kubehelper.domain.filters.ContainersSecurityFilter;
import com.kubehelper.domain.filters.PodsSecurityFilter;
import com.kubehelper.domain.filters.PodsSecurityPoliciesSecurityFilter;
import com.kubehelper.domain.filters.RBACFilter;
import com.kubehelper.domain.filters.RoleRulesSecurityFilter;
import com.kubehelper.domain.filters.RolesSecurityFilter;
import com.kubehelper.domain.filters.ServiceAccountsSecurityFilter;
import com.kubehelper.domain.models.SecurityModel;
import com.kubehelper.domain.results.ContainerSecurityResult;
import com.kubehelper.domain.results.PodSecurityContextResult;
import com.kubehelper.domain.results.PodSecurityPoliciesResult;
import com.kubehelper.domain.results.RBACResult;
import com.kubehelper.domain.results.RoleResult;
import com.kubehelper.domain.results.RoleRuleResult;
import com.kubehelper.domain.results.ServiceAccountResult;
import com.kubehelper.services.CommonService;
import com.kubehelper.services.SecurityService;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zkoss.bind.BindUtils;
import org.zkoss.bind.annotation.AfterCompose;
import org.zkoss.bind.annotation.BindingParam;
import org.zkoss.bind.annotation.Command;
import org.zkoss.bind.annotation.ContextParam;
import org.zkoss.bind.annotation.ContextType;
import org.zkoss.bind.annotation.Init;
import org.zkoss.bind.annotation.NotifyChange;
import org.zkoss.zk.ui.Component;
import org.zkoss.zk.ui.Executions;
import org.zkoss.zk.ui.Path;
import org.zkoss.zk.ui.select.Selectors;
import org.zkoss.zk.ui.select.annotation.VariableResolver;
import org.zkoss.zk.ui.select.annotation.Wire;
import org.zkoss.zk.ui.select.annotation.WireVariable;
import org.zkoss.zk.ui.util.Notification;
import org.zkoss.zkplus.spring.DelegatingVariableResolver;
import org.zkoss.zul.Auxhead;
import org.zkoss.zul.Combobox;
import org.zkoss.zul.Footer;
import org.zkoss.zul.ListModelList;
import org.zkoss.zul.Window;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author JDev
 */
@VariableResolver(DelegatingVariableResolver.class)
public class SecurityVM implements PropertyChangeListener {

    private static Logger logger = LoggerFactory.getLogger(SecurityVM.class);

    private boolean isGetRolesButtonPressed;
    private boolean isGetPodsSecurityContextsButtonPressed;
    private boolean isGetRBACsButtonPressed;
    private boolean isGetContainersButtonPressed;
    private boolean isGetServiceAccountsButtonPressed;
    private boolean isGetPodSecurityPoliciesButtonPressed;

    private SecurityModel securityModel;

    private ListModelList<RoleResult> rolesResults = new ListModelList<>();
    private ListModelList<RoleResult.RoleBindingSubject> roleSubjectsResults = new ListModelList<>();
    private ListModelList<RoleRuleResult> roleRulesResults = new ListModelList<>();
    private ListModelList<RBACResult> rbacsResults = new ListModelList<>();
    private ListModelList<PodSecurityContextResult> podsSecurityContextsResults = new ListModelList<>();
    private ListModelList<ContainerSecurityResult> containersResults = new ListModelList<>();
    private ListModelList<ServiceAccountResult> serviceAccountsResults = new ListModelList<>();
    private ListModelList<PodSecurityPoliciesResult> podsSecurityPoliciesResults = new ListModelList<>();

    private String clickedRoleBindingSubjectsLabel = "";
    private String clickedRoleRulesLabel = "";

    @Wire
    private Footer rolesGridFooter;

    @Wire
    private Footer roleRulesGridFooter;

    @Wire
    private Footer podsSecurityContextsGridFooter;

    @Wire
    private Footer rbacsGridFooter;

    @Wire
    private Footer containersGridFooter;

    @Wire
    private Footer serviceAccountsGridFooter;

    @Wire
    private Footer podSecurityPoliciesGridFooter;

    @WireVariable
    private CommonService commonService;

    @WireVariable
    private SecurityService securityService;

    @Init
    public void init() {
        securityModel = (SecurityModel) Global.ACTIVE_MODELS.computeIfAbsent(Global.SECURITY_MODEL, (k) -> Global.NEW_MODELS.get(Global.SECURITY_MODEL));
        securityModel.addPropertyChangeListener(SecurityVM.this);
        setAllNamespacesToModel();
    }

    /**
     * We need Selectors.wireComponents() in order to be able to @Wire GUI components.
     */
    @AfterCompose
    public void afterCompose(@ContextParam(ContextType.VIEW) Component view) {
        Selectors.wireComponents(view, this, false);
    }

    //  GETTING ================

    @Command
    @NotifyChange({"rolesTotalItems", "rolesResults", "rolesFilter"})
    public void getRoles() {
        securityModel.setRolesFilter(new RolesSecurityFilter());
        securityService.getRoles(securityModel);
        isGetRolesButtonPressed = true;
        setAllNamespacesToModel();
        if (securityModel.getRolesFilter().isFilterActive() && !securityModel.getRolesResults().isEmpty()) {
            filterSecurityRoles();
        } else {
            rolesResults = new ListModelList<>(securityModel.getRolesResultsList());
        }
    }

    @Command
    @NotifyChange({"rbacsTotalItems", "rbacsResults", "rbacsFilter"})
    public void getRbacs() {
        securityModel.setServiceAccountsFilter(new ServiceAccountsSecurityFilter());
        securityService.getRBACs(securityModel);
        isGetRBACsButtonPressed = true;
        setAllNamespacesToModel();
        if (securityModel.getRbacsFilter().isFilterActive() && !securityModel.getRbacsResults().isEmpty()) {
            filterRbacs();
        } else {
            rbacsResults = new ListModelList<>(securityModel.getRbacsResults());
        }
    }

    @Command
    @NotifyChange({"podsSecurityContextsTotalItems", "podsSecurityContextResults", "podsFilter"})
    public void getPodsSecurityContexts() {
        securityModel.setPodsFilter(new PodsSecurityFilter());
        securityService.getPodsSecurityContexts(securityModel);
        isGetPodsSecurityContextsButtonPressed = true;
//        if (securityModel.getRolesFilter().isFilterActive() && !securityModel.getRolesResults().isEmpty()) {
////            filterIps();
//        } else {
//            rolesResults = new ListModelList<>(securityModel.getRolesResultsList());
//        }
        podsSecurityContextsResults = new ListModelList<>(securityModel.getPodsSecurityContextsResults());
//        onInitPreparations();
    }

    @Command
    @NotifyChange({"containersTotalItems", "containersResults", "containersFilter"})
    public void getContainers() {
        securityModel.setContainersFilter(new ContainersSecurityFilter());
//        securityService.getContainers(securityModel);
        isGetContainersButtonPressed = true;
//        onInitPreparations();
    }

    @Command
    @NotifyChange({"serviceAccountsTotalItems", "serviceAccountsResults", "serviceAccountsFilter"})
    public void getServiceAccounts() {
        securityModel.setServiceAccountsFilter(new ServiceAccountsSecurityFilter());
//        securityService.getServiceAccounts(securityModel);
        isGetServiceAccountsButtonPressed = true;
//        onInitPreparations();
    }

    @Command
    @NotifyChange({"podsSecurityPoliciesTotalItems", "podsSecurityPoliciesResults", "podSecurityPoliciesFilter"})
    public void getPodsSecurityPolicies() {
        securityModel.setPodSecurityPoliciesFilter(new PodsSecurityPoliciesSecurityFilter());
        securityService.getPodsSecurityPolicies(securityModel);
        isGetPodSecurityPoliciesButtonPressed = true;
        podsSecurityPoliciesResults = new ListModelList<>(securityModel.getPodSecurityPoliciesResults());
        setAllNamespacesToModel();
    }

    private void setAllNamespacesToModel() {
        securityModel.setNamespaces(securityModel.getNamespaces().isEmpty() ? commonService.getAllNamespaces() : securityModel.getNamespaces());
        logger.info("Found {} namespaces.", securityModel.getNamespaces());
    }

    //  FILTERING ================

    @Command
    @NotifyChange({"rolesTotalItems", "rolesResults"})
    public void filterSecurityRoles() {
        rolesResults.clear();
        for (RoleResult roleResult : securityModel.getRolesResultsList()) {
            if (StringUtils.containsIgnoreCase(roleResult.getCreationTime(), getRolesFilter().getCreationTime()) &&
                    checkEqualsFilter(roleResult.getResourceName(), getRolesFilter().getSelectedResourceNameFilter()) &&
                    checkEqualsFilter(roleResult.getResourceType(), getRolesFilter().getSelectedResourceTypeFilter()) &&
                    checkEqualsFilter(roleResult.getNamespace(), getRolesFilter().getSelectedNamespaceFilter())) {
                rolesResults.add(roleResult);
            }
        }
    }

    @Command
    @NotifyChange({"rbacsTotalItems", "rbacsResults"})
    public void filterRbacs() {
        rbacsResults.clear();
        for (RBACResult rbacResult : securityModel.getRbacsResults()) {
            if (StringUtils.containsIgnoreCase(rbacResult.getApiGroup(), getRbacFilter().getApiGroup()) &&
                    checkEqualsFilter(rbacResult.getResourceName(), getRbacFilter().getSelectedResourceNameFilter()) &&
                    checkEqualsFilter(rbacResult.getResourceType(), getRbacFilter().getSelectedResourceTypeFilter()) &&
                    checkEqualsFilter(rbacResult.getNamespace(), getRbacFilter().getSelectedNamespaceFilter()) &&
                    checkEqualsFilter(rbacResult.getSubjectKind(), getRbacFilter().getSelectedSubjectKindFilter()) &&
                    checkEqualsFilter(rbacResult.getSubjectName(), getRbacFilter().getSelectedSubjectNameFilter()) &&
                    checkEqualsFilter(rbacResult.getRoleName(), getRbacFilter().getSelectedRoleNameFilter()) &&
                    getRbacFilter().getVerbAll().equals(checkRbacRoleFilter(getRbacFilter().getVerbAll(), rbacResult.isAll())) &&
                    getRbacFilter().getVerbGet().equals(checkRbacRoleFilter(getRbacFilter().getVerbGet(), rbacResult.isGet())) &&
                    getRbacFilter().getVerbList().equals(checkRbacRoleFilter(getRbacFilter().getVerbList(), rbacResult.isList())) &&
                    getRbacFilter().getVerbCreate().equals(checkRbacRoleFilter(getRbacFilter().getVerbCreate(), rbacResult.isCreate())) &&
                    getRbacFilter().getVerbUpdate().equals(checkRbacRoleFilter(getRbacFilter().getVerbUpdate(), rbacResult.isUpdate())) &&
                    getRbacFilter().getVerbPatch().equals(checkRbacRoleFilter(getRbacFilter().getVerbPatch(), rbacResult.isPatch())) &&
                    getRbacFilter().getVerbWatch().equals(checkRbacRoleFilter(getRbacFilter().getVerbWatch(), rbacResult.isWatch())) &&
                    getRbacFilter().getVerbDelete().equals(checkRbacRoleFilter(getRbacFilter().getVerbDelete(), rbacResult.isDelete())) &&
                    getRbacFilter().getVerbDeleteCollection().equals(checkRbacRoleFilter(getRbacFilter().getVerbDeleteCollection(), rbacResult.isDeletecollection())) &&
                    StringUtils.containsIgnoreCase(rbacResult.getOthers(), getRbacFilter().getOthers())) {
                rbacsResults.add(rbacResult);
            }
        }
    }

    private boolean checkEqualsFilter(String resource, String filter) {
        if (filter.equals("")) {
            return true;
        }
        if (resource.equals(filter)) {
            return true;
        }
        return false;
    }

    private String checkRbacRoleFilter(String verb, boolean rbacVerb) {
        if (rbacVerb && verb.equals("Yes")) {
            return "Yes";
        }
        if (!rbacVerb && verb.equals("No")) {
            return "No";
        }
        return "";
    }

    //  CLEARING ================


    @Command
    @NotifyChange({"rolesTotalItems", "rolesResults", "roleRulesResults", "roleSubjectsResults", "rolesFilter", "selectedRolesNamespace"})
    public void clearAllRoles() {
        securityModel.setRolesResults(new HashMap<>())
                .setRolesFilter(new RolesSecurityFilter())
                .setNamespaces(commonService.getAllNamespaces())
                .setSelectedRolesNamespace("all")
                .setSearchExceptions(new ArrayList<>());
        rolesResults = new ListModelList<>();
        roleRulesResults = new ListModelList<>();
        roleSubjectsResults = new ListModelList<>();
        clearAllRolesFilterComboboxes();
    }

    @Command
    @NotifyChange({"rbacsTotalItems", "rbacsResults", "rbacFilter", "selectedRBACsNamespace"})
    public void clearAllRbacs() {
        securityModel.setRbacsResults(new ArrayList<>())
                .setRbacsFilter(new RBACFilter())
                .setNamespaces(commonService.getAllNamespaces())
                .setSelectedRBACsNamespace("all")
                .setSearchExceptions(new ArrayList<>());
        rbacsResults = new ListModelList<>();
        clearAllRbacFilterComboboxes();
    }

    @Command
    @NotifyChange({"podsTotalItems", "podsResults", "podsFilter", "selectedPodsNamespace"})
    public void clearAllPods() {
//        securityModel.setRolesResults(new ListModelList<>())
//                .setFilter(new IpsAndPortsFilter())
//                .setNamespaces(commonService.getAllNamespaces())
//                .setSelectedNamespace("all")
//                .setSearchExceptions(new ArrayList<>());
        containersResults = new ListModelList<>();
        clearAllFilterComboboxes();
    }

    @Command
    @NotifyChange({"containersTotalItems", "containersResults", "containersFilter", "selectedContainersNamespace"})
    public void clearAllContainers() {
//        securityModel.setRolesResults(new ListModelList<>())
//                .setFilter(new IpsAndPortsFilter())
//                .setNamespaces(commonService.getAllNamespaces())
//                .setSelectedNamespace("all")
//                .setSearchExceptions(new ArrayList<>());
        containersResults = new ListModelList<>();
        clearAllFilterComboboxes();
    }

    @Command
    @NotifyChange({"serviceAccountsTotalItems", "serviceAccountsResults", "serviceAccountsFilter", "selectedServiceAccountsNamespace"})
    public void clearAllServiceAccounts() {
//        securityModel.setRolesResults(new ListModelList<>())
//                .setFilter(new IpsAndPortsFilter())
//                .setNamespaces(commonService.getAllNamespaces())
//                .setSelectedNamespace("all")
//                .setSearchExceptions(new ArrayList<>());
        serviceAccountsResults = new ListModelList<>();
        clearAllFilterComboboxes();
    }

    @Command
    @NotifyChange({"podSecurityPoliciesTotalItems", "podSecurityPoliciesResults", "podSecurityPoliciesFilter", "selectedPodSecurityPoliciesNamespace"})
    public void clearAllPodSecurityPolicies() {
//        securityModel.setRolesResults(new ListModelList<>())
//                .setFilter(new IpsAndPortsFilter())
//                .setNamespaces(commonService.getAllNamespaces())
//                .setSelectedNamespace("all")
//                .setSearchExceptions(new ArrayList<>());
        podsSecurityPoliciesResults = new ListModelList<>();
        clearAllFilterComboboxes();
    }

    /**
     * Removes last selected value from all filter comboboxes.
     */
    private void clearAllFilterComboboxes() {
        Auxhead searchGridAuxHead = (Auxhead) Path.getComponent("//indexPage/templateInclude/rbacGridAuxHead");
        for (Component child : searchGridAuxHead.getFellows()) {
            if (Arrays.asList("filterResourceNamesCBox", "filterNamespacesCBox", "filterResourceTypesCBox").contains(child.getId())) {
                Combobox cBox = (Combobox) child;
                cBox.setValue("");
            }
        }
    }

    private void clearAllRolesFilterComboboxes() {
        Auxhead searchGridAuxHead = (Auxhead) Path.getComponent("//indexPage/templateInclude/rolesGridAuxHead");
        for (Component child : searchGridAuxHead.getFellows()) {
            if (Arrays.asList("filterRolesNamespacesCBox", "filterRolesResourceTypesCBox", "filterRolesResourceNamesCBox").contains(child.getId())) {
                Combobox cBox = (Combobox) child;
                cBox.setValue("");
            }
        }
    }

    /**
     * Removes last selected value from all filter comboboxes.
     */
    private void clearAllRbacFilterComboboxes() {
        Auxhead searchGridAuxHead = (Auxhead) Path.getComponent("//indexPage/templateInclude/rbacGridAuxHead");
        for (Component child : searchGridAuxHead.getFellows()) {
            if (Arrays.asList("rbacResourceNamesFilterCBox", "rbacSubjectKindsFilterCBox", "rbacSubjectNamesFilterCBox", "rbacResourceTypesFilterCBox", "rbacNamespacesFilterCBox", "rbacVerbAllCBox", "rbacVerbGetCBox", "rbacVerbListCBox", "rbacVerbCreateCBox", "rbacVerbUpdateCBox", "rbacVerbPatchCBox", "rbacWerbWatchCBox", "rbacVerbDeleteCBox", "rbacVerbDeleteCollectionCBox", "rbacVerbPatchCBox").contains(child.getId())) {
                Combobox cBox = (Combobox) child;
                cBox.setValue("");
            }
        }
    }

    //  FULL DEFINITION / LOGIC ================

    @Command
    public void showRoleFullDefinition(@BindingParam("item") RoleResult item) {
        Map<String, String> parameters = Map.of("title", item.getResourceName(), "content", item.getFullDefinition());
        Window window = (Window) Executions.createComponents("~./zul/components/file-display.zul", null, parameters);
        window.doModal();
    }

    @Command
    public void showRoleRuleFullDefinition(@BindingParam("item") RoleRuleResult item) {
        Map<String, String> parameters = Map.of("title", String.valueOf(item.getId()), "content", item.getFullDefinition());
        Window window = (Window) Executions.createComponents("~./zul/components/file-display.zul", null, parameters);
        window.doModal();
    }

    @Command
    public void showPodSecurityContextFullDefinition(@BindingParam("item") PodSecurityContextResult item) {
        Map<String, String> parameters = Map.of("title", String.valueOf(item.getId()), "content", item.getFullDefinition());
        Window window = (Window) Executions.createComponents("~./zul/components/file-display.zul", null, parameters);
        window.doModal();
    }

    @Command
    public void showPodSecurityPolicyFullDefinition(@BindingParam("item") PodSecurityPoliciesResult item) {
        Map<String, String> parameters = Map.of("title", String.valueOf(item.getResourceName()), "content", item.getFullDefinition());
        Window window = (Window) Executions.createComponents("~./zul/components/file-display.zul", null, parameters);
        window.doModal();
    }

    @Command
    @NotifyChange({"roleSubjectsResults", "roleRulesResults", "clickedRoleBindingSubjectsLabel", "clickedRoleRulesLabel", "roleRulesTotalItems"})
    public void showRoleRules(@BindingParam("clickedItem") RoleResult item) {
        roleSubjectsResults = new ListModelList<>(item.getSubjects());
        //TODO make simple, remove id from roleRules
        roleRulesResults = new ListModelList<>(item.getRoleRules().get(item.getId()));
        clickedRoleRulesLabel = item.getResourceName();
        clickedRoleBindingSubjectsLabel = item.getResourceName();
    }


    public void showNotificationAndExceptions(boolean pressedButton, ListModelList results, Footer footer) {
        if (pressedButton && results.isEmpty()) {
            Notification.show("Nothing found.", "info", footer, "before_end", 2000);
        }
        if (pressedButton && !results.isEmpty()) {
            Notification.show("Found: " + results.size() + " items", "info", footer, "before_end", 2000);
        }
        if (pressedButton && securityModel.hasSearchErrors()) {
            Window window = (Window) Executions.createComponents("~./zul/components/errors.zul", null, Map.of("errors", securityModel.getSearchExceptions()));
            window.doModal();
            securityModel.setSearchExceptions(new ArrayList<>());
        }
    }

    public SecurityModel getModel() {
        return securityModel;
    }


    @Override
    public void propertyChange(PropertyChangeEvent evt) {
        BindUtils.postNotifyChange(null, null, this, ".");
    }


    //  RESULTS ================


    public ListModelList<RoleResult> getRolesResults() {
        showNotificationAndExceptions(isGetRolesButtonPressed, rolesResults, rolesGridFooter);
        isGetRolesButtonPressed = false;
        return rolesResults;
    }

    public ListModelList<RoleRuleResult> getRoleRulesResults() {
        return roleRulesResults;
    }

    public ListModelList<RBACResult> getRbacsResults() {
        showNotificationAndExceptions(isGetRBACsButtonPressed, rbacsResults, rbacsGridFooter);
        isGetPodsSecurityContextsButtonPressed = false;
        return rbacsResults;
    }

    public ListModelList<RoleResult.RoleBindingSubject> getRoleSubjectsResults() {
        return roleSubjectsResults;
    }

    public ListModelList<PodSecurityContextResult> getPodsSecurityContextResults() {
        showNotificationAndExceptions(isGetPodsSecurityContextsButtonPressed, podsSecurityContextsResults, podsSecurityContextsGridFooter);
        isGetPodsSecurityContextsButtonPressed = false;
        return podsSecurityContextsResults;
    }

    public ListModelList<ContainerSecurityResult> getContainersResults() {
        showNotificationAndExceptions(isGetContainersButtonPressed, containersResults, containersGridFooter);
        isGetContainersButtonPressed = false;
        return containersResults;
    }

    public ListModelList<ServiceAccountResult> getServiceAccountsResults() {
        showNotificationAndExceptions(isGetServiceAccountsButtonPressed, serviceAccountsResults, serviceAccountsGridFooter);
        isGetServiceAccountsButtonPressed = false;
        return serviceAccountsResults;
    }

    public ListModelList<PodSecurityPoliciesResult> getPodsSecurityPoliciesResults() {
        showNotificationAndExceptions(isGetPodSecurityPoliciesButtonPressed, podsSecurityPoliciesResults, podSecurityPoliciesGridFooter);
        isGetPodSecurityPoliciesButtonPressed = false;
        return podsSecurityPoliciesResults;
    }


    //  SELECTED NAMESPACES ================

    public String getSelectedRolesNamespace() {
        return securityModel.getSelectedRolesNamespace();
    }

    public String getSelectedRBACsNamespace() {
        return securityModel.getSelectedRBACsNamespace();
    }

    public void setSelectedRolesNamespace(String selectedRolesNamespace) {
        this.securityModel.setSelectedRolesNamespace(selectedRolesNamespace);
    }

    public void setSelectedRBACsNamespace(String selectedRBACsNamespace) {
        this.securityModel.setSelectedRBACsNamespace(selectedRBACsNamespace);
    }

    public String getSelectedPodsSecurityContextsNamespace() {
        return securityModel.getSelectedPodsSecurityContextsNamespace();
    }

    public void setSelectedPodsSecurityContextsNamespace(String selectedPodsNamespace) {
        this.securityModel.setSelectedPodsSecurityContextsNamespace(selectedPodsNamespace);
    }

    public String getSelectedContainersNamespace() {
        return securityModel.getSelectedContainersNamespace();
    }

    public void setSelectedContainersNamespace(String selectedContainersNamespace) {
        this.securityModel.setSelectedContainersNamespace(selectedContainersNamespace);
    }

    public String getSelectedServiceAccountsNamespace() {
        return securityModel.getSelectedServiceAccountsNamespace();
    }

    public void setSelectedServiceAccountsNamespace(String selectedServiceAccountsNamespace) {
        this.securityModel.setSelectedServiceAccountsNamespace(selectedServiceAccountsNamespace);
    }

    public String getSelectedPodSecurityPoliciesNamespace() {
        return securityModel.getSelectedPodSecurityPoliciesNamespace();
    }

    public void setSelectedPodSecurityPoliciesNamespace(String selectedPodSecurityPoliciesNamespace) {
        this.securityModel.setSelectedPodSecurityPoliciesNamespace(selectedPodSecurityPoliciesNamespace);
    }


    //  TOTAL ITEMS ================

    public String getRolesTotalItems() {
        return String.format("Total Items: %d", rolesResults.size());
    }

    public String getRoleRulesTotalItems() {
        return String.format("Total Items: %d", roleRulesResults.size());
    }

    public String getRbacsTotalItems() {
        return String.format("Total Items: %d", rbacsResults.size());
    }

    public String getPodsSecurityContextsTotalItems() {
        return String.format("Total Items: %d", podsSecurityContextsResults.size());
    }

    public String getContainersTotalItems() {
        return String.format("Total Items: %d", containersResults.size());
    }

    public String getServiceAccountsTotalItems() {
        return String.format("Total Items: %d", serviceAccountsResults.size());
    }

    public String getPodsSecurityPoliciesTotalItems() {
        return String.format("Total Items: %d", podsSecurityPoliciesResults.size());
    }


    //  FILTERS ================

    public RolesSecurityFilter getRolesFilter() {
        return securityModel.getRolesFilter();
    }

    public RoleRulesSecurityFilter getRoleRulesFilter() {
        return securityModel.getRoleRulesFilter();
    }

    public RBACFilter getRbacFilter() {
        return securityModel.getRbacsFilter();
    }

    public PodsSecurityFilter getPodsFilter() {
        return securityModel.getPodsFilter();
    }

    public ContainersSecurityFilter getContainersFilter() {
        return securityModel.getContainersFilter();
    }

    public ServiceAccountsSecurityFilter getServiceAccountsFilter() {
        return securityModel.getServiceAccountsFilter();
    }

    public PodsSecurityPoliciesSecurityFilter getPodSecurityPoliciesFilter() {
        return securityModel.getPodSecurityPoliciesFilter();
    }

    //  LABELS / HEIGHTS / OTHERS ================

    public String getClickedRoleBindingSubjectsLabel() {
        return "Role Binding subjects for the Role: " + clickedRoleBindingSubjectsLabel;
    }

    public String getClickedRoleRulesLabel() {
        return "Rules for the Role: " + clickedRoleRulesLabel;
    }

    public String getRBACIcon(@BindingParam("verb") boolean verb) {
        return verb ? "z-icon-check" : "z-icon-times";
    }

    public String getRBACIconColor(@BindingParam("verb") boolean verb) {
        return verb ? "color:green;" : "color:red;";
    }


    public List<String> getNamespaces() {
        return securityModel.getNamespaces();
    }

    public String getRolesGridHeight() {
        return securityModel.getMainGridHeight() * 0.43 + "px";
    }

    public String getRbacsGridHeight() {
        return securityModel.getMainGridHeight() + "px";
    }

    public String getSubjectsGridHeight() {
        return securityModel.getMainGridHeight() * 0.13 + "px";
    }

    public String getRoleRulesGridHeight() {
        return securityModel.getMainGridHeight() * 0.44 + "px";
    }

    public String getPodsSecurityContextsGridHeight() {
        return securityModel.getMainGridHeight() + "px";
    }

    public String getPodsSecurityPoliciesGridHeight() {
        return securityModel.getMainGridHeight() + "px";
    }

    public boolean isSkipKubeNamespaces() {
        return securityModel.isSkipKubeNamespaces();
    }

    public void setSkipKubeNamespaces(boolean skipKubeNamespaces) {
        securityModel.setSkipKubeNamespaces(skipKubeNamespaces);
    }

}
