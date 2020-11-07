package com.kubehelper.viewmodels;

import com.kubehelper.common.Global;
import com.kubehelper.domain.models.PageModel;
import com.kubehelper.services.CommonService;
import org.zkoss.bind.BindUtils;
import org.zkoss.bind.annotation.BindingParam;
import org.zkoss.bind.annotation.Command;
import org.zkoss.bind.annotation.Init;
import org.zkoss.zk.ui.Executions;
import org.zkoss.zk.ui.Path;
import org.zkoss.zk.ui.event.ClientInfoEvent;
import org.zkoss.zk.ui.select.annotation.VariableResolver;
import org.zkoss.zk.ui.select.annotation.Wire;
import org.zkoss.zk.ui.select.annotation.WireVariable;
import org.zkoss.zkplus.spring.DelegatingVariableResolver;
import org.zkoss.zul.Toolbarbutton;
import org.zkoss.zul.Window;

import java.util.Map;

/**
 * @author JDev
 */
@VariableResolver(DelegatingVariableResolver.class)
public class IndexVM {

    private PageModel pageModel;
    private String currentModelName;

    @WireVariable
    private CommonService commonService;

    @Command
    public void onClientInfoEvent(ClientInfoEvent evt) {
        pageModel.setDesktopWithAndHeight(evt.getDesktopWidth(), evt.getDesktopHeight());
        BindUtils.postGlobalCommand(null, null, "updateHeightsAndRerenderVM", Map.of("eventType", "onClientInfo"));
    }

    @Init
    public void init() {
//        pageModel = new DashboardModel();
//        pageModel = new SearchModel();
//        pageModel = Global.ACTIVE_MODELS.computeIfAbsent(Global.IPS_AND_PORTS_MODEL, (k) -> Global.NEW_MODELS.get(Global.IPS_AND_PORTS_MODEL));
        pageModel = Global.ACTIVE_MODELS.computeIfAbsent(Global.SEARCH_MODEL, (k) -> Global.NEW_MODELS.get(Global.SEARCH_MODEL));
        currentModelName = pageModel.getName();
    }

    public PageModel getPageModel() {
        return pageModel;
    }

    @Command()
    public void switchView(@BindingParam("modelName") String modelName) {
        pageModel = Global.ACTIVE_MODELS.computeIfAbsent(modelName, (k) -> Global.NEW_MODELS.get(modelName));
        enableDisableMenuItem(modelName);
        BindUtils.postNotifyChange(null, null, this, ".");
    }

    @Command()
    public void contactDeveloper() {
        Window window = (Window) Executions.createComponents("~./zul/components/contact.zul", null, null);
        window.doModal();
    }

    private void enableDisableMenuItem(String modelName) {
        Toolbarbutton clickedMenuBtn = (Toolbarbutton) Path.getComponent("//indexPage/" + modelName + "MenuBtn");
        Toolbarbutton currentMenuBtn = (Toolbarbutton) Path.getComponent("//indexPage/" + currentModelName + "MenuBtn");
        clickedMenuBtn.setDisabled(true);
        currentMenuBtn.setDisabled(false);
        currentModelName = modelName;
    }
}