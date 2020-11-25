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
package com.kubehelper.domain.filters;

import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * @author JDev
 */
public class FeaturesFilter {
    private String description = "", group = "", command = "";

    private String selectedGroupFilter = "";

    private List<String> groupsFilter = new ArrayList<>();

    public FeaturesFilter() {
    }

    public void addGroupFilter(String groupFilter) {
        if (!groupsFilter.contains(groupFilter)) {
            groupsFilter.add(groupFilter);
        }
    }

    public boolean isFilterActive() {
        return StringUtils.isNoneBlank(description, group, command, selectedGroupFilter);
    }

    public String getDescription() {
        return description;
    }

    public FeaturesFilter setDescription(String description) {
        this.description = description == null ? "" : description;
        return this;
    }

    public String getGroup() {
        return group;
    }

    public FeaturesFilter setGroup(String group) {
        this.group = group;
        return this;
    }

    public String getCommand() {
        return command;
    }

    public FeaturesFilter setCommand(String command) {
        this.command = command == null ? "" : command;
        return this;
    }

    public String getSelectedGroupFilter() {
        return selectedGroupFilter;
    }

    public FeaturesFilter setSelectedGroupFilter(String selectedGroupFilter) {
        this.selectedGroupFilter = selectedGroupFilter == null ? "" : selectedGroupFilter;
        return this;
    }

    public List<String> getGroupsFilter() {
        return groupsFilter;
    }

}