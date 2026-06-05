"use strict";
/*
 * Slim adapter for the OASIS cti-stix-visualization library.
 * This version auto-loads a STIX bundle from the `?bundle_url=` query
 * parameter instead of showing the file-upload / paste UI.
 *
 * All sidebar, legend, connections and timeline logic is preserved from
 * the original application.js.
 */
require.config({
    paths: {
        "nbextensions/stix2viz/vis-network": "stix2viz/visjs/vis-network.min"
    }
});

require(["domReady!", "stix2viz/stix2viz/stix2viz"], function (document, stix2viz) {

    // ------------------------------------------------------------------ //
    //  State
    // ------------------------------------------------------------------ //
    let view = null;
    let canvasContainer = document.getElementById("canvas-container");
    let canvas           = document.getElementById("canvas");
    let loadingEl        = document.getElementById("loading");
    let errorEl          = document.getElementById("error-msg");
    let timelineVersions      = null;
    let cumulativeIdGroups    = null;
    let nonCumulativeIdGroups = null;

    // ------------------------------------------------------------------ //
    //  Helpers
    // ------------------------------------------------------------------ //
    function alertException(exc, initialMessage) {
        let messages = [];
        if (initialMessage) messages.push(initialMessage);
        messages.push(exc.toString());
        while (exc instanceof Error && exc.cause) {
            exc = exc.cause;
            messages.push(exc.toString());
        }
        showError(messages.join("\n\nCaused by:\n\n"));
    }

    function showError(msg) {
        if (loadingEl)  loadingEl.style.display  = "none";
        if (errorEl)    { errorEl.textContent = msg; errorEl.style.display = "block"; }
        else            alert(msg);
    }

    // ------------------------------------------------------------------ //
    //  Graph click handlers
    // ------------------------------------------------------------------ //
    function graphViewClickHandler(event, edgeDataSet, stixIdToObject) {
        if (event.nodes.length > 0) {
            let stixObject = stixIdToObject.get(event.nodes[0]);
            if (stixObject) populateSelected(stixObject, edgeDataSet, stixIdToObject);
        } else if (event.edges.length > 0) {
            let stixRel = stixIdToObject.get(event.edges[0]);
            if (stixRel)
                populateSelected(stixRel, edgeDataSet, stixIdToObject);
            else
                populateSelected(new Map([["", "(Embedded relationship)"]]), edgeDataSet, stixIdToObject);
        }
    }

    function listViewClickHandler(event, edgeDataSet, stixIdToObject) {
        let clickedItem = event.target;
        if (clickedItem.tagName === "LI") {
            let stixId     = clickedItem.id;
            let stixObject = stixIdToObject.get(stixId);
            view.selectNode(stixId);
            if (stixObject)
                populateSelected(stixObject, edgeDataSet, stixIdToObject);
            else
                populateSelected(new Map([["", "(Embedded relationship)"]]), edgeDataSet, stixIdToObject);
        }
    }

    // ------------------------------------------------------------------ //
    //  Main visualisation entry point
    // ------------------------------------------------------------------ //
    function vizStixWrapper(content) {
        let customConfig = { iconDir: "stix2viz/stix2viz/icons" };

        if (loadingEl) loadingEl.style.display = "none";
        canvasContainer.style.display = "block";

        try {
            let [nodeDataSet, edgeDataSet, stixIdToObject]
                = stix2viz.makeGraphData(content, customConfig);

            [timelineVersions, cumulativeIdGroups, nonCumulativeIdGroups]
                = makeTimelineGroups(nodeDataSet);

            let wantsList = false;
            if (nodeDataSet.length > 200)
                wantsList = confirm(
                    "This graph contains " + nodeDataSet.length +
                    " nodes.  Display as a list?"
                );

            if (wantsList) {
                view = stix2viz.makeListView(
                    canvas, nodeDataSet, edgeDataSet, stixIdToObject, customConfig
                );
                view.on("click", e => listViewClickHandler(e, edgeDataSet, stixIdToObject));
            } else {
                view = stix2viz.makeGraphView(
                    canvas, nodeDataSet, edgeDataSet, stixIdToObject, customConfig
                );
                view.on("click", e => graphViewClickHandler(e, edgeDataSet, stixIdToObject));
            }

            setupTimelineSlider(timelineVersions);
            populateLegend(...view.legendData);
        } catch (err) {
            console.error(err);
            alertException(err);
        }
    }

    // ------------------------------------------------------------------ //
    //  Timeline helpers
    // ------------------------------------------------------------------ //
    function makeTimelineGroups(nodeDataSet) {
        let distinctVersions = nodeDataSet.distinct("version");
        let idxNull = distinctVersions.indexOf(null);
        if (idxNull > -1) distinctVersions.splice(idxNull, 1);
        distinctVersions.sort((d1, d2) => d1 - d2);

        let cumulativeIdGroups    = [];
        let nonCumulativeIdGroups = [];
        for (let _ of distinctVersions) {
            cumulativeIdGroups.push(new Set());
            nonCumulativeIdGroups.push(new Set());
        }

        nodeDataSet.forEach(function (item) {
            let firstGroup = 0;
            if (item.version !== null) firstGroup = distinctVersions.indexOf(item.version);
            for (let i = firstGroup; i < distinctVersions.length; i++)
                cumulativeIdGroups[i].add(item.id);
            nonCumulativeIdGroups[firstGroup].add(item.id);
        });

        return [distinctVersions, cumulativeIdGroups, nonCumulativeIdGroups];
    }

    function setTimelineSliderLabelFor(sliderValue) {
        let slider      = document.getElementById("timeline");
        let sliderLabel = slider.labels.item(0);
        let selectedVersion = timelineVersions[sliderValue];
        sliderLabel.textContent = "Timeline: " + new Date(selectedVersion).toISOString();
    }

    function setupTimelineSlider(versions) {
        let slider   = document.getElementById("timeline");
        let checkbox = document.getElementById("timelineCheckbox");
        if (versions.length < 1) return;
        slider.min   = 0;
        slider.max   = versions.length - 1;
        slider.value = slider.max;
        slider.disabled   = false;
        checkbox.disabled = false;
        setTimelineSliderLabelFor(slider.value);
    }

    function setVisibilityForTimeline() {
        let timelineSlider   = document.getElementById("timeline");
        let timelineCheckbox = document.getElementById("timelineCheckbox");
        let sliderValue = timelineSlider.value;
        let cumulative  = timelineCheckbox.checked;
        let idGroups    = cumulative ? cumulativeIdGroups : nonCumulativeIdGroups;
        setTimelineSliderLabelFor(sliderValue);
        view.setVisible(idGroups[sliderValue]);
    }

    function sliderChangeHandler(event) {
        event.stopPropagation();
        setVisibilityForTimeline();
    }

    // ------------------------------------------------------------------ //
    //  Legend
    // ------------------------------------------------------------------ //
    function legendClickHandler(event) {
        if (!view) return;
        let td;
        let tag = event.target.tagName.toLowerCase();
        if (tag === "td")        td = event.target;
        else if (tag === "img")  td = event.target.parentElement;
        else return;
        view.toggleStixType(td.textContent.trim().toLowerCase());
        td.classList.toggle("typeHidden");
    }

    function populateLegend(iconURLMap, defaultIconURL) {
        let table = document.getElementById("legend-content");
        let tbody;
        if (table.tBodies.length === 0) tbody = table.createTBody();
        else tbody = table.tBodies[0];
        tbody.replaceChildren();

        let tr = tbody.insertRow();
        let colIdx = 0;

        for (let [stixType, iconURL] of iconURLMap) {
            let img  = document.createElement("img");
            img.onerror = function () { this.src = defaultIconURL; this.width = 37; this.height = 37; };
            img.src = iconURL;

            if (colIdx > 1) { colIdx = 0; tr = tbody.insertRow(); }
            let td = tr.insertCell();
            ++colIdx;
            td.append(img);
            td.append(stixType.charAt(0).toUpperCase() + stixType.slice(1));
        }
    }

    // ------------------------------------------------------------------ //
    //  Selected-node rendering (full port from application.js)
    // ------------------------------------------------------------------ //
    function stixArrayContentToDOMNodes(arrayContent, edgeDataSet, stixIdToObject, isRefs) {
        let nodes = [];
        let ol = document.createElement("ol");
        ol.className = "selected-object-list";
        for (let elt of arrayContent) {
            let contentNodes = isRefs
                ? stixStringContentToDOMNodes(elt, edgeDataSet, stixIdToObject, true)
                : stixContentToDOMNodes(elt, edgeDataSet, stixIdToObject);
            let li = document.createElement("li");
            li.append(...contentNodes);
            ol.append(li);
        }
        nodes.push(document.createTextNode("["));
        nodes.push(ol);
        nodes.push(document.createTextNode("]"));
        return nodes;
    }

    function stixObjectContentToDOMNodes(objectContent, edgeDataSet, stixIdToObject, topLevel) {
        let nodes = [];
        if (!topLevel) nodes.push(document.createTextNode("{"));
        for (let [propName, propValue] of objectContent) {
            let propNameSpan = document.createElement("span");
            propNameSpan.className = "selected-object-prop-name";
            propNameSpan.append(propName + ":");

            let contentNodes;
            if (propName.endsWith("_ref"))
                contentNodes = stixStringContentToDOMNodes(propValue, edgeDataSet, stixIdToObject, true);
            else if (propName.endsWith("_refs"))
                contentNodes = stixArrayContentToDOMNodes(propValue, edgeDataSet, stixIdToObject, true);
            else
                contentNodes = stixContentToDOMNodes(propValue, edgeDataSet, stixIdToObject);

            let propDiv = document.createElement("div");
            propDiv.append(propNameSpan, ...contentNodes);
            if (!topLevel) propDiv.className = "selected-object-object-content";
            nodes.push(propDiv);
        }
        if (!topLevel) nodes.push(document.createTextNode("}"));
        return nodes;
    }

    function stixStringContentToDOMNodes(stringContent, edgeDataSet, stixIdToObject, isRef) {
        let span = document.createElement("span");
        span.append(stringContent);
        if (isRef) {
            let referentObj = stixIdToObject.get(stringContent);
            if (referentObj) {
                span.className = "selected-object-text-value-ref";
                span.addEventListener("click", e => {
                    e.stopPropagation();
                    view.selectNode(referentObj.get("id"));
                    populateSelected(referentObj, edgeDataSet, stixIdToObject);
                });
            } else {
                span.className = "selected-object-text-value-ref-dangling";
            }
        } else {
            span.className = "selected-object-text-value";
        }
        return [span];
    }

    function stixOtherContentToDOMNodes(otherContent) {
        let span = document.createElement("span");
        span.append(
            otherContent === null      ? "null" :
            otherContent === undefined ? "undefined" :
            otherContent.toString()
        );
        span.className = "selected-object-nontext-value";
        return [span];
    }

    function stixContentToDOMNodes(stixContent, edgeDataSet, stixIdToObject) {
        if (stixContent instanceof Map)
            return stixObjectContentToDOMNodes(stixContent, edgeDataSet, stixIdToObject);
        if (Array.isArray(stixContent))
            return stixArrayContentToDOMNodes(stixContent, edgeDataSet, stixIdToObject);
        if (typeof stixContent === "string" || stixContent instanceof String)
            return stixStringContentToDOMNodes(stixContent, edgeDataSet, stixIdToObject);
        return stixOtherContentToDOMNodes(stixContent);
    }

    function populateConnections(stixObject, edgeDataSet, stixIdToObject) {
        let objId = stixObject.get("id");
        let edges = edgeDataSet.get({ filter: item => item.from === objId || item.to === objId });

        let eltIn  = document.getElementById("connections-incoming");
        let eltOut = document.getElementById("connections-outgoing");
        eltIn.replaceChildren();
        eltOut.replaceChildren();

        let listIn  = document.createElement("ol");
        let listOut = document.createElement("ol");
        eltIn.append(listIn);
        eltOut.append(listOut);

        for (let edge of edges) {
            let targetList;
            let summaryNode  = document.createElement("summary");
            let otherEndSpan = document.createElement("span");
            let otherEndObj;

            if (objId === edge.from) {
                otherEndObj = stixIdToObject.get(edge.to);
                otherEndSpan.append(otherEndObj.get("type"));
                summaryNode.append(edge.label + " ", otherEndSpan);
                targetList = listOut;
            } else {
                otherEndObj = stixIdToObject.get(edge.from);
                otherEndSpan.append(otherEndObj.get("type"));
                summaryNode.append(otherEndSpan, " " + edge.label);
                targetList = listIn;
            }

            otherEndSpan.className = "selected-object-text-value-ref";
            otherEndSpan.addEventListener("click", e => {
                view.selectNode(otherEndObj.get("id"));
                populateSelected(otherEndObj, edgeDataSet, stixIdToObject);
            });

            let li          = document.createElement("li");
            let detailsNode = document.createElement("details");
            let objNodes    = stixObjectContentToDOMNodes(otherEndObj, edgeDataSet, stixIdToObject, true);
            detailsNode.append(summaryNode, ...objNodes);
            li.append(detailsNode);
            targetList.append(li);
        }
    }

    function populateSelected(stixObject, edgeDataSet, stixIdToObject) {
        let selectedContainer = document.getElementById("selection");
        selectedContainer.replaceChildren();
        let contentNodes = stixObjectContentToDOMNodes(stixObject, edgeDataSet, stixIdToObject, true);
        selectedContainer.append(...contentNodes);
        populateConnections(stixObject, edgeDataSet, stixIdToObject);
    }

    // ------------------------------------------------------------------ //
    //  Selected-node expand / collapse on click
    // ------------------------------------------------------------------ //
    function selectedNodeClick() {
        let selected = document.getElementById("selected");
        if (!selected.classList.contains("clicked")) {
            selected.classList.add("clicked");
            selected.style.position = "absolute";
            selected.style.left = "25px";
            selected.style.width = (window.innerWidth - 110) + "px";
            selected.style.top  = (document.getElementById("canvas").offsetHeight + 25) + "px";
            selected.scrollIntoView(true);
        } else {
            selected.classList.remove("clicked");
            selected.removeAttribute("style");
        }
    }

    // ------------------------------------------------------------------ //
    //  Auto-fetch from ?bundle_url= query parameter
    // ------------------------------------------------------------------ //
    function fetchBundleFromParam() {
        let params    = new URLSearchParams(window.location.search);
        let bundleUrl = params.get("bundle_url");

        if (!bundleUrl) {
            showError("No bundle_url parameter provided.");
            return;
        }

        if (loadingEl) loadingEl.style.display = "flex";

        fetch(bundleUrl)
            .then(function (resp) {
                if (!resp.ok) throw new Error("HTTP " + resp.status + " – " + resp.statusText);
                return resp.text();
            })
            .then(function (content) {
                vizStixWrapper(content);
            })
            .catch(function (err) {
                showError("Failed to load STIX bundle:\n" + err.message);
            });
    }

    // ------------------------------------------------------------------ //
    //  Event bindings
    // ------------------------------------------------------------------ //
    document.getElementById("selected")
        .addEventListener("click", selectedNodeClick, false);
    document.getElementById("legend")
        .addEventListener("click", legendClickHandler, { capture: true });
    document.getElementById("timeline")
        .addEventListener("input", sliderChangeHandler, false);
    document.getElementById("timelineCheckbox")
        .addEventListener("change", sliderChangeHandler, false);

    // ------------------------------------------------------------------ //
    //  Bootstrap
    // ------------------------------------------------------------------ //
    fetchBundleFromParam();
});
