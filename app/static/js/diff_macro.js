export function createSimpleDiffLines(oldText, newText) {
    // Normaliser les retours chariots et retirer les espaces de fin
    oldText = oldText.replace(/\r\n/g, "\n");
    newText = newText.replace(/\r\n/g, "\n");

    const oldLines = oldText.split("\n").map(l => l.replace(/\s+$/,''));
    const newLines = newText.split("\n").map(l => l.replace(/\s+$/,''));

    let diffLines = "";
    const max = Math.max(oldLines.length, newLines.length);

    for (let i = 0; i < max; i++) {
        const oldLine = oldLines[i] ?? "";
        const newLine = newLines[i] ?? "";

        // Comparaison en ignorant les espaces de début/fin
        if (oldLine === newLine) {
            diffLines += " " + oldLine + "\n";
        } else {
            if (oldLine !== "") diffLines += "-" + oldLine + "\n";
            if (newLine !== "") diffLines += "+" + newLine + "\n";
        }
    }

    let diff = "";
    diff += "--- a/simplifié\n";
    diff += "+++ b/simplifié\n";
    diff += `@@ -1,${oldLines.length} +1,${newLines.length} @@\n`;
    diff += diffLines;

    return diff;
}

export function renderDiff(oldText, newText, elementId = "myDiffElement", diffType = "twoText") {
    const diff = createSimpleDiffLines(oldText, newText);

    const config = {
        outputFormat: diffType === "oneText" ? "line-by-line" : "side-by-side",
        drawFileList: false,
        matching: "lines",
        synchronisedScroll: true,
        highlight: true,
        renderNothingWhenEmpty: false,
    };

    const target = document.getElementById(elementId);
    if (!target) return console.error("Element not found:", elementId);

    target.innerHTML = "";
    target.classList.add("simple-diff-view");

    const diff2htmlUi = new Diff2HtmlUI(target, diff, config);
    diff2htmlUi.draw();
    diff2htmlUi.highlightCode();
}
