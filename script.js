async function checkURL() {

    const url = document.getElementById("urlInput").value;
    const result = document.getElementById("result");

    if (url === "") {
        result.innerHTML = "Please enter a URL.";
        return;
    }

    result.innerHTML = `
    <div class="scanning">
        <div class="scan-title">[ SCANNING... ]</div>
        <div class="scan-text">ANALYZING URL SECURITY</div>
        <div class="scan-bar">
            <div class="scan-progress"></div>
        </div>
        <div class="scan-status">
            CONNECTING TO SECURITY ENGINES...
        </div>
    </div>
`;

    try {

        const response = await fetch("/api/analyze-url", {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url
            })
        });

        const data = await response.json();

if (data.error) {
    result.innerHTML = "❌ " + data.error;
    return;
}

        let riskClass = "";

if (data.riskLevel === "Potentially Malicious") {
    riskClass = "danger";
}
else if (data.riskLevel === "Suspicious") {
    riskClass = "warning";
}
else if (data.riskLevel === "Analysis In Progress") {
    riskClass = "scanning";
}
else {
    riskClass = "safe";
}

        let aiResult = data.result;

aiResult = aiResult.replace(
    /^Risk Level:.*$/m,
    ""
);

result.innerHTML = `
    <div class="risk-box ${riskClass}">
        <h2>Risk Level: ${data.riskLevel}</h2>

        ${
            data.riskScore !== null &&
            data.riskScore !== undefined
            ? `<p>📊 Our Risk Score: ${data.riskScore}/100</p>`
            : `<p>⏳ Risk Score: Not available yet</p>`
        }
    </div>

    <pre>${aiResult}</pre>
`;

    } catch (error) {

        console.error(error);

        result.innerHTML =
            "❌ Could not connect to the server.";
    }
}