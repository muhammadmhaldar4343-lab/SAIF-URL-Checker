const express = require("express");
const axios = require("axios");
const OpenAI = require("openai");
require("dotenv").config();

const app = express();

app.use(express.json());
app.use(express.static("."));

const client = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
});

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;


// ================================
// VERIFY URL
// ================================

app.post("/analyze-url", async (req, res) => {

    try {

        const { url } = req.body;

        if (!url) {
            return res.status(400).json({
                error: "URL is required."
            });
        }


        // -------------------------------
        // 1. Send URL to VirusTotal
        // -------------------------------

        const formData = new URLSearchParams();

        formData.append("url", url);

        const scanResponse = await axios.post(
            "https://www.virustotal.com/api/v3/urls",
            formData,
            {
                headers: {
                    "x-apikey": VIRUSTOTAL_API_KEY,
                    "Content-Type": "application/x-www-form-urlencoded"
                }
            }
        );


        const analysisId =
            scanResponse.data.data.id;


        // -------------------------------
        // 2. Wait for VirusTotal analysis
        // -------------------------------

        let analysis;
let analysisCompleted = false;

for (let i = 0; i < 12; i++) {

    await new Promise(resolve =>
        setTimeout(resolve, 5000)
    );

    const analysisResponse = await axios.get(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        {
            headers: {
                "x-apikey": VIRUSTOTAL_API_KEY
            }
        }
    );

    analysis = analysisResponse.data.data;

    if (analysis.attributes.status === "completed") {

        analysisCompleted = true;

        break;
    }
}


        // -------------------------------
        // 3. Get security statistics
        // -------------------------------

        const stats =
            analysis.attributes.stats || {};


        const malicious =
            stats.malicious || 0;

        const suspicious =
            stats.suspicious || 0;

        const harmless =
            stats.harmless || 0;

        const undetected =
    stats.undetected || 0;

// Our custom risk score
let riskScore = 0;

riskScore += malicious * 25;
riskScore += suspicious * 15;

if (riskScore > 100) {
    riskScore = 100;
}
let riskLevel;

if (!analysisCompleted) {
    riskLevel = "Analysis In Progress";
} else if (riskScore >= 60) {
    riskLevel = "Potentially Malicious";
} else if (riskScore >= 20) {
    riskLevel = "Suspicious";
} else {
    riskLevel = "No Current Detections";
}
        const findings = `
VirusTotal results:

Risk Level: ${riskLevel}
Our Risk Score: ${
    analysisCompleted ? `${riskScore}/100` : "Not available yet"
}

Malicious detections: ${malicious}
Suspicious detections: ${suspicious}
Harmless detections: ${harmless}
Undetected: ${undetected}

Analysis status:
${analysis.attributes.status}

Analysis completed:
${analysisCompleted}
`;


        // -------------------------------
        // 4. Ask AI to explain the results
        // -------------------------------

        const prompt = `
You are a cybersecurity URL-analysis assistant.

Analyze the URL using ONLY the VirusTotal
security findings provided below.

URL:
${url}

VirusTotal findings:
${findings}

Give the result in this format:

Risk Level:
Explanation:
Security Findings:
Recommendation:

Important rules:

- Do not invent security results.
- The Risk Level shown in the VirusTotal findings is calculated by the application.
- Copy that Risk Level exactly into the "Risk Level:" section of your response.
- Do not replace it with "Not provided" or create a different risk level.
- Do not claim a URL is definitely safe.
- Explain that VirusTotal results are evidence,
  not an absolute guarantee of safety.
- If malicious detections are greater than 0,
  clearly mention that.
- If suspicious detections are greater than 0,
  clearly mention that.
If the analysis is not completed, clearly state:
"VirusTotal analysis is still in progress."

The application calculates its own custom risk score using the VirusTotal findings.
The risk score is NOT a VirusTotal score.
When mentioning the score, call it "Our Risk Score" or "Application Risk Score".
Do not claim that VirusTotal calculated the score.
- Do not present partial results as final results.
`;


        const response =
            await client.responses.create({

                model: "gpt-6-luna",

                input: prompt

            });


        // -------------------------------
        // 5. Send result back to website
        // -------------------------------

        res.json({

    result: response.output_text,

    riskLevel: riskLevel,
riskScore: riskScore,
    virusTotal: {
                malicious,
                suspicious,
                harmless,
                undetected,
                status:
                    analysis.attributes.status
            }

        });


    } catch (error) {

        console.error(error);

        res.status(500).json({

            error:
                "URL security analysis failed."

        });

    }

});


// ================================
// START SERVER
// ================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {

    console.log(
        `SAIF URL Checker running on port ${PORT}`
    );

});