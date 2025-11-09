#include "reporting.h"
#include "utils.h"
#include <iostream>

Reporter::Reporter(const std::string& baseName) : outputPathBase(baseName) {
    // Constructor
}

void Reporter::setData(const AnalysisData& data) {
    this->analysisData = data;
}

void Reporter::printCLI() {
    // Stub implementation
    std::cout << "\n--- RE-Tools Analysis ---\n" << std::endl;
    if (analysisData.empty()) {
        std::cout << "(No analysis data provided)" << std::endl;
    } else {
        std::cout << analysisData << std::endl;
    }
    std::cout << "\n--- End of Report ---\n" << std::endl;
}

bool Reporter::exportJSON() {
    // Stub implementation
    std::string filePath = outputPathBase + ".json";
    Utils::logInfo("[Reporter] Exporting JSON to " + filePath);

    // Dummy JSON
    std::string jsonContent = "{\n";
    jsonContent += "  \"analysis_summary\": \"" + analysisData + "\"\n";
    jsonContent += "}\n";

    return Utils::writeFile(filePath, jsonContent);
}

bool Reporter::exportHTML() {
    // Stub implementation
    std::string filePath = outputPathBase + ".html";
    Utils::logInfo("[Reporter] Exporting HTML to " + filePath);

    // Dummy HTML
    std::string htmlContent = "<html><head><title>RE-Tools Report</title></head><body>";
    htmlContent += "<h1>RE-Tools Analysis Report</h1>";
    htmlContent += "<pre>" + analysisData + "</pre>";
    htmlContent += "</body></html>";

    return Utils::writeFile(filePath, htmlContent);
}