#pragma once

#include <string>


using AnalysisData = std::string; 

class Reporter {
public:
    Reporter(const std::string& baseName);

    /**
     * @brief Sets the analysis data to be reported.
     */
    void setData(const AnalysisData& data);

    /**
     * @brief Prints a summary to the standard output (CLI).
     */
    void printCLI();

    /**
     * @brief Exports the full analysis to a JSON file.
     * @return True on success, false on failure.
     */
    bool exportJSON();

    /**
     * @brief Exports the full analysis to an HTML report.
     * @return True on success, false on failure.
     */
    bool exportHTML();

private:
    std::string outputPathBase; // e.g., "report"
    AnalysisData analysisData;
};