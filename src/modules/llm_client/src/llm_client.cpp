#include "llm_client.h"
#include "utils.h"

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>


using json = nlohmann::json;

LLMClient::LLMClient(const std::string& key) : apiKey(key) {
    Utils::logInfo("[LLMClient] Initializing client.");
}

std::string LLMClient::sendPrompt(const std::string& prompt) {
    Utils::logInfo("[LLMClient] Sending prompt to API: " + apiUrl);

    // JSON body for the API
    json requestBody;
    std::string fullPrompt = "You are a reverse engineering assistant analyzing assembly code. "
                             "Provide a summary of the function's purpose and identify "
                             "potential vulnerabilities.\n\n" + prompt;

    requestBody["contents"] = json::array({
        {
            {"parts", json::array({
                {{"text", fullPrompt}}
            })}
        }
    });

    // Add safety settings.
    requestBody["safetySettings"] = json::array({
        {{"category", "HARM_CATEGORY_HARASSMENT"}, {"threshold", "BLOCK_NONE"}},
        {{"category", "HARM_CATEGORY_HATE_SPEECH"}, {"threshold", "BLOCK_NONE"}},
        {{"category", "HARM_CATEGORY_SEXUALLY_EXPLICIT"}, {"threshold", "BLOCK_NONE"}},
        {{"category", "HARM_CATEGORY_DANGEROUS_CONTENT"}, {"threshold", "BLOCK_NONE"}}
    });

    std::string requestBodyStr = requestBody.dump();

    // Send the POST request using cpr
    cpr::Response r = cpr::Post(
        cpr::Url{apiUrl},
        cpr::Header{
            {"Content-Type", "application/json"},
            {"x-goog-api-key", apiKey}
        },
        cpr::Body{requestBodyStr},
        cpr::Timeout{60000} // 60-second timeout
    );

    // Handle the response
    if (r.status_code == 200) {
        Utils::logInfo("[LLMClient] Received successful response (Status " + std::to_string(r.status_code) + ").");
        return parseResponse(r.text);
    } else {
        Utils::logError("[LLMClient] API request failed. Status: " + std::to_string(r.status_code));
        Utils::logError("[LLMClient] Response Body: " + r.text);
        return "Error: API request failed with status " + std::to_string(r.status_code) + ". Response: " + r.text;
    }
}

std::string LLMClient::parseResponse(const std::string& response) {
    try {
        json parsed = json::parse(response);

        // Check for API-level errors
        if (parsed.contains("error") && parsed["error"].is_object()) {
            if (parsed["error"].contains("message")) {
                std::string errorMsg = parsed["error"]["message"].get<std::string>();
                Utils::logError("[LLMClient] API returned an error: " + errorMsg);
                return "Error (from API): " + errorMsg;
            }
        }

        // Navigate the expected Gemini JSON structure
        if (parsed.contains("candidates") && parsed["candidates"].is_array() && !parsed["candidates"].empty()) {
            const auto& firstCandidate = parsed["candidates"][0];

            if (firstCandidate.contains("finishReason") && 
                (firstCandidate["finishReason"] == "SAFETY" || firstCandidate["finishReason"] == "OTHER")) {
                 Utils::logError("[LLMClient] Response blocked. Finish Reason: " + firstCandidate["finishReason"].get<std::string>());
                 return "Error: Response was blocked by API. (Reason: " + firstCandidate["finishReason"].get<std::string>() + ")";
            }

            if (firstCandidate.contains("content") && firstCandidate["content"].is_object()) {
                if (firstCandidate["content"].contains("parts") && firstCandidate["content"]["parts"].is_array() && !firstCandidate["content"]["parts"].empty()) {
                    if (firstCandidate["content"]["parts"][0].contains("text")) {
                        // Extract and return the content
                        return firstCandidate["content"]["parts"][0]["text"].get<std::string>();
                    }
                }
            }
        }

        // Handle unexpected JSON structure
        Utils::logWarning("[LLMClient] Could not parse 'text' from JSON response. Unexpected structure.");
        Utils::logWarning("[LLMClient] Full Response: " + response);
        return "Error: Failed to parse LLM response structure.";

    } catch (json::parse_error& e) {
        Utils::logError("[LLMClient] JSON parse error: " + std::string(e.what()));
        return "Error: Failed to parse JSON response.";
    }
}