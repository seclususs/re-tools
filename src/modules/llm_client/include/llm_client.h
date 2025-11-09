#pragma once

#include <string>

class LLMClient {
public:
    LLMClient(const std::string& key);
    
    /**
     * @brief Sends a prompt to the configured LLM API.
     * @param prompt The prompt to send.
     * @return The text response from the LLM.
     */
    std::string sendPrompt(const std::string& prompt);

    /**
     * @brief Parses the JSON response from the LLM.
     * @param response The raw JSON response.
     * @return The extracted text content.
     */
    std::string parseResponse(const std::string& response);

private:
    std::string apiKey;
    std::string apiUrl = "https://api.example.com/v1/chat/completions";
    
    // Handle for a network library like cpr or libcurl
    // void* curl_handle; 
};