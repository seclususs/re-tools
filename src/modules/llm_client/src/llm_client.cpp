#include "llm_client.h"
#include "utils.h"

LLMClient::LLMClient(const std::string& key) : apiKey(key) {
    Utils::logInfo("[LLMClient] Initializing client.");
    // Stub: Initialize network library (e.g., curl_global_init)
}

std::string LLMClient::sendPrompt(const std::string& prompt) {
    Utils::logInfo("[LLMClient] Sending prompt...");
    // Stub implementation
    // In a real app, this would make an HTTPS POST request
    // e.g., using cpr::Post(...) or libcurl
    
    // Simulate a network delay and response
    // std::this_thread::sleep_for(std::chrono::seconds(1)); 
    
    std::string dummyResponse = R"({
        "id": "chatcmpl-123",
        "object": "chat.completion",
        "created": 1677652288,
        "model": "gpt-3.5-turbo",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "This function appears to be a simple C function prologue and epilogue. It sets up a stack frame (push rbp; mov rbp, rsp) and then immediately tears it down (pop rbp; ret). It likely does nothing useful."
            },
            "finish_reason": "stop"
        }]
    })";

    return parseResponse(dummyResponse);
}

std::string LLMClient::parseResponse(const std::string& response) {
    // Stub implementation
    // Use a JSON library (e.g., nlohmann-json)
    // return json::parse(response)["choices"][0]["message"]["content"];
    
    // Simple string search for the dummy data
    std::string contentKey = R"("content": ")";
    size_t start = response.find(contentKey);
    if (start == std::string::npos) {
        return "Error: Could not parse response.";
    }
    start += contentKey.length();
    
    size_t end = response.find("\"", start);
    if (end == std::string::npos) {
        return "Error: Could not parse response.";
    }
    
    return response.substr(start, end - start);
}