chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
        console.log('Request details:', details);
        
        // Check if the request URL matches the desired endpoint (API for messages)
        if (details.url === 'https://chatgpt.com/backend-api/conversation' && details.method === 'POST') {
            
            const requestBody = details.requestBody;
            if (requestBody && requestBody.raw) {
                // Combine and parse raw data into a JSON string
                const rawData = requestBody.raw.map(part => String.fromCharCode.apply(null, new Uint8Array(part.bytes))).join('');
                try {
                    const payload = JSON.parse(rawData);
                    console.log('Captured Payload:', payload);

                    // Check if messages exist in the payload
                    if (payload.messages && payload.messages.length > 0) {
                        const userMessages = payload.messages
                            .filter(msg => msg.author.role === 'user')  // Filter only user messages
                            .map(msg => msg.content.parts[0]);  // Extract the message content
                        console.log('User Messages:', userMessages);

                        // Fetch student name from Chrome's local storage
                        chrome.storage.local.get('studentName', function(data) {
                            const studentName = data.studentName || 'Unknown';  // Default to 'Unknown' if not found

                            // Send the log data to the server
                            fetch('http://192.168.20.55:5000/api/log', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json'
                                },
                                body: JSON.stringify({
                                    studentName: studentName,
                                    url: details.url,
                                    timestamp: new Date().toISOString(),
                                    method: details.method,
                                    userMessages: userMessages
                                })
                            }).catch(error => console.error('Error sending log:', error));
                        });
                    }
                } catch (e) {
                    console.error('Error parsing payload:', e);
                }
            }
        }
    },
    {urls: ["*://chatgpt.com/backend-api/conversation"]},
    ['requestBody']
);

// Event listener for page updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete') {
        const logData = {
            url: tab.url,
            timestamp: new Date().toISOString(),
            action: "Page Visit"
        };

        // Send page visit logs to the server
        fetch('http://192.168.20.55:5000/api/log', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(logData)
        }).catch(error => console.error('Error sending log:', error));
    }
});
