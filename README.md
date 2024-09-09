# Student Activity Logger

This project is a Chrome extension and Flask-based server designed to monitor and log students' web activity, particularly focusing on detecting usage of ChatGPT during exams. It captures web requests made to specific URLs, stores the student's name along with their activity in a local database for review, and keeps the logging discreet.

## Features
- **Real-time Monitoring**: Captures and logs web requests made to ChatGPT-related URLs.
- **Student Identification**: Logs the student's name (stored in the browser's local storage) along with their activity.
- **Server-Side Logging**: Logs data to a Flask server with an SQLite database for easy retrieval and analysis.
- **Action Identification**: Categorizes different types of actions based on the URL accessed.
- **Page Visit Logging**: Records when a student visits a page, adding an extra layer of monitoring.

## Installation

### Chrome Extension
1. Clone the repository:
    ```bash
    git clone https://github.com/ilyeshr2/student-activity-logger-anti-chatGPT-cheating.git
    ```
2. Navigate to `chrome-extension/` and load the extension:
    - Open Chrome and go to `chrome://extensions/`.
    - Enable "Developer mode" in the top right corner.
    - Click "Load unpacked" and select the `chrome-extension/` directory.

3. Configure the Extension: VERY IMPORTANT:
    - When you install the extension on a student's browser, 
    you will navigate to the extension options page by right-clicking on the extension icon in the Chrome toolbar and selecting "Options."
    - You will manually enter the student's name in the field and save it. After saving, the extension will automatically include the student's name with each log sent to the server.

### Flask Server
1. Create a virtual environment and activate it:
    ```bash
    python3 -m venv venv
    venv\Scripts\activate
    ```
2. Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```
3. Navigate to the server directory:
    ```bash
    cd flaskserver/
    ```
4. Run the Flask server:
    ```bash
    python app.py
    ```
    The server will be running at `http://localhost:5000`.

## Usage
Once the Chrome extension is installed and the Flask server is running, the extension will start logging web activity related to ChatGPT. You can view logged data by navigating to:

`http://localhost:5000/view_logs`

or you can use the admine dashboard at:

`http://localhost:5000/admin`

## Configuration
- **Monitoring URLs**: By default, the extension monitors `https://chatgpt.com/`. You can customize this URL in the `background.js` file under the `urls` array.
- **Database**: The server uses an SQLite database (`activity_logs.db`) to store logs. The database is initialized automatically when the server first runs.

## Security Considerations
- **Privacy**: Ensure that all users are informed about the monitoring, and that you comply with applicable privacy laws and policies.
- **CORS**: The server is configured with CORS enabled for all origins. Modify this setting if you deploy the server in a production environment to restrict access.

## Contributions
Contributions are welcome! Please fork the repository and submit a pull request with your improvements or bug fixes.

## License
This project is licensed under the MIT License.

## Acknowledgments
- **Flask**: [Flask Documentation](https://flask.palletsprojects.com/)
- **Chrome Extensions**: [Chrome Extensions Documentation](https://developer.chrome.com/docs/extensions/)
