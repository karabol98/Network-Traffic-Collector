function formatNumberWithSpaces(value) {
    if (typeof value === "string" && !isNaN(value)) {
        value = Number(value); // Convert to number if it's a numeric string
    }
    if (typeof value === "number") {
        return value.toLocaleString('en-US').replace(/,/g, ' '); // Replace commas with spaces
    }
    return value; // Return as is if not a number
}



async function queryContentLoader() {
    // Get references to the textarea and run button
    const queryInput = document.getElementById("query");
    const runButton = document.getElementById("run-query");

    // Listen for keydown event on the textarea
    queryInput.addEventListener("keydown", async function (e) {
        const box = e.target;
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && queryInput.value.trim() !== "") {
            e.preventDefault(); // Prevent new line from being added
            runButton.click(); // Simulate button click
        }
        if (e.ctrlKey && e.key === 'r') {
          e.preventDefault();
          await handleHistorySearch(box);
        } else if (e.ctrlKey && e.key === 'ArrowUp') {
          e.preventDefault();
          handleHistoryUp(box);
        } else if (e.ctrlKey && e.key === 'ArrowDown') {
          e.preventDefault();
          handleHistoryDown(box);
        }    
    });

    // Listen for click event on the run button
    runButton.addEventListener('click', runQuery);
    // Show or hide custom time range inputs based on the selected option
    document.getElementById('time-range').addEventListener('change', toggleTimeRange);
    // Toggle between Table and JSON view
    document.getElementById('toggle-view').addEventListener('click', toggleView);
    // Set the logout logic
    document.getElementById('logout-link').addEventListener('click', handleLogout);
}

async function handleLogout (e) {
    e.preventDefault(); // Prevent default link behavior
    const token = fetchToken();
    const response = await fetch('/logout', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        }
    });
    if (response.ok) {
        localStorage.removeItem('access_token'); // Clear the token from localStorage
        window.location.href = '/login'; // Redirect to login page
    } else {
        alert('Logout failed, please try again.');
    }
}

async function runQuery(event) {
    event.preventDefault();  // Prevent button's default action

    const query = document.getElementById('query').value;
    const timeRange = document.getElementById('time-range').value;

    // Show the loading spinner and hide the "Run Query" button
    document.getElementById('loading-spinner').style.display = 'block';
    document.getElementById('run-query').style.display = 'none';

    // Prepare the time range (start and end timestamp)
    let startTimestamp, endTimestamp;

    const now = new Date();

    if (timeRange === 'custom') {
        startTimestamp = document.getElementById('start-date').value;
        endTimestamp = document.getElementById('end-date').value;
    } else {
        // Extract the value (e.g., "1h", "7d", "1m")
        const durationValue = timeRange.slice(0, -1);  // Get the number (e.g., "1", "7", "12")
        const durationUnit = timeRange.slice(-1);      // Get the unit (e.g., "h", "d", "m")

        // Calculate the end timestamp (current time)
        endTimestamp = now.toISOString();
        if (timeRange === 'ytd') {
            // Start of the current year
            startTimestamp = new Date(now.getFullYear(), 0, 1).toISOString();
        }else {
            // Subtract the duration from the current time based on the unit
            if (durationUnit === 'h') {
                now.setHours(now.getHours() - durationValue);
            } else if (durationUnit === 'd') {
                now.setDate(now.getDate() - durationValue);
            } else if (durationUnit === 'w') {
                now.setDate(now.getDate() - (durationValue * 7));  // 7 days per week
            } else if (durationUnit === 'm') {
                now.setMonth(now.getMonth() - durationValue);  // Months
            } else if (durationUnit === 'y') {
                now.setYear(now.getFullYear() - durationValue);  // Years
            }
            startTimestamp = now.toISOString();
        }
    }

    // Build the query URL dynamically based on the user inputs and time range
    const queryUrl = `/query?query=${encodeURIComponent(query)}&start=${encodeURIComponent(startTimestamp)}&end=${encodeURIComponent(endTimestamp)}`;
    const start_render = performance.now();

    try {
        // calculate the time taken to execute the query
        const start_query = performance.now();
        // Send the query to the backend API
        const response = await fetch(queryUrl, {
            method: "GET",
            credentials: "include", 
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": `Bearer ${fetchToken()}`
            }});
        if (!response.ok) {
            if (response.status === 401) {
                alert("Session expired. Please log in again.");
                window.location.href = '/login';
            }
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        // calculate the time taken to execute the query
        const end_query = performance.now();

        console.log("Time taken to execute the query: ", end_query - start_query, " milliseconds");

        // Handle the result or display an error
        const resultTable = document.getElementById('result-table');
        const resultBody = resultTable.querySelector('tbody');
        const jsonTable = document.getElementById('json-table');
        const jsonBody = jsonTable.querySelector('tbody');
        const noDataMessage = document.getElementById('no-data-message');
        const additionalInfo = document.getElementById('additional-info');
        const jsonView = document.getElementById('json-view');
        const tableView = document.getElementById('table-view');

        noDataMessage.style.display = 'none';  // Hide no data message by default
        resultBody.innerHTML = '';  // Clear previous results
        jsonBody.innerHTML = '';  // Clear previous JSON

        // reload history
        fetchHistory();

        // Hide the loading spinner and show the "Run Query" button again
        document.getElementById('loading-spinner').style.display = 'none';
        document.getElementById('run-query').style.display = 'inline-block';

        if (data.error) {
            // If there's an error, show it
            noDataMessage.style.display = 'block';
            noDataMessage.textContent = data.error;
            additionalInfo.style.display = 'none';  // Hide additional info
            jsonView.style.display = 'none';
            tableView.style.display = 'none';
            return;
        }

        // Show additional information
        document.getElementById('events-returned').textContent = formatNumberWithSpaces(data.number_of_events_returned);
        document.getElementById('total-events').textContent = formatNumberWithSpaces(data.total_number_of_events);
        document.getElementById('execution-time').textContent = data.execution_time.toFixed(2);

        // Show additional info section
        additionalInfo.style.display = 'block';

        // Display results in table view
        let headers = []
        if (data.result.length > 0) {
            headers = Object.keys(data.result[0]);
            // get the index of header _time
            let timeIndex = headers.indexOf('_time');
            // if _time is present, move it to the first position, unless it is already in the first position
            if (timeIndex > 0) {
                headers.splice(timeIndex, 1);
                headers.unshift('_time');
            }
        }
        const headerRow = resultTable.querySelector('thead tr');
        headerRow.innerHTML = '';  // Clear previous headers

        headers.forEach(header => {
            const th = document.createElement('th');
            th.textContent = header;
            headerRow.appendChild(th);
        });

        const resultFragment = document.createDocumentFragment();
        data.result.forEach(row => {
            const tr = document.createElement('tr');
            headers.forEach(header => {
                const td = document.createElement('td');
                td.textContent = formatNumberWithSpaces(row[header]); // Apply formatting
                // td.textContent = row[header];
                tr.appendChild(td);
            });
            resultFragment.appendChild(tr);
        });
        resultBody.appendChild(resultFragment);


        const jsonFragment = document.createDocumentFragment();
        data.result.forEach((row, index) => {
            const tr = document.createElement('tr');
            const td1 = document.createElement('td');
            td1.textContent = index + 1;  // Row number
            tr.appendChild(td1);

            const td2 = document.createElement('td');
            td2.textContent = JSON.stringify(removeNullValues(row), null, 2);  // Filter null values
            tr.appendChild(td2);

            jsonFragment.appendChild(tr);
        });

        jsonBody.appendChild(jsonFragment);
        tableView.style.display = 'block';
        jsonView.style.display = 'none';  // Hide JSON view

        // If no results were returned, display a "No data available" message
        if (data.result.length === 0) {
            noDataMessage.style.display = 'block';
            noDataMessage.textContent = "No data found for the query.";
        }

    } catch (error) {
        console.error("Error fetching query:", error);
        alert("An error occurred while fetching the query result.");

        // Hide the spinner and show the button again
        document.getElementById('loading-spinner').style.display = 'none';
        document.getElementById('run-query').style.display = 'inline-block';
    }

    requestAnimationFrame(() => {
        // End measuring time after the next frame
        const endTime = performance.now();
        console.log(`Time taken to render HTML: ${(endTime - start_render).toFixed(0)} milliseconds`);
    });
}

function toggleTimeRange() {
    const customTimeRangeDiv = document.getElementById('custom-time-range');
    if (this.value === 'custom') {
        customTimeRangeDiv.style.display = 'block';
    } else {
        customTimeRangeDiv.style.display = 'none';
    }
}

// Remove null values from JSON object
function removeNullValues(obj) {
    return Object.fromEntries(Object.entries(obj).filter(([_, v]) => v != null));
}

function toggleView() {
    const tableView = document.getElementById('table-view');
    const jsonView = document.getElementById('json-view');
    const toggleButton = document.getElementById('toggle-view');

    if (tableView.style.display === 'none') {
        // If we are in JSON view, switch to table view
        tableView.style.display = 'block';
        jsonView.style.display = 'none';
        toggleButton.textContent = "Show as JSON";
    } else {
        // If we are in table view, switch to JSON view
        tableView.style.display = 'none';
        jsonView.style.display = 'block';
        toggleButton.textContent = "Show as Table";
    }
}

let queryHistory = [];
let historyIndex = -1;

async function fetchHistory() {
  const res = await fetch("/history", { 
    method: "GET",
    credentials: "include", 
    headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": `Bearer ${fetchToken()}`
    }});
  queryHistory = await res.json();
  historyIndex = queryHistory.length;
  if (!res.ok) {
    if (res.status === 401) {
        alert("Session expired. Please log in again.");
        window.location.href = '/login';
    }
  }

}

async function handleHistorySearch(box) {
  const search = prompt("Search history:");
  if (search) {
    const res = await fetch(`/history/search?q=${encodeURIComponent(search)}`, { 
        method: "GET",
        credentials: "include", 
        headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": `Bearer ${fetchToken()}`
        }});
    if (!res.ok) {
        if (res.status === 401) {
            alert("Session expired. Please log in again.");
            window.location.href = '/login';
        }
        throw new Error(`HTTP error! status: ${res.status}`);
    }
    const result = await res.json();
    if (result.length > 0) {
      box.value = result[0].query || result[0];
    }
  }
}

function handleHistoryUp(box) {
  if (historyIndex > 0) {
    historyIndex--;
    const entry = queryHistory[historyIndex];
    box.value = typeof entry === 'object' ? entry.query : entry;
  }
}

function handleHistoryDown(box) {
  if (historyIndex < queryHistory.length - 1) {
    historyIndex++;
    const entry = queryHistory[historyIndex];
    box.value = typeof entry === 'object' ? entry.query : entry;
  } else {
    box.value = '';
  }
}

// -----------------------------------------------

async function handleLogin(event) {
    event.preventDefault(); // Prevent form from submitting normally

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });

        if (response.ok) {
            const data = await response.json();

            // Store the JWT token in localStorage for future requests
            localStorage.setItem('access_token', data.access_token);

            window.location.href = '/'; // Redirect to the main page after successful login
        } else {
            console.error('Login failed:', response.status);
            alert('Invalid credentials, please try again.');
        }
    } catch (error) {
        console.error('Error during login:', error);
        alert('An error occurred, please try again later.');
    }
}

function fetchToken() {
    const token = localStorage.getItem('access_token');
    if (token) {
        return token;
    } else {
        // Redirect to login page if there's no token
        window.location.href = '/login';
        return;        return null;
    }
}

async function loginContentLoader() {
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
}


async function fetchUserInfo() {
    const token = fetchToken();

    console.log('Fetching user info with token:', token);
    const response = await fetch('/user_info', {
        method: "GET",
        credentials: "include", 
        headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": `Bearer ${fetchToken()}`
        }});

    if (response.ok) {
        // Check if the response is an HTML page or JSON
        const contentType = response.headers.get("Content-Type");

        if (contentType && contentType.includes("text/html")) {
            // If the response is HTML (user info page), show it
            const text = await response.text();
            document.open();
            document.write(text);  // Write the HTML response directly to the page
            document.close();
        } else if (contentType && contentType.includes("application/json")) {
            // If the response is JSON (error or invalid token), handle the error
            const errorData = await response.json();
            alert(errorData.detail || "An error occurred, please try again.");
            window.location.href = '/login';  // Redirect to login if token is invalid
        }
    } else {
        if (response.status === 401) {
            alert("Session expired. Please log in again.");
            window.location.href = '/login';
        }

        console.error('Failed to fetch user info');
        window.location.href = '/login';  // Redirect to login if something went wrong
    }
}
